"""MAKA-E device base: keystore helpers, the AKE engine (§4.6.4) and session-sealed messages.

Responder validation order for HS1 -- each failure is a FAIL verdict plus an event, no reply:
  1 decode (DECODE_ERROR)  2 ID_R is me (WRONG_RECIPIENT)  3 purpose valid (BAD_PURPOSE)
  4 initiator authorised (UNAUTHORISED_PEER)  5 pending limits (RATE_LIMITED)
  6 X is a valid point (BAD_POINT)  7 PSK, y, Z, keys, HS2.
Checks 1-5 run before any pairing or scalar multiplication (the P-07 DoS mitigation).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag

from maka import aead, codec, ledger
from maka.codec import DecodeError
from maka.curve import CurveParams, Point
from maka.enhanced import ake
from maka.enhanced import messages as m
from maka.enhanced import states as st
from maka.enhanced.states import Session
from maka.kdf import ct_equal
from maka.rng import RandomSource
from maka.runtime.bus import Frame
from maka.runtime.device import Device
from maka.runtime.keystore import Keystore, SecretClass

SECRET = SecretClass.SECRET
PUBLIC = SecretClass.PUBLIC


@dataclass(frozen=True)
class EnhancedConfig:
    curve: CurveParams
    g: Point
    id_bs: str
    max_pending: int = 16
    t_hs: int = 20
    t_retry: int = 5
    max_retries: int = 3
    batch_steps: int = 5
    batch_max: int = 8


class Rejected(Exception):
    """Raised inside handlers; handle() turns it into a FAIL verdict and an event."""

    def __init__(self, code: str, peer: str | None = None, sid: bytes | None = None, **details: Any) -> None:
        super().__init__(code)
        self.code, self.peer, self.sid, self.details = code, peer, sid, details


class EnhancedDevice(Device):
    def __init__(self, identity: str, cluster: str | None, keystore: Keystore, randomness: RandomSource,
                 cfg: EnhancedConfig) -> None:
        super().__init__(identity, cluster, keystore, randomness)
        self.cfg = cfg
        self.curve = cfg.curve
        self.g = cfg.g
        self.sessions: dict[str, Session] = {}
        self.current: dict[tuple[str, str], str] = {}
        self.superseded: set[str] = set()
        self.retries: dict[tuple[str, str], int] = {}
        self.retry_via: dict[tuple[str, str], str | None] = {}
        self._gave_up: list[Session] = []  # initiators out of retries, reported after the call
        self._pending_out: list[Frame] = []  # notices produced while rejecting a frame

    # == dispatch ===============================================================================

    def handlers(self) -> dict[int, Any]:
        return {m.HS1: self._on_hs1, m.HS2: self._on_hs2, m.HS3: self._on_hs3,
                m.SESSION_UNKNOWN: self._on_session_unknown}

    def handle(self, frame: Frame) -> list[Frame]:
        return self.dispatch(frame.payload, frame.src) + self._extras()

    def _extras(self) -> list[Frame]:
        out, self._pending_out = self._pending_out, []
        gave_up, self._gave_up = self._gave_up, []
        for s in gave_up:
            out += self.on_gave_up(s)
        return out

    def dispatch(self, payload: bytes, link: str) -> list[Frame]:
        try:
            try:
                t = m.mtype(payload)
            except DecodeError as exc:
                raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
            handler = self.handlers().get(t)
            if handler is None:
                raise Rejected("DECODE_ERROR", peer=link, error=f"unexpected {m.LABELS.get(t, hex(t))}")
            return handler(payload, link)  # type: ignore[no-any-return]
        except Rejected as r:
            self.check(r.code, False, str(r.details.get("reason", "")))
            return self.reject(r.code, peer=r.peer, sid=r.sid.hex() if r.sid else None, **r.details)

    def send_to(self, peer: str, payload: bytes, via: str | None = None) -> Frame:
        if via is not None and via != peer:
            return self.frame(via, f"RELAY:{m.label(payload)}", m.encode_relay(peer, payload))
        return self.frame(peer, m.label(payload), payload)

    # == keys ======================================================================================

    def _pr(self) -> Point:
        return codec.load_point(self.curve, self.keystore.get("pr"))

    def psk(self, peer: str) -> bytes:
        """§4.6.3, cached in the keystore under psk:<peer> (one pairing per peer, ever)."""
        name = f"psk:{peer}"
        if self.keystore.has(name):
            return self.keystore.get(name)
        value = ake.compute_psk(self.curve, self._pr(), self.identity, peer)
        self.keystore.put(name, value, SECRET)
        return value

    def _destroy_session_material(self, s: Session) -> None:
        for name in (s.key("send"), s.key("recv"), s.key("hop"), f"eph:{s.sid_hex}:x", f"hs:{s.sid_hex}:kc"):
            self.keystore.destroy(name)

    def drop_peer(self, peer: str, state: str = st.CLOSED) -> int:
        """Destroys every session and the cached PSK with `peer` (revocation, §4.6.7)."""
        n = 0
        for s in list(self.sessions.values()):
            if s.peer == peer and s.state not in (st.FAILED, st.SUPERSEDED, st.CLOSED, st.ABORTED):
                self._destroy_session_material(s)
                s.state = state
                self.cancel_timer(f"hs:{s.sid_hex}")
                n += 1
        for key in [k for k in self.current if k[0] == peer]:
            del self.current[key]
        self.keystore.destroy(f"psk:{peer}")
        return n

    def abort_all_sessions(self) -> None:
        """§4.8 recovery rule: every session ABORTED, no session key retained."""
        for s in self.sessions.values():
            if s.state not in (st.FAILED, st.SUPERSEDED, st.CLOSED, st.ABORTED):
                s.state = st.ABORTED
            self._destroy_session_material(s)
        self.current.clear()
        self.keystore.destroy_prefix("sess:")
        self.keystore.destroy_prefix("eph:")
        self.keystore.destroy_prefix("hs:")

    # == sessions ======================================================================================

    def current_session(self, peer: str, purpose: str) -> Session | None:
        sid = self.current.get((peer, purpose))
        s = self.sessions.get(sid) if sid else None
        return s if s is not None and s.state == st.ESTABLISHED else None

    def _pending_responder(self, peer: str | None = None) -> int:
        return sum(1 for s in self.sessions.values()
                   if s.role == st.RESPONDER and s.state == st.WAIT_HS3 and (peer is None or s.peer == peer))

    # hooks for roles ---------------------------------------------------------------------

    def purpose_ok(self, id_i: str, purpose: str) -> bool:
        return False

    def authorised(self, id_i: str, purpose: str) -> bool:
        return False

    def screen_hs1(self, hs1: m.Hs1) -> str | None:
        """Role-specific early refusal (e.g. NOT_DESIGNATED at a CM), before the purpose check."""
        return None

    def may_initiate(self, peer: str, purpose: str) -> str | None:
        return None

    def on_established(self, s: Session) -> list[Frame]:
        return []

    def on_gave_up(self, s: Session) -> list[Frame]:
        return []

    # == AKE: initiator ===========================================================================

    def start_ake(self, peer: str, purpose: str, via: str | None = None, *, fresh_budget: bool = False) -> list[Frame]:
        key = (peer, purpose)
        if fresh_budget:
            self.retries[key] = 0
        if any(s.state == st.SENT_HS1 and s.peer == peer and s.purpose == purpose for s in self.sessions.values()):
            return []  # one handshake in flight per (peer, purpose)
        refusal = self.may_initiate(peer, purpose)
        if refusal is not None:
            return self.reject(refusal, peer=peer, purpose=purpose)
        with ledger.LedgerScope(self.identity, "ake"):
            sid = self.rng.bytes(m.SID_BYTES)
            x = self.rng.randint(1, self.curve.r_group)
            hs1 = m.encode_hs1(sid, self.identity, peer, purpose, self.rng.bytes(m.NONCE_BYTES),
                               codec.enc_point(x * self.g))
        s = Session(sid=sid, peer=peer, purpose=purpose, role=st.INITIATOR, state=st.SENT_HS1,
                    started_step=self.now, via=via, hs1=hs1)
        self.keystore.put(f"eph:{s.sid_hex}:x", codec.enc_scalar(self.curve, x), SECRET)
        del x
        self.sessions[s.sid_hex] = s
        self.retry_via[key] = via
        self.set_timer(f"hs:{s.sid_hex}", self.cfg.t_hs)
        return [self.send_to(peer, hs1, via)]

    def _on_hs2(self, payload: bytes, link: str) -> list[Frame]:
        try:
            h = m.decode_hs2(payload)
        except DecodeError as exc:
            raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        s = self.sessions.get(h.sid.hex())
        if not self.check("sid matches a pending HS1", s is not None and s.role == st.INITIATOR
                          and s.state == st.SENT_HS1):
            raise Rejected("UNKNOWN_SESSION", peer=h.id_r, sid=h.sid)
        assert s is not None  # type narrowing only
        if not self.check("ID_R is the intended peer", h.id_r == s.peer and h.id_i == self.identity):
            raise Rejected("WRONG_RECIPIENT", peer=h.id_r, sid=h.sid)
        with ledger.LedgerScope(self.identity, "ake"):
            try:
                y_pt = codec.dec_point(self.curve, h.y_raw)
            except DecodeError as exc:
                self._fail_session(s, "BAD_POINT")
                raise Rejected("BAD_POINT", peer=s.peer, sid=s.sid) from exc
            self.check("Y is a valid subgroup point", True)
            x = codec.dec_scalar(self.curve, self.keystore.get(f"eph:{s.sid_hex}:x"))
            th = ake.transcript_hash(s.hs1, h.body)
            keys = ake.key_schedule(self.psk(s.peer), x * y_pt, th, s.purpose)
            del x
            if not self.check("tag_R valid", ct_equal(ake.tag_r(keys.kc_r, th), h.tag)):
                self._fail_session(s, "BAD_TAG")
                raise Rejected("BAD_TAG", peer=s.peer, sid=s.sid, purpose=s.purpose)
            hs3 = m.encode_hs3(s.sid, ake.tag_i(keys.kc_i, th))
        self.keystore.destroy(f"eph:{s.sid_hex}:x")
        self.keystore.put(s.key("send"), keys.k_ir, SECRET)
        self.keystore.put(s.key("recv"), keys.k_ri, SECRET)
        del keys  # kc_R, kc_I and the okm are not kept anywhere
        out = [self.send_to(s.peer, hs3, s.via)]
        return out + self._establish(s)

    # == AKE: responder ===============================================================================

    def _on_hs1(self, payload: bytes, link: str) -> list[Frame]:
        try:
            h = m.decode_hs1(payload)
        except DecodeError as exc:
            raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        self.check("HS1 decodes", True)
        if not self.check("ID_R is me", h.id_r == self.identity):
            raise Rejected("WRONG_RECIPIENT", peer=h.id_i, sid=h.sid)
        early = self.screen_hs1(h)
        if early is not None:
            self.check("initiator acceptable", False, early)
            raise Rejected(early, peer=h.id_i, sid=h.sid)
        if not self.check("purpose valid for both roles", self.purpose_ok(h.id_i, h.purpose)):
            raise Rejected("BAD_PURPOSE", peer=h.id_i, sid=h.sid, purpose=h.purpose)
        if not self.check("initiator authorised", self.authorised(h.id_i, h.purpose)):
            raise Rejected("UNAUTHORISED_PEER", peer=h.id_i, sid=h.sid, purpose=h.purpose)
        if not self.check("within pending limits", self._pending_responder(h.id_i) < 1
                          and self._pending_responder() < self.cfg.max_pending):
            raise Rejected("RATE_LIMITED", peer=h.id_i, sid=h.sid)
        if not self.check("sid not seen before", h.sid.hex() not in self.sessions):
            raise Rejected("REPLAY_REJECTED", peer=h.id_i, sid=h.sid, reason="sid reuse")
        with ledger.LedgerScope(self.identity, "ake"):
            try:
                x_pt = codec.dec_point(self.curve, h.x_raw)
            except DecodeError as exc:
                raise Rejected("BAD_POINT", peer=h.id_i, sid=h.sid) from exc
            self.check("X is a valid subgroup point", True)
            psk = self.psk(h.id_i)
            y = self.rng.randint(1, self.curve.r_group)
            body = m.hs2_body(h.sid, self.identity, h.id_i, self.rng.bytes(m.NONCE_BYTES), codec.enc_point(y * self.g))
            th = ake.transcript_hash(payload, body)
            keys = ake.key_schedule(psk, y * x_pt, th, h.purpose)
            del y  # y and Z are not needed again
            tag = ake.tag_r(keys.kc_r, th)
        s = Session(sid=h.sid, peer=h.id_i, purpose=h.purpose, role=st.RESPONDER, state=st.WAIT_HS3,
                    started_step=self.now, via=link if link != h.id_i else None, th=th)
        self.keystore.put(s.key("recv"), keys.k_ir, SECRET)
        self.keystore.put(s.key("send"), keys.k_ri, SECRET)
        self.keystore.put(f"hs:{s.sid_hex}:kc", keys.kc_i, SECRET)
        del keys
        self.sessions[s.sid_hex] = s
        self.set_timer(f"hs:{s.sid_hex}", self.cfg.t_hs)
        return [self.send_to(h.id_i, body + tag, s.via)]

    def _on_hs3(self, payload: bytes, link: str) -> list[Frame]:
        try:
            sid, tag = m.decode_hs3(payload)
        except DecodeError as exc:
            raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        s = self.sessions.get(sid.hex())
        if not self.check("sid is waiting for HS3", s is not None and s.role == st.RESPONDER
                          and s.state == st.WAIT_HS3):
            raise Rejected("UNKNOWN_SESSION", peer=link, sid=sid)
        assert s is not None  # type narrowing only
        with ledger.LedgerScope(self.identity, "ake"):
            ok = ct_equal(ake.tag_i(self.keystore.get(f"hs:{s.sid_hex}:kc"), s.th), tag)
        self.keystore.destroy(f"hs:{s.sid_hex}:kc")
        if not self.check("tag_I valid", ok):
            self._fail_session(s, "BAD_TAG")
            raise Rejected("BAD_TAG", peer=s.peer, sid=s.sid, purpose=s.purpose)
        return self._establish(s)

    # == AKE: completion, failure, retries ==========================================================

    def _establish(self, s: Session) -> list[Frame]:
        s.state, s.established_step = st.ESTABLISHED, self.now
        self.cancel_timer(f"hs:{s.sid_hex}")
        if s.purpose == m.CM_CH:  # hop-MAC key, derived once per session from k_CM->CH = k_IR
            k_ir = self.keystore.get(s.key("send" if s.role == st.INITIATOR else "recv"))
            with ledger.LedgerScope(self.identity, "ake"):
                self.keystore.put(s.key("hop"), ake.hop_mac_key(k_ir), SECRET)
        key = (s.peer, s.purpose)
        old_sid = self.current.get(key)
        rotated = False
        if old_sid is not None and old_sid != s.sid_hex:
            old = self.sessions.get(old_sid)
            if old is not None and old.state == st.ESTABLISHED:
                self._destroy_session_material(old)
                old.state, old.superseded_by = st.SUPERSEDED, s.sid_hex
                self.superseded.add(old_sid)
                self.emit("SESSION_SUPERSEDED", peer=s.peer, sid=old_sid, purpose=s.purpose, by=s.sid_hex)
                rotated = True
        self.current[key] = s.sid_hex
        self.retries[key] = 0
        # One HANDSHAKE_OK per handshake, at the responder once tag_I verifies (both sides have
        # then confirmed the keys); the initiator records KEY_CONFIRMED when tag_R verifies.
        self.emit("HANDSHAKE_OK" if s.role == st.RESPONDER else "KEY_CONFIRMED", peer=s.peer, sid=s.sid_hex,
                  purpose=s.purpose)
        if rotated:
            self.emit("KEY_ROTATED", peer=s.peer, sid=s.sid_hex, purpose=s.purpose)
        return self.on_established(s)

    def _fail_session(self, s: Session, reason: str) -> None:
        s.state = st.FAILED
        self.cancel_timer(f"hs:{s.sid_hex}")
        self._destroy_session_material(s)
        self.emit("HANDSHAKE_FAIL", peer=s.peer, sid=s.sid_hex, purpose=s.purpose, reason=reason)
        if s.role == st.INITIATOR:
            key = (s.peer, s.purpose)
            n = self.retries.get(key, 0)
            if n < self.cfg.max_retries:
                self.retries[key] = n + 1
                self.set_timer(f"retry:{s.peer}|{s.purpose}", self.cfg.t_retry)
            else:
                self._gave_up.append(s)

    def on_timer(self, name: str) -> list[Frame]:
        out: list[Frame] = []
        if name.startswith("hs:"):
            s = self.sessions.get(name[3:])
            if s is not None and s.state in st.PENDING:
                self.emit("TIMEOUT", peer=s.peer, sid=s.sid_hex, purpose=s.purpose)
                self._fail_session(s, "TIMEOUT")
        elif name.startswith("retry:"):
            peer, _, purpose = name[6:].partition("|")
            out = self.start_ake(peer, purpose, self.retry_via.get((peer, purpose)))
        else:
            out = self.on_role_timer(name)
        return out + self._extras()

    def on_role_timer(self, name: str) -> list[Frame]:
        return []

    def _on_session_unknown(self, payload: bytes, link: str) -> list[Frame]:
        """The responder lost a session we believe ESTABLISHED (V-ADV-07): start a fresh
        handshake, which supersedes the stale one. Nothing is trusted from this notice."""
        try:
            sid, id_r, id_i = m.decode_session_unknown(payload)
        except DecodeError as exc:
            raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        s = self.sessions.get(sid.hex())
        if s is None or s.role != st.INITIATOR or s.peer != id_r or id_i != self.identity:
            raise Rejected("UNKNOWN_SESSION", peer=id_r, sid=sid)
        if self.current.get((s.peer, s.purpose)) != s.sid_hex:
            return []  # already replaced
        return self.start_ake(s.peer, s.purpose, s.via, fresh_budget=True)

    # == session-sealed messages (§4.6.5-4.6.6) ======================================================

    def seal(self, s: Session, t: int, plaintext: bytes) -> bytes:
        s.send_seq += 1
        s.sent += 1
        ad = m.secure_ad(t, s.sid, self.identity, s.peer, s.send_seq)
        ct = aead.encrypt(self.keystore.get(s.key("send")), plaintext, ad=ad, nonce=aead.counter_nonce(s.send_seq))
        return m.encode_secure(t, s.sid, s.send_seq, ct)

    def open_sealed(self, payload: bytes, *, peer: str | None, purpose: str,
                    notify_via: str | None = None) -> tuple[Session, m.Secure, bytes]:
        """Decodes, finds the session by sid, enforces strictly increasing seq, decrypts."""
        try:
            sec = m.decode_secure(payload)
        except DecodeError as exc:
            raise Rejected("DECODE_ERROR", peer=peer, error=str(exc)) from exc
        s = self.sessions.get(sec.sid.hex())
        if s is None or s.state != st.ESTABLISHED or s.purpose != purpose or (peer is not None and s.peer != peer):
            code = "SESSION_SUPERSEDED" if sec.sid.hex() in self.superseded else "UNKNOWN_SESSION"
            self.check("session established", False, code)
            if code == "UNKNOWN_SESSION" and peer is not None:
                self._notify_unknown(sec.sid, peer, notify_via)
            raise Rejected(code, peer=peer, sid=sec.sid)
        if not self.check("seq fresh", sec.seq > s.recv_last):
            raise Rejected("REPLAY_REJECTED", peer=s.peer, sid=s.sid, seq=sec.seq)
        ad = m.secure_ad(sec.mtype, s.sid, s.peer, self.identity, sec.seq)
        try:
            pt = aead.decrypt(self.keystore.get(s.key("recv")), sec.ct, ad=ad)
        except InvalidTag as exc:
            self.check("AEAD tag valid", False)
            raise Rejected("BAD_TAG", peer=s.peer, sid=s.sid) from exc
        self.check("AEAD tag valid", True)
        s.recv_last = sec.seq
        s.recv += 1
        return s, sec, pt

    def _notify_unknown(self, sid: bytes, peer: str, via: str | None) -> None:
        self._pending_out.append(self.send_to(peer, m.encode_session_unknown(sid, self.identity, peer), via))

