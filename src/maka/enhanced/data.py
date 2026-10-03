"""Data transmission (IMPLEMENTATION_PLAN.md §4.6.6): end-to-end CM->BS encryption, per-hop
authentication and authenticated batching at the CH -- in place of RP9's undefined
aggregation (AM-05). The CH never holds a CM->BS key (V-POS-04).

CM:  inner   = sealed DATA_INNER over the CM-BS session (AEAD, AD = V||type||LP(sid,src,dst,seq))
     hop_tag = HMAC(HKDF(k_CM->CH, "hop-mac"), LP(inner))
     DATA_CM = V||0x40||LP(sid_CM-CH, inner, hop_tag)
CH:  checks the hop tag, batches (ID_CM, inner); every BATCH_STEPS steps or BATCH_MAX items
     sends DATA_BATCH sealed over the CH-BS session.
BS:  opens the batch, checks each CM is granted to that CH (MEMBERSHIP_MISMATCH), opens each
     inner frame with that CM's session (strictly increasing seq), stores the reading.
"""

from __future__ import annotations

from typing import Any

from maka import ledger
from maka.codec import LP, DecodeError
from maka.enhanced import messages as m
from maka.enhanced import states as st
from maka.enhanced.device import Rejected
from maka.enhanced.membership import BSMembership, CHMembership, CMMembership
from maka.kdf import ct_equal, hmac256
from maka.runtime import events as ev
from maka.runtime.bus import Frame


class CMData(CMMembership):
    def send_reading(self, value: str) -> list[Frame]:
        """Operator command (FR-06)."""
        to_bs = self.current_session(self.cfg.id_bs, m.CM_BS)
        hop = self.current_session(self.designated, m.CM_CH) if self.designated else None
        if to_bs is None or hop is None or self.designated is None:
            return self.reject("UNAUTHENTICATED_PEER", peer=self.designated,
                               reason="no CM-BS and CM-CH sessions yet")
        with ledger.LedgerScope(self.identity, "data"):
            inner = self.seal(to_bs, m.DATA_INNER, value.encode())
            tag = hmac256(self.keystore.get(hop.key("hop")), LP(inner))
            hop.sent += 1
        return [self.frame(self.designated, "DATA_CM", m.encode_data_cm(hop.sid, inner, tag))]


class CHData(CHMembership):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.batch: list[tuple[str, bytes]] = []

    def handlers(self) -> dict[int, Any]:
        return {**super().handlers(), m.DATA_CM: self._on_data_cm}

    def _on_data_cm(self, payload: bytes, link: str) -> list[Frame]:
        try:
            sid, inner, tag = m.decode_data_cm(payload)
        except DecodeError as exc:
            raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        if not self.check("sender is a granted member", link in self.grant):
            raise Rejected("UNAUTHENTICATED_PEER", peer=link, reason="not a granted member")
        s = self.sessions.get(sid.hex())
        if s is None or s.state != st.ESTABLISHED or s.peer != link or s.purpose != m.CM_CH:
            code = "SESSION_SUPERSEDED" if sid.hex() in self.superseded else "UNKNOWN_SESSION"
            self.check("CM-CH session established", False, code)
            if code == "UNKNOWN_SESSION":
                self._pending_out.append(self.send_to(link, m.encode_session_unknown(sid, self.identity, link)))
            raise Rejected(code, peer=link, sid=sid)
        with ledger.LedgerScope(self.identity, "data"):
            ok = ct_equal(hmac256(self.keystore.get(s.key("hop")), LP(inner)), tag)
        if not self.check("hop tag valid", ok):
            raise Rejected("BAD_TAG", peer=link, sid=sid, reason="hop MAC")
        s.recv += 1
        self.batch.append((link, inner))
        if len(self.batch) >= self.cfg.batch_max:
            return self._flush_batch()
        if len(self.batch) == 1:
            self.set_timer("batch", self.cfg.batch_steps)
        return []

    def on_role_timer(self, name: str) -> list[Frame]:
        return self._flush_batch() if name == "batch" else super().on_role_timer(name)

    def _flush_batch(self) -> list[Frame]:
        self.cancel_timer("batch")
        if not self.batch:
            return []
        s = self.current_session(self.cfg.id_bs, m.CH_BS)
        items, self.batch = self.batch, []
        if s is None:
            self.emit("UNKNOWN_SESSION", peer=self.cfg.id_bs, reason="no CH-BS session; batch dropped",
                      items=len(items))
            return []
        with ledger.LedgerScope(self.identity, "data"):
            sealed = self.seal(s, m.DATA_BATCH, m.encode_batch(items))
        self.emit("BATCH_SENT", peer=self.cfg.id_bs, items=len(items))
        return [self.send_to(self.cfg.id_bs, sealed)]


class BSData(BSMembership):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.readings: list[dict[str, Any]] = []

    def handlers(self) -> dict[int, Any]:
        return {**super().handlers(), m.DATA_BATCH: self._on_batch}

    def _on_batch(self, payload: bytes, link: str) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "data"):
            _, _, pt = self.open_sealed(payload, peer=link, purpose=m.CH_BS)
            try:
                items = m.decode_batch(pt)
            except DecodeError as exc:
                raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
            accepted, first_failure = 0, None
            for cm, inner in items:
                try:
                    if cm not in self.grants.get(link, set()):
                        raise Rejected("MEMBERSHIP_MISMATCH", peer=cm, ch=link)
                    s, sec, reading = self.open_sealed(inner, peer=cm, purpose=m.CM_BS, notify_via=link)
                    if sec.mtype != m.DATA_INNER:
                        raise Rejected("DECODE_ERROR", peer=cm, error="not a reading")
                except Rejected as r:
                    first_failure = first_failure or r.code
                    self.emit(r.code, peer=r.peer, sid=r.sid.hex() if r.sid else None, **r.details)
                    continue
                self.readings.append({"device": cm, "seq": sec.seq, "value": reading.decode("utf-8", "replace"),
                                      "step": self.now})
                self.emit("DATA_ACCEPTED", peer=cm, sid=s.sid_hex, seq=sec.seq, via=link)
                accepted += 1
        if accepted == 0 and first_failure is not None:
            self._verdict = (ev.REJECT, first_failure)
        return []
