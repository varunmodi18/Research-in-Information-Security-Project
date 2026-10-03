"""RP9 §5.1-5.5 as device state machines (original mode), with the M1 fixes (§4.7):

ER-01 (A4 = r_CM * P_CM); `secure_pseudo_ids` (default on); fixed 160-bit IDs with zero
rejection; decode-then-verify on every frame; one A1/A2/EM2 per CH round; failures enforced
as rejections and status changes; data stops at the CH with AGGREGATION_UNDEFINED (AM-05)
unless the Lab-only `forward_ciphertexts` variant is selected.

Each handler runs inside a ledger scope (entity, phase) so RP9 Table 2 can be read off the
ledger. A rejected frame changes nothing but the verdict and an event; a device becomes
`failed` only when its protocol step times out without a valid message.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidTag

from maka import aead, codec, hashing, ibe, ledger, pairing
from maka.codec import DecodeError
from maka.curve import CurveParams, Point
from maka.field import fp2_to_bytes
from maka.original_rt import messages as m
from maka.protocol.data_transmission import data_ad
from maka.protocol.p3_node_registration import DegenerateScalarError, xor_to_scalar
from maka.protocol.p5_session_key_agreement import K_SYM_BYTES, k_sym_label
from maka.rng import RandomSource
from maka.runtime import device as dv
from maka.runtime.bus import BROADCAST, Frame
from maka.runtime.device import Device
from maka.runtime.keystore import Keystore, SecretClass

SECRET, PUBLIC = SecretClass.SECRET, SecretClass.PUBLIC
NONCE_BYTES = 20
# Timeouts in scheduler steps. One frame is delivered per step, so latency grows with the
# number of frames in flight; network builders scale these with the device count.
T_REG = 10  # steps a CH waits for its members' PUB_CM before sending the beacon anyway
T_AUTH = 20  # steps a CH waits for EM3s, and a registered CM waits for EM1


@dataclass(frozen=True)
class OriginalConfig:
    curve: CurveParams
    g: Point
    id_bs: str
    secure_pseudo_ids: bool = True
    forward_ciphertexts: bool = False  # Lab-only addition to RP9 (§4.7)
    t_reg: int = T_REG
    t_auth: int = T_AUTH


class _OriginalDevice(Device):
    def __init__(self, identity: str, cluster: str | None, keystore: Keystore,
                 randomness: RandomSource, cfg: OriginalConfig) -> None:
        super().__init__(identity, cluster, keystore, randomness)
        self.cfg = cfg
        self.curve = cfg.curve
        self.g = cfg.g
        self.nonces_seen: set[bytes] = set()

    # -- keystore helpers ---------------------------------------------------------

    def _point(self, name: str) -> Point:
        return codec.load_point(self.curve, self.keystore.get(name))

    def _put_point(self, name: str, pt: Point, cls: SecretClass) -> None:
        self.keystore.put(name, codec.enc_point(pt), cls)

    def _seal(self, plaintext: bytes, recipient_pu: Point) -> bytes:
        ct = ibe.encrypt(self.curve, self.g, plaintext, recipient_pu, self._point("k_pub"))
        return codec.encode_ibe(ct)

    def _unseal(self, payload: bytes) -> bytes:
        return ibe.decrypt(self.curve, codec.decode_ibe(self.curve, payload), self._point("pr"))

    def _fresh(self, nonce: bytes) -> bool:
        fresh = nonce not in self.nonces_seen
        self.nonces_seen.add(nonce)
        return fresh

    def _keygen(self) -> Point:
        """RP9 §5.2: Pu = H(ID), Pr = k * Pu, then the keystore entry holding k is zeroed and
        removed. The int decoded from it cannot be wiped (Python limitation, I-09)."""
        pu = hashing.hash_to_point(self.curve, self.identity.encode())
        k = codec.dec_scalar(self.curve, self.keystore.get("k"))
        self._put_point("pr", k * pu, SECRET)
        self._put_point("pu", pu, PUBLIC)
        self.keystore.destroy("k")
        return pu

    def _session_key(self) -> None:
        """RP9 §5.5: SK_{i-BS} = e(Pr_i, Pu_BS); k_sym = KDF(...) (IA-06)."""
        sk = pairing.modified_pairing(self.curve, self._point("pr"), self._point("pu_bs"))
        self.keystore.put("ksym", hashing.kdf(fp2_to_bytes(sk), k_sym_label(self.cfg.id_bs, self.identity),
                                              K_SYM_BYTES), SECRET)
        self.emit("ORIG_SESSION_KEY", peer=self.cfg.id_bs)

    def _decode_failure(self, frame: Frame, exc: Exception) -> list[Frame]:
        self.check(f"{frame.label} decrypts and decodes", False, type(exc).__name__)
        return self.reject("DECODE_ERROR", peer=frame.src, label=frame.label, error=type(exc).__name__)


class OriginalBS(_OriginalDevice):
    role = dv.BS

    def __init__(self, identity: str, keystore: Keystore, randomness: RandomSource,
                 cfg: OriginalConfig) -> None:
        super().__init__(identity, None, keystore, randomness, cfg)
        self.ch_keys: dict[str, Point] = {}
        self.clusters: dict[str, dict[str, Point]] = {}  # decoded beacons: ID_CH -> {ID_CM: Pu_CM}
        self.pseudo_ids: dict[str, Point] = {}
        self.authenticated_chs: set[str] = set()
        self.last_seq: dict[str, int] = {}
        self.readings: list[dict[str, object]] = []

    def keygen(self) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "keygen"):
            self.keystore.destroy("k")  # OB-01
        self.set_status(dv.ACTIVE)
        return []

    def handle(self, frame: Frame) -> list[Frame]:
        handlers = {m.PUB_CH: self._on_pub_ch, m.BEACON: self._on_beacon, m.EM2: self._on_em2,
                    m.DATA_FWD: self._on_data_fwd}
        handler = handlers.get(frame.label)
        if handler is None:
            return [] if frame.label in (m.PUB_CM,) else self.reject(
                "DECODE_ERROR", peer=frame.src, label=frame.label, error="unexpected label")
        return handler(frame)

    def _on_pub_ch(self, frame: Frame) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "registration"):
            try:
                self.ch_keys[frame.src] = codec.decode_pub(self.curve, frame.payload)
            except DecodeError as exc:
                return self._decode_failure(frame, exc)
        return []

    def _on_beacon(self, frame: Frame) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "registration"):
            try:
                beacon = codec.decode_beacon(self.curve, self._unseal(frame.payload))
            except (DecodeError, InvalidTag) as exc:
                return self._decode_failure(frame, exc)
            self.check("BEACON decrypts and decodes", True)
            if not self.check("N_reg fresh", self._fresh(beacon.n_reg)):
                return self.reject("REPLAY_REJECTED", peer=beacon.id_ch, label=frame.label)
            try:
                p_ch = xor_to_scalar(self.identity, beacon.id_ch, self.curve.r_group) * self.g
                p_cms = [xor_to_scalar(beacon.id_ch, cm_id, self.curve.r_group) * self.g
                         for cm_id, _ in beacon.members]
            except DegenerateScalarError as exc:
                self.check("pseudo-identity scalars non-zero", False, str(exc))
                return self.reject("ORIG_AUTH_FAIL", peer=beacon.id_ch, reason="degenerate pseudo-identity")
            self.clusters[beacon.id_ch] = dict(beacon.members)
            self.pseudo_ids[beacon.id_ch] = p_ch
            for (cm_id, _), p_cm in zip(beacon.members, p_cms):
                self.pseudo_ids[cm_id] = p_cm
            self.emit("ORIG_REGISTERED", peer=beacon.id_ch, members=len(beacon.members))
            plaintext = codec.encode_pseudo_bs_ch(p_ch, p_cms)
            payload = (self._seal(plaintext, hashing.hash_to_point(self.curve, beacon.id_ch.encode()))
                       if self.cfg.secure_pseudo_ids else plaintext)
        return [self.frame(beacon.id_ch, m.PSEUDO_BS_CH, payload, m.bits_pseudo_bs_ch(len(p_cms)))]

    def _on_em2(self, frame: Frame) -> list[Frame]:
        ch_id = frame.src
        with ledger.LedgerScope(self.identity, "authentication"):
            try:
                a1, a2, nonce = codec.decode_auth(self.curve, self._unseal(frame.payload))
            except (DecodeError, InvalidTag) as exc:
                return self._decode_failure(frame, exc)
            self.check("EM2 decrypts and decodes", True)
            if not self.check("N_auth_CH fresh", self._fresh(nonce)):
                return self.reject("REPLAY_REJECTED", peer=ch_id, label=frame.label)
            if not self.check("CH is registered", ch_id in self.clusters):
                return self.reject("ORIG_AUTH_FAIL", peer=ch_id, reason="unregistered CH")
            ok = xor_to_scalar(self.identity, ch_id, self.curve.r_group) * a1 == a2
            if not self.check("A2' == A2", ok):
                return self.reject("ORIG_AUTH_FAIL", peer=ch_id, reason="A2' != A2")
        self.authenticated_chs.add(ch_id)
        self.emit("ORIG_AUTH_OK", peer=ch_id)
        return []

    def _on_data_fwd(self, frame: Frame) -> list[Frame]:
        """Lab variant: member ciphertexts forwarded unchanged by an authenticated CH."""
        ch_id = frame.src
        with ledger.LedgerScope(self.identity, "data"):
            if not self.check("forwarding CH authenticated", ch_id in self.authenticated_chs):
                return self.reject("UNAUTHENTICATED_PEER", peer=ch_id)
            try:
                raw_id, inner = codec.unLP(frame.payload, 2)
                cm_id = codec.dec_id(raw_id)
                seq, blob = codec.decode_data(inner)
            except DecodeError as exc:
                return self._decode_failure(frame, exc)
            if not self.check("CM registered under this CH", cm_id in self.clusters.get(ch_id, {})):
                return self.reject("MEMBERSHIP_MISMATCH", peer=cm_id, ch=ch_id)
            key_name = f"ksym:{cm_id}"
            if not self.keystore.has(key_name):
                sk = pairing.modified_pairing(self.curve, self.clusters[ch_id][cm_id], self._point("pr"))
                self.keystore.put(key_name, hashing.kdf(fp2_to_bytes(sk), k_sym_label(self.identity, cm_id),
                                                        K_SYM_BYTES), SECRET)
            try:
                reading = aead.decrypt(self.keystore.get(key_name), blob, ad=data_ad(cm_id, self.identity, seq))
            except InvalidTag:
                self.check("reading authenticates", False)
                return self.reject("BAD_TAG", peer=cm_id)
            if not self.check("seq fresh", seq > self.last_seq.get(cm_id, 0)):
                return self.reject("REPLAY_REJECTED", peer=cm_id, seq=seq)
        self.last_seq[cm_id] = seq
        self.readings.append({"device": cm_id, "seq": seq, "value": reading.decode("utf-8", "replace"),
                              "step": self.now})
        self.emit("DATA_ACCEPTED", peer=cm_id, seq=seq, via=ch_id)
        return []


class OriginalCH(_OriginalDevice):
    role = dv.CH

    def __init__(self, identity: str, keystore: Keystore, randomness: RandomSource,
                 cfg: OriginalConfig, expected_members: list[str]) -> None:
        super().__init__(identity, identity, keystore, randomness, cfg)
        self.expected_members = list(expected_members)  # provisioning config ("local discovery")
        self.members: dict[str, Point] = {}  # from received PUB_CM frames, arrival order
        self.member_order: list[str] = []
        self.beacon_sent = False
        self.p_ch: Point | None = None
        self.p_cm_table: dict[str, Point] = {}
        self.pending_em3: set[str] = set()
        self.authenticated_members: set[str] = set()
        self.round_done = False

    def keygen(self) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "keygen"):
            pu = self._keygen()
        self.set_timer("reg", self.cfg.t_reg)
        return [self.frame(BROADCAST, m.PUB_CH, codec.encode_pub(pu), m.bits_pub())]

    def handle(self, frame: Frame) -> list[Frame]:
        handlers = {m.PUB_CM: self._on_pub_cm, m.PSEUDO_BS_CH: self._on_pseudo,
                    m.EM3: self._on_em3, m.DATA_CM: self._on_data}
        handler = handlers.get(frame.label)
        if handler is None:
            return [] if frame.label == m.PUB_CH else self.reject(
                "DECODE_ERROR", peer=frame.src, label=frame.label, error="unexpected label")
        return handler(frame)

    def on_timer(self, name: str) -> list[Frame]:
        if name == "reg" and not self.beacon_sent and self.members:
            return self._send_beacon()
        if name == "round" and not self.round_done:
            for cm_id in sorted(self.pending_em3):
                self.emit("ORIG_AUTH_FAIL", peer=cm_id, reason="no valid EM3 before timeout")
            return self._finish_round()
        return []

    def _on_pub_cm(self, frame: Frame) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "registration"):
            try:
                self.members[frame.src] = codec.decode_pub(self.curve, frame.payload)
            except DecodeError as exc:
                return self._decode_failure(frame, exc)
        if not self.beacon_sent and set(self.expected_members) <= set(self.members):
            return self._send_beacon()
        return []

    def _send_beacon(self) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "registration"):
            n_reg = self.rng.bytes(NONCE_BYTES)
            self.member_order = list(self.members)
            plaintext = codec.encode_beacon(self.identity, list(self.members.items()), n_reg)
            payload = self._seal(plaintext, self._point("pu_bs"))
        self.beacon_sent = True
        self.cancel_timer("reg")
        return [self.frame(self.cfg.id_bs, m.BEACON, payload, m.bits_beacon(len(self.member_order)))]

    def _on_pseudo(self, frame: Frame) -> list[Frame]:
        out: list[Frame] = []
        with ledger.LedgerScope(self.identity, "registration"):
            try:
                raw = self._unseal(frame.payload) if self.cfg.secure_pseudo_ids else frame.payload
                p_ch, p_cms = codec.decode_pseudo_bs_ch(self.curve, raw)
                if len(p_cms) != len(self.member_order):
                    raise DecodeError("P_CM count differs from the beacon's member count")
            except (DecodeError, InvalidTag) as exc:
                return self._decode_failure(frame, exc)
            self.check("PSEUDO_BS_CH decrypts and decodes", True)
            self.p_ch = p_ch
            self.p_cm_table = dict(zip(self.member_order, p_cms))
            for cm_id, p_cm in self.p_cm_table.items():
                plaintext = codec.encode_pseudo_ch_cm(self.identity, p_cm)
                payload = (self._seal(plaintext, self.members[cm_id])
                           if self.cfg.secure_pseudo_ids else plaintext)
                out.append(self.frame(cm_id, m.PSEUDO_CH_CM, payload, m.bits_pseudo_ch_cm()))
        self.set_status(dv.REGISTERED)
        return out + self._start_round()

    def _start_round(self) -> list[Frame]:
        """RP9 §5.4: one (A1, A2, N_auth_CH) per round, one EM1 per member, one EM2 (IA-15)."""
        assert self.p_ch is not None  # type narrowing only
        out = []
        with ledger.LedgerScope(self.identity, "authentication"):
            r_ch = self.rng.randint(1, self.curve.r_group)
            self.keystore.put("r_ch", codec.enc_scalar(self.curve, r_ch), SECRET)
            a1, a2 = r_ch * self.g, r_ch * self.p_ch
            sealed = codec.encode_auth(a1, a2, self.rng.bytes(NONCE_BYTES))
            for cm_id in self.p_cm_table:
                out.append(self.frame(cm_id, m.EM1, self._seal(sealed, self.members[cm_id]), m.bits_em()))
            out.append(self.frame(self.cfg.id_bs, m.EM2, self._seal(sealed, self._point("pu_bs")), m.bits_em()))
        self.pending_em3 = set(self.p_cm_table)
        self.set_timer("round", self.cfg.t_auth)
        return out

    def _on_em3(self, frame: Frame) -> list[Frame]:
        cm_id = frame.src
        with ledger.LedgerScope(self.identity, "authentication"):
            try:
                a3, a4, nonce = codec.decode_auth(self.curve, self._unseal(frame.payload))
            except (DecodeError, InvalidTag) as exc:
                return self._decode_failure(frame, exc)
            self.check("EM3 decrypts and decodes", True)
            if not self.check("N_auth_CM fresh", self._fresh(nonce)):
                return self.reject("REPLAY_REJECTED", peer=cm_id, label=frame.label)
            if not self.check("EM3 answers an outstanding challenge", cm_id in self.pending_em3):
                return self.reject("ORIG_AUTH_FAIL", peer=cm_id, reason="no outstanding challenge")
            ok = xor_to_scalar(self.identity, cm_id, self.curve.r_group) * a3 == a4
            if not self.check("A4' == A4", ok):
                return self.reject("ORIG_AUTH_FAIL", peer=cm_id, reason="A4' != A4")
        self.pending_em3.discard(cm_id)
        self.authenticated_members.add(cm_id)
        self.emit("ORIG_AUTH_OK", peer=cm_id)
        return self._finish_round() if not self.pending_em3 else []

    def _finish_round(self) -> list[Frame]:
        if self.round_done:
            return []
        self.round_done = True
        self.cancel_timer("round")
        self.keystore.destroy("r_ch")
        with ledger.LedgerScope(self.identity, "session_key"):
            self._session_key()
        self.set_status(dv.ACTIVE)
        return []

    def _on_data(self, frame: Frame) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "data"):
            if not self.check("sender authenticated in this round", frame.src in self.authenticated_members):
                return self.reject("UNAUTHENTICATED_PEER", peer=frame.src)
            try:
                codec.decode_data(frame.payload)
            except DecodeError as exc:
                return self._decode_failure(frame, exc)
        if self.cfg.forward_ciphertexts:
            payload = codec.LP(codec.enc_id(frame.src), frame.payload)
            return [self.frame(self.cfg.id_bs, m.DATA_FWD, payload, len(payload) * 8)]
        self.emit("AGGREGATION_UNDEFINED", peer=frame.src,
                  reason="RP9 §5.5 specifies no Aggregate operation; the CH cannot read SK_CM-BS "
                         "ciphertexts (AM-05)")
        return []


class OriginalCM(_OriginalDevice):
    role = dv.CM

    def __init__(self, identity: str, keystore: Keystore, randomness: RandomSource,
                 cfg: OriginalConfig, deployed_ch: str) -> None:
        super().__init__(identity, deployed_ch, keystore, randomness, cfg)
        self.deployed_ch = deployed_ch  # where PUB_CM is addressed (deployment, not protocol state)
        self.heard_pub_ch: dict[str, bytes] = {}  # raw PUB_CH broadcasts, decoded on demand
        self.id_ch: str | None = None  # learned from PSEUDO_CH_CM (IA-14)
        self.pu_ch: Point | None = None
        self.p_cm: Point | None = None
        self.ch_verified = False
        self.seq = 0

    def keygen(self) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "keygen"):
            pu = self._keygen()
        return [self.frame(self.deployed_ch, m.PUB_CM, codec.encode_pub(pu), m.bits_pub())]

    def handle(self, frame: Frame) -> list[Frame]:
        if frame.label == m.PUB_CH:
            self.heard_pub_ch[frame.src] = frame.payload
            return []
        handlers = {m.PSEUDO_CH_CM: self._on_pseudo, m.EM1: self._on_em1}
        handler = handlers.get(frame.label)
        if handler is None:
            return self.reject("DECODE_ERROR", peer=frame.src, label=frame.label, error="unexpected label")
        return handler(frame)

    def on_timer(self, name: str) -> list[Frame]:
        if name == "auth" and not self.ch_verified:
            self.set_status(dv.FAILED)
            self.emit("ORIG_AUTH_FAIL", peer=self.id_ch, reason="no valid EM1 before timeout")
        return []

    def _on_pseudo(self, frame: Frame) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "registration"):
            try:
                raw = self._unseal(frame.payload) if self.cfg.secure_pseudo_ids else frame.payload
                id_ch, p_cm = codec.decode_pseudo_ch_cm(self.curve, raw)
                heard = self.heard_pub_ch.get(id_ch)
                if heard is None:
                    raise DecodeError(f"no PUB_CH broadcast from {id_ch} was heard")
                pu_ch = codec.decode_pub(self.curve, heard)
            except (DecodeError, InvalidTag) as exc:
                return self._decode_failure(frame, exc)
            self.check("PSEUDO_CH_CM decrypts and decodes", True)
        self.id_ch, self.p_cm, self.pu_ch = id_ch, p_cm, pu_ch
        self.set_status(dv.REGISTERED)
        self.set_timer("auth", self.cfg.t_auth)
        return []

    def _on_em1(self, frame: Frame) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "authentication"):
            if not self.check("registered", self.id_ch is not None and self.p_cm is not None):
                return self.reject("ORIG_AUTH_FAIL", peer=frame.src, reason="not registered")
            assert self.id_ch is not None and self.p_cm is not None and self.pu_ch is not None  # type narrowing only
            try:
                a1, a2, nonce = codec.decode_auth(self.curve, self._unseal(frame.payload))
            except (DecodeError, InvalidTag) as exc:
                return self._decode_failure(frame, exc)
            self.check("EM1 decrypts and decodes", True)
            if not self.check("N_auth_CH fresh", self._fresh(nonce)):
                return self.reject("REPLAY_REJECTED", peer=self.id_ch, label=frame.label)
            ok = xor_to_scalar(self.cfg.id_bs, self.id_ch, self.curve.r_group) * a1 == a2
            if not self.check("A2' == A2", ok):
                return self.reject("ORIG_AUTH_FAIL", peer=self.id_ch, reason="A2' != A2")
            self.emit("ORIG_AUTH_OK", peer=self.id_ch)
            self.ch_verified = True
            self.cancel_timer("auth")
            r_cm = self.rng.randint(1, self.curve.r_group)
            a3, a4 = r_cm * self.g, r_cm * self.p_cm  # ER-01: r_CM, not RP9's printed r_CH
            em3 = self._seal(codec.encode_auth(a3, a4, self.rng.bytes(NONCE_BYTES)), self.pu_ch)
        if not self.keystore.has("ksym"):
            with ledger.LedgerScope(self.identity, "session_key"):
                self._session_key()
            self.set_status(dv.ACTIVE)
        return [self.frame(self.id_ch, m.EM3, em3, m.bits_em())]

    def send_reading(self, value: str) -> list[Frame]:
        """Operator command (FR-06): encrypt one reading under k_sym and send it to the CH."""
        if not self.keystore.has("ksym") or self.id_ch is None:
            return self.reject("UNAUTHENTICATED_PEER", peer=self.id_ch, reason="no session key yet")
        with ledger.LedgerScope(self.identity, "data"):
            self.seq += 1
            blob = aead.encrypt(self.keystore.get("ksym"), value.encode(),
                                ad=data_ad(self.identity, self.cfg.id_bs, self.seq),
                                nonce=aead.counter_nonce(self.seq))
            payload = codec.encode_data(self.seq, blob)
        return [self.frame(self.id_ch, m.DATA_CM, payload, len(blob) * 8)]
