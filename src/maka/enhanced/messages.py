"""MAKA-E v1 wire format (IMPLEMENTATION_PLAN.md §4.6). Every message starts V || type with
V = 0x02, so original-mode (0x01) bytes are rejected as DECODE_ERROR (V-ADV-14). Decoders
raise only codec.DecodeError (V-FUZZ-01)."""

from __future__ import annotations

from dataclasses import dataclass

from maka import codec
from maka.codec import LP, DecodeError, body_of, dec_id, enc_id, unLP

V = codec.V_ENHANCED
HS1, HS2, HS3 = 0x10, 0x11, 0x12
CLUSTER_CLAIM, CLUSTER_GRANT, DESIGNATION = 0x20, 0x21, 0x22
REVOKE_NOTICE, REVOKE_ACK, SESSION_UNKNOWN = 0x23, 0x24, 0x26
RELAY, CLUSTER_OPEN = 0x30, 0x33
DATA_CM, DATA_INNER, DATA_BATCH = 0x40, 0x41, 0x42

LABELS = {HS1: "HS1", HS2: "HS2", HS3: "HS3", CLUSTER_CLAIM: "CLUSTER_CLAIM", CLUSTER_GRANT: "CLUSTER_GRANT",
          DESIGNATION: "DESIGNATION", REVOKE_NOTICE: "REVOKE_NOTICE", REVOKE_ACK: "REVOKE_ACK",
          SESSION_UNKNOWN: "SESSION_UNKNOWN", RELAY: "RELAY", CLUSTER_OPEN: "CLUSTER_OPEN",
          DATA_CM: "DATA_CM", DATA_INNER: "DATA_INNER", DATA_BATCH: "DATA_BATCH"}
SECURE_TYPES = (CLUSTER_CLAIM, CLUSTER_GRANT, DESIGNATION, REVOKE_NOTICE, REVOKE_ACK, DATA_INNER, DATA_BATCH)

CH_BS, CM_BS, CM_CH = "CH-BS", "CM-BS", "CM-CH"
PURPOSES = (CH_BS, CM_BS, CM_CH)
SID_BYTES, NONCE_BYTES, TAG_BYTES = 16, 32, 32


def mtype(payload: bytes) -> int:
    if len(payload) < 2 or payload[0] != V:
        raise DecodeError("not a MAKA-E v1 message")
    return payload[1]


def label(payload: bytes) -> str:
    try:
        t = mtype(payload)
    except DecodeError:
        return "UNKNOWN"
    if t == RELAY:
        try:
            _, inner = decode_relay(payload)
            return f"RELAY:{label(inner)}"
        except DecodeError:
            return "RELAY"
    return LABELS.get(t, "UNKNOWN")


def _fixed(raw: bytes, n: int, what: str) -> bytes:
    if len(raw) != n:
        raise DecodeError(f"{what} must be {n} bytes")
    return raw


def _purpose(raw: bytes) -> str:
    try:
        purpose = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DecodeError("purpose is not ASCII") from exc
    if purpose not in PURPOSES:
        raise DecodeError(f"unknown purpose {purpose!r}")
    return purpose


# -- AKE (§4.6.4) --------------------------------------------------------------------------

@dataclass(frozen=True)
class Hs1:
    sid: bytes
    id_i: str
    id_r: str
    purpose: str
    n_i: bytes
    x_raw: bytes  # validated later, after the cheap checks (DoS order, §4.6.4)


def encode_hs1(sid: bytes, id_i: str, id_r: str, purpose: str, n_i: bytes, x_enc: bytes) -> bytes:
    return bytes([V, HS1]) + LP(sid, enc_id(id_i), enc_id(id_r), purpose.encode(), n_i, x_enc)


def decode_hs1(data: bytes) -> Hs1:
    sid, i, r, raw_purpose, n, x = unLP(body_of(data, V, HS1), 6)
    return Hs1(_fixed(sid, SID_BYTES, "sid"), dec_id(i), dec_id(r), _purpose(raw_purpose),
               _fixed(n, NONCE_BYTES, "N_I"), x)


@dataclass(frozen=True)
class Hs2:
    sid: bytes
    id_r: str
    id_i: str
    n_r: bytes
    y_raw: bytes
    tag: bytes
    body: bytes  # V || 0x11 || LP(...): the transcript part, without the tag


def hs2_body(sid: bytes, id_r: str, id_i: str, n_r: bytes, y_enc: bytes) -> bytes:
    return bytes([V, HS2]) + LP(sid, enc_id(id_r), enc_id(id_i), n_r, y_enc)


def decode_hs2(data: bytes) -> Hs2:
    if len(data) < 2 + TAG_BYTES:
        raise DecodeError("HS2 too short")
    body, tag = data[:-TAG_BYTES], data[-TAG_BYTES:]
    sid, r, i, n, y = unLP(body_of(body, V, HS2), 5)
    return Hs2(_fixed(sid, SID_BYTES, "sid"), dec_id(r), dec_id(i), _fixed(n, NONCE_BYTES, "N_R"), y, tag, body)


def encode_hs3(sid: bytes, tag: bytes) -> bytes:
    return bytes([V, HS3]) + LP(sid) + tag


def decode_hs3(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < 2 + TAG_BYTES:
        raise DecodeError("HS3 too short")
    (sid,) = unLP(body_of(data[:-TAG_BYTES], V, HS3), 1)
    return _fixed(sid, SID_BYTES, "sid"), data[-TAG_BYTES:]


# -- messages sealed under a session key ---------------------------------------------------------

@dataclass(frozen=True)
class Secure:
    mtype: int
    sid: bytes
    seq: int
    ct: bytes


def secure_ad(t: int, sid: bytes, src: str, dst: str, seq: int) -> bytes:
    """AD = V || type || LP(sid, src, dst, seq) (§4.6.6); src/dst are the session parties."""
    return bytes([V, t]) + LP(sid, enc_id(src), enc_id(dst), seq.to_bytes(8, "big"))


def encode_secure(t: int, sid: bytes, seq: int, ct: bytes) -> bytes:
    return bytes([V, t]) + LP(sid, seq.to_bytes(8, "big"), ct)


def decode_secure(data: bytes) -> Secure:
    t = mtype(data)
    if t not in SECURE_TYPES:
        raise DecodeError(f"type 0x{t:02x} is not a session message")
    sid, seq, ct = unLP(data[2:], 3)
    return Secure(t, _fixed(sid, SID_BYTES, "sid"), int.from_bytes(_fixed(seq, 8, "seq"), "big"), ct)


# -- plaintexts carried inside sealed messages -------------------------------------------------

def enc_ids(ids: list[str]) -> bytes:
    return LP(*(enc_id(i) for i in ids))


def dec_ids(raw: bytes) -> list[str]:
    return [dec_id(i) for i in codec.unLP_all(raw)]


def encode_grant(epoch: int, granted: list[str], rejected: list[str]) -> bytes:
    return LP(epoch.to_bytes(8, "big"), enc_ids(granted), enc_ids(rejected))


def decode_grant(raw: bytes) -> tuple[int, list[str], list[str]]:
    e, g, r = unLP(raw, 3)
    return int.from_bytes(_fixed(e, 8, "epoch"), "big"), dec_ids(g), dec_ids(r)


def encode_epoch_id(epoch: int, ident: str) -> bytes:
    """DESIGNATION, REVOKE_NOTICE, REVOKE_ACK, CLUSTER_OPEN payload: LP(epoch, ID)."""
    return LP(epoch.to_bytes(8, "big"), enc_id(ident))


def decode_epoch_id(raw: bytes) -> tuple[int, str]:
    e, i = unLP(raw, 2)
    return int.from_bytes(_fixed(e, 8, "epoch"), "big"), dec_id(i)


def encode_batch(items: list[tuple[str, bytes]]) -> bytes:
    return LP(*(LP(enc_id(cm), inner) for cm, inner in items))


def decode_batch(raw: bytes) -> list[tuple[str, bytes]]:
    out = []
    for item in codec.unLP_all(raw):
        cm, inner = unLP(item, 2)
        out.append((dec_id(cm), inner))
    return out


# -- unsealed messages ----------------------------------------------------------------------

def encode_relay(final_dst: str, inner: bytes) -> bytes:
    return bytes([V, RELAY]) + LP(enc_id(final_dst), inner)


def decode_relay(data: bytes) -> tuple[str, bytes]:
    dst, inner = unLP(body_of(data, V, RELAY), 2)
    return dec_id(dst), inner


def encode_open(id_ch: str, epoch: int) -> bytes:
    """CLUSTER_OPEN: an unauthenticated hint from a CH to a granted member to start its CM-BS
    handshake (docs/PLAN_ERRATA.md E-05). Acting on it costs at most one rate-limited AKE."""
    return bytes([V, CLUSTER_OPEN]) + encode_epoch_id(epoch, id_ch)


def decode_open(data: bytes) -> tuple[int, str]:
    return decode_epoch_id(body_of(data, V, CLUSTER_OPEN))


def hop_mac_input(sid_cm_ch: bytes, hop_seq: int, inner: bytes) -> bytes:
    """What the hop tag covers: LP(sid_CM-CH, hop_seq, inner) (follow-up D1)."""
    return LP(sid_cm_ch, hop_seq.to_bytes(8, "big"), inner)


def encode_data_cm(sid_cm_ch: bytes, hop_seq: int, inner: bytes, hop_tag: bytes) -> bytes:
    """DATA_CM = V || 0x40 || LP(sid_CM-CH, hop_seq, inner, hop_tag). The CM-CH sid lets the CH pick
    the hop key and report UNKNOWN_SESSION precisely (docs/PLAN_ERRATA.md E-05); hop_seq, covered by
    the hop tag, lets the CH reject a replayed frame before batching it (E-09, D1)."""
    return bytes([V, DATA_CM]) + LP(sid_cm_ch, hop_seq.to_bytes(8, "big"), inner, hop_tag)


def decode_data_cm(data: bytes) -> tuple[bytes, int, bytes, bytes]:
    sid, seq, inner, tag = unLP(body_of(data, V, DATA_CM), 4)
    return (_fixed(sid, SID_BYTES, "sid"), int.from_bytes(_fixed(seq, 8, "hop_seq"), "big"), inner,
            _fixed(tag, TAG_BYTES, "hop tag"))


def encode_session_unknown(sid: bytes, id_r: str, id_i: str) -> bytes:
    """Unauthenticated notice that `sid` is unknown at the responder (V-ADV-07): the initiator
    reacts only by starting a fresh handshake, never by trusting or destroying anything."""
    return bytes([V, SESSION_UNKNOWN]) + LP(sid, enc_id(id_r), enc_id(id_i))


def decode_session_unknown(data: bytes) -> tuple[bytes, str, str]:
    sid, r, i = unLP(body_of(data, V, SESSION_UNKNOWN), 3)
    return _fixed(sid, SID_BYTES, "sid"), dec_id(r), dec_id(i)


DECODERS = {
    "hs1": decode_hs1, "hs2": decode_hs2, "hs3": decode_hs3, "secure": decode_secure,
    "relay": decode_relay, "open": decode_open, "data_cm": decode_data_cm,
    "session_unknown": decode_session_unknown,
}
