"""Wire codec: canonical encodings, validated decodings, and the original-mode messages.

Realises: IMPLEMENTATION_PLAN.md M1-T1 (I-06) and §4.6.1. Applies: IA-12 (subgroup
validation priced as T_SM_val), IA-13 (fixed 20-byte identifier field).

Every decoder either returns well-typed values or raises `DecodeError`; nothing else may
escape for any input (V-FUZZ-01). Every message starts with `version || type`:

    version 0x01  original-mode (RP9) messages, this module
    version 0x02  MAKA-E v1 messages, maka.enhanced.messages
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from maka import ibe, ledger
from maka.curve import CurveParams, Point
from maka.field import Fp, fp2_to_bytes

V_ORIGINAL = 0x01
V_ENHANCED = 0x02

ID_MAX_BYTES = 20
NONCE_BYTES = 20  # RP9 §7.2: nonce = 160 bits
_ID_PATTERN = re.compile(rb"[A-Za-z0-9-]{1,20}")

# original-mode message types
T_PUB = 0x01
T_BEACON = 0x02
T_PSEUDO_BS_CH = 0x03
T_PSEUDO_CH_CM = 0x04
T_AUTH = 0x05
T_IBE = 0x06
T_DATA = 0x07

enc_gt = fp2_to_bytes


class DecodeError(ValueError):
    """Malformed, truncated, or invalid input on the wire."""


# -- identities ---------------------------------------------------------------

def enc_id(ident: str) -> bytes:
    """UTF-8 bytes of an identifier: 1-20 bytes from [A-Za-z0-9-]. Raises ValueError."""
    raw = ident.encode("utf-8")
    if not _ID_PATTERN.fullmatch(raw):
        raise ValueError(f"invalid identifier {ident!r}: need 1-20 bytes of [A-Za-z0-9-]")
    return raw


def dec_id(raw: bytes) -> str:
    if not _ID_PATTERN.fullmatch(raw):
        raise DecodeError("invalid identifier on the wire")
    return raw.decode("ascii")


def id_field(ident: str) -> bytes:
    """The identifier left-aligned in a zero-padded 20-byte (160-bit) field (IA-13)."""
    return enc_id(ident).ljust(ID_MAX_BYTES, b"\x00")


# -- length-prefixed fields ---------------------------------------------------

def LP(*fields: bytes) -> bytes:
    """Concatenation of fields, each prefixed with a 2-byte big-endian length."""
    out = bytearray()
    for f in fields:
        if not isinstance(f, (bytes, bytearray)):
            raise TypeError(f"LP fields must be bytes, got {type(f).__name__}")
        if len(f) > 0xFFFF:
            raise ValueError("LP field longer than 65535 bytes")
        out += len(f).to_bytes(2, "big") + f
    return bytes(out)


def unLP_all(data: bytes) -> list[bytes]:
    """Splits a complete LP encoding into its fields. Rejects truncation."""
    fields = []
    i = 0
    while i < len(data):
        if i + 2 > len(data):
            raise DecodeError("truncated LP length prefix")
        n = int.from_bytes(data[i:i + 2], "big")
        i += 2
        if i + n > len(data):
            raise DecodeError("truncated LP field")
        fields.append(bytes(data[i:i + n]))
        i += n
    return fields


def unLP(data: bytes, n: int) -> list[bytes]:
    """Exactly n LP fields; rejects truncation and trailing bytes."""
    fields = unLP_all(data)
    if len(fields) != n:
        raise DecodeError(f"expected {n} LP fields, got {len(fields)}")
    return fields


# -- points -------------------------------------------------------------------

def point_width(curve: CurveParams) -> int:
    return (curve.p_field.bit_length() + 7) // 8


def enc_point(pt: Point) -> bytes:
    """Fixed-width uncompressed x || y. The point at infinity has no encoding."""
    if pt.is_infinity():
        raise ValueError("the point at infinity has no wire encoding")
    assert pt.x is not None and pt.y is not None  # type narrowing only
    w = point_width(pt.params)
    return pt.x.val.to_bytes(w, "big") + pt.y.val.to_bytes(w, "big")


def dec_point(curve: CurveParams, data: bytes) -> Point:
    """Decodes and validates a point: right length, coordinates < p_field, on the curve, not
    infinity, and in the order-r_group subgroup (r*P = O).

    The subgroup check costs one scalar multiplication. It is counted under the separate
    ledger counter T_SM_val (IA-12) so RP9's Table 2 T_SM column stays comparable."""
    w = point_width(curve)
    if len(data) != 2 * w:
        raise DecodeError(f"point encoding must be {2 * w} bytes, got {len(data)}")
    x = int.from_bytes(data[:w], "big")
    y = int.from_bytes(data[w:], "big")
    if x == 0 and y == 0:
        raise DecodeError("all-zero encoding (point at infinity) rejected")
    if x >= curve.p_field or y >= curve.p_field:
        raise DecodeError("coordinate out of range")
    pt = Point(Fp(x, curve.p_field), Fp(y, curve.p_field), curve)
    if not pt.is_on_curve():
        raise DecodeError("point is not on the curve")
    with ledger.suppressed():
        in_subgroup = pt.scalar_mul_unaccounted(curve.r_group).is_infinity()
    ledger.bump("T_SM_val")
    if not in_subgroup:
        raise DecodeError("point is not in the order-r_group subgroup")
    return pt


# -- message framing ------------------------------------------------------------

def header(version: int, mtype: int) -> bytes:
    return bytes([version, mtype])


def body_of(data: bytes, version: int, mtype: int) -> bytes:
    """Strips and checks the `version || type` header."""
    if len(data) < 2:
        raise DecodeError("message shorter than its header")
    if data[0] != version:
        raise DecodeError(f"wrong protocol version 0x{data[0]:02x}")
    if data[1] != mtype:
        raise DecodeError(f"wrong message type 0x{data[1]:02x}")
    return data[2:]


def _nonce(raw: bytes) -> bytes:
    if len(raw) != NONCE_BYTES:
        raise DecodeError(f"nonce must be {NONCE_BYTES} bytes")
    return raw


# -- original-mode (RP9) messages, version 0x01 ------------------------------------

def encode_pub(pu: Point) -> bytes:
    """PUB_CH / PUB_CM: a node's public key Pu_i (RP9 §5.2)."""
    return header(V_ORIGINAL, T_PUB) + LP(enc_point(pu))


def decode_pub(curve: CurveParams, data: bytes) -> Point:
    (raw,) = unLP(body_of(data, V_ORIGINAL, T_PUB), 1)
    return dec_point(curve, raw)


def encode_beacon(id_ch: str, members: list[tuple[str, Point]], n_reg: bytes) -> bytes:
    """BEACON plaintext (RP9 §5.3): ID_CH, [ID_CM...], [Pu_CM...], N_reg."""
    ids = LP(*(enc_id(i) for i, _ in members))
    pts = LP(*(enc_point(pu) for _, pu in members))
    return header(V_ORIGINAL, T_BEACON) + LP(enc_id(id_ch), ids, pts, _nonce(n_reg))


@dataclass(frozen=True)
class Beacon:
    id_ch: str
    members: list[tuple[str, Point]]
    n_reg: bytes


def decode_beacon(curve: CurveParams, data: bytes) -> Beacon:
    raw_ch, raw_ids, raw_pts, raw_n = unLP(body_of(data, V_ORIGINAL, T_BEACON), 4)
    ids = [dec_id(i) for i in unLP_all(raw_ids)]
    pts = unLP_all(raw_pts)
    if len(ids) != len(pts):
        raise DecodeError("beacon member-ID and public-key counts differ")
    if len(set(ids)) != len(ids):
        raise DecodeError("duplicate member ID in beacon")
    return Beacon(dec_id(raw_ch), [(i, dec_point(curve, pt)) for i, pt in zip(ids, pts)],
                  _nonce(raw_n))


def encode_pseudo_bs_ch(p_ch: Point, p_cms: list[Point]) -> bytes:
    """PSEUDO_BS_CH plaintext (RP9 §5.3): P_CH, then each P_CM in the order the members
    appeared in the CH's beacon (RP9 sends no member IDs here, so none are added)."""
    return header(V_ORIGINAL, T_PSEUDO_BS_CH) + LP(enc_point(p_ch), LP(*(enc_point(pt) for pt in p_cms)))


def decode_pseudo_bs_ch(curve: CurveParams, data: bytes) -> tuple[Point, list[Point]]:
    raw_pch, raw_pts = unLP(body_of(data, V_ORIGINAL, T_PSEUDO_BS_CH), 2)
    return dec_point(curve, raw_pch), [dec_point(curve, pt) for pt in unLP_all(raw_pts)]


def encode_pseudo_ch_cm(id_ch: str, p_cm: Point) -> bytes:
    """PSEUDO_CH_CM plaintext: ID_CH (IA-14, an addition to RP9) and P_CM."""
    return header(V_ORIGINAL, T_PSEUDO_CH_CM) + LP(enc_id(id_ch), enc_point(p_cm))


def decode_pseudo_ch_cm(curve: CurveParams, data: bytes) -> tuple[str, Point]:
    raw_id, raw_pt = unLP(body_of(data, V_ORIGINAL, T_PSEUDO_CH_CM), 2)
    return dec_id(raw_id), dec_point(curve, raw_pt)


def encode_auth(a: Point, b: Point, nonce: bytes) -> bytes:
    """EM1/EM2 plaintext (A1, A2, N_auth_CH) or EM3 plaintext (A3, A4, N_auth_CM), RP9 §5.4."""
    return header(V_ORIGINAL, T_AUTH) + LP(enc_point(a), enc_point(b), _nonce(nonce))


def decode_auth(curve: CurveParams, data: bytes) -> tuple[Point, Point, bytes]:
    raw_a, raw_b, raw_n = unLP(body_of(data, V_ORIGINAL, T_AUTH), 3)
    return dec_point(curve, raw_a), dec_point(curve, raw_b), _nonce(raw_n)


def encode_ibe(ct: ibe.Ciphertext) -> bytes:
    """An IBE ciphertext (IA-03) as frame payload: U and the DEM body."""
    return header(V_ORIGINAL, T_IBE) + LP(enc_point(ct.u_point), ct.body)


def decode_ibe(curve: CurveParams, data: bytes) -> ibe.Ciphertext:
    raw_u, body = unLP(body_of(data, V_ORIGINAL, T_IBE), 2)
    return ibe.Ciphertext(u_point=dec_point(curve, raw_u), body=body)


def encode_data(seq: int, blob: bytes) -> bytes:
    """DATA_CM: per-sender sequence number and the AEAD blob (IA-16)."""
    return header(V_ORIGINAL, T_DATA) + LP(seq.to_bytes(8, "big"), blob)


def decode_data(data: bytes) -> tuple[int, bytes]:
    raw_seq, blob = unLP(body_of(data, V_ORIGINAL, T_DATA), 2)
    if len(raw_seq) != 8:
        raise DecodeError("sequence number must be 8 bytes")
    return int.from_bytes(raw_seq, "big"), blob


DECODERS = {
    "pub": decode_pub,
    "beacon": decode_beacon,
    "pseudo_bs_ch": decode_pseudo_bs_ch,
    "pseudo_ch_cm": decode_pseudo_ch_cm,
    "auth": decode_auth,
    "ibe": decode_ibe,
}
