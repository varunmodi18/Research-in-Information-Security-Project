"""The Lab's adversary module: protocol steps computed with whatever keys the attacker holds
(IMPLEMENTATION_PLAN.md §2.1 AT1-AT4, §6.3 V-ADV-*, M6).

Everything here uses only public values plus explicitly supplied stolen or guessed keys. Its
outputs are frames and verdicts; secret values never leave the Lab code (§4.4).
"""

from __future__ import annotations

from dataclasses import dataclass

from maka import codec, hashing, ibe
from maka.codec import DecodeError
from maka.curve import CurveParams, Point
from maka.enhanced import ake
from maka.enhanced import messages as m
from maka.kdf import ct_equal
from maka.protocol.p3_node_registration import xor_to_scalar
from maka.rng import RandomSource


@dataclass(frozen=True)
class ForgedHs1:
    payload: bytes
    x: int


def forge_hs1(curve: CurveParams, g: Point, rng: RandomSource, id_i: str, id_r: str, purpose: str,
              sid: bytes | None = None) -> ForgedHs1:
    """An HS1 claiming to come from id_i. Anyone can build one; completing the handshake needs PSK."""
    x = rng.randint(1, curve.r_group)
    payload = m.encode_hs1(sid or rng.bytes(m.SID_BYTES), id_i, id_r, purpose, rng.bytes(m.NONCE_BYTES),
                           codec.enc_point(x * g))
    return ForgedHs1(payload, x)


def forge_hs2(curve: CurveParams, g: Point, rng: RandomSource, hs1: bytes, psk_guess: bytes,
              responder_id: str | None = None) -> bytes:
    """Answers a captured HS1 as its responder, using the attacker's best PSK."""
    h = m.decode_hs1(hs1)
    x_pt = codec.dec_point(curve, h.x_raw)
    y = rng.randint(1, curve.r_group)
    body = m.hs2_body(h.sid, responder_id or h.id_r, h.id_i, rng.bytes(m.NONCE_BYTES), codec.enc_point(y * g))
    th = ake.transcript_hash(hs1, body)
    keys = ake.key_schedule(psk_guess, y * x_pt, th, h.purpose)
    return body + ake.tag_r(keys.kc_r, th)


def finish_as_initiator(curve: CurveParams, hs1: bytes, x: int, hs2: bytes, psk_guess: bytes) -> bytes | None:
    """Checks tag_R with the attacker's PSK; returns HS3 if it verifies, else None."""
    h1, h2 = m.decode_hs1(hs1), m.decode_hs2(hs2)
    th = ake.transcript_hash(hs1, h2.body)
    keys = ake.key_schedule(psk_guess, x * codec.dec_point(curve, h2.y_raw), th, h1.purpose)
    if not ct_equal(ake.tag_r(keys.kc_r, th), h2.tag):
        return None
    return m.encode_hs3(h1.sid, ake.tag_i(keys.kc_i, th))


def try_derive_session(curve: CurveParams, hs1: bytes, hs2: bytes, psk: bytes, z_candidates: list[Point]) -> bool:
    """Forward-secrecy probe (V-ADV-12): with recorded HS1/HS2 and the long-term PSK, does any
    candidate Z reproduce the recorded tag_R? Without x or y the attacker has no correct Z."""
    try:
        h1, h2 = m.decode_hs1(hs1), m.decode_hs2(hs2)
    except DecodeError:
        return False
    th = ake.transcript_hash(hs1, h2.body)
    for z in z_candidates:
        if z.is_infinity():
            continue
        if ct_equal(ake.tag_r(ake.key_schedule(psk, z, th, h1.purpose).kc_r, th), h2.tag):
            return True
    return False


def forge_rp9_em1(curve: CurveParams, g: Point, rng: RandomSource, k_pub: Point, id_bs: str, id_ch: str,
                  victim_id: str) -> bytes:
    """RP9 insider/outsider CH impersonation (P-01): A1 = rho*g, A2 = rho*(ID_BS xor ID_CH)*g needs
    only public values; the result is sealed to the victim's public key H(ID)."""
    rho = rng.randint(1, curve.r_group)
    a1 = rho * g
    a2 = rho * (xor_to_scalar(id_bs, id_ch, curve.r_group) * g)
    plaintext = codec.encode_auth(a1, a2, rng.bytes(codec.NONCE_BYTES))
    victim_pu = hashing.hash_to_point(curve, victim_id.encode())
    return codec.encode_ibe(ibe.encrypt(curve, g, plaintext, victim_pu, k_pub))
