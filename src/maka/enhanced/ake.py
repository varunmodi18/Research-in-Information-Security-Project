"""C2 pairwise PSKs and C3 authenticated key exchange (IMPLEMENTATION_PLAN.md §4.6.3-4.6.4).

PSK_AB = HKDF(enc_gt(ê(Pr_A, H(ID_B))), "MAKA-E/v1/psk", LP(lo, hi), 32). Both ends get the same
value because ê is symmetric and bilinear: both equal ê(Pu_A, Pu_B)^k. The BS, which holds k,
can compute any PSK; no third device can (BDH).

HS1 I->R : V||0x10||LP(sid, ID_I, ID_R, purpose, N_I, X)            X = x*g
HS2 R->I : V||0x11||LP(sid, ID_R, ID_I, N_R, Y) || tag_R              Y = y*g
HS3 I->R : V||0x12||LP(sid) || tag_I
Z = x*Y = y*X;  th = SHA-256(HS1 || HS2 without tag)
okm = HKDF(PSK || enc_point(Z), salt=th, info=LP("MAKA-E/v1/keys", purpose), 128)
kc_R | kc_I | k_IR | k_RI = okm;  tag_R = HMAC(kc_R, "HS2"||th);  tag_I = HMAC(kc_I, "HS3"||th)

The pure functions here are also what the Lab's adversary module calls with stolen keys.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from maka import codec, hashing, ledger, pairing
from maka.codec import LP
from maka.curve import CurveParams, Point
from maka.kdf import hkdf, hmac256

PSK_SALT = b"MAKA-E/v1/psk"
KEYS_LABEL = b"MAKA-E/v1/keys"


def psk_info(id_a: str, id_b: str) -> bytes:
    lo, hi = sorted([id_a, id_b])
    return LP(codec.enc_id(lo), codec.enc_id(hi))


def psk_from_shared(shared_gt_bytes: bytes, id_a: str, id_b: str) -> bytes:
    return hkdf(shared_gt_bytes, PSK_SALT, psk_info(id_a, id_b), 32)


def compute_psk(curve: CurveParams, my_pr: Point, my_id: str, peer_id: str) -> bytes:
    """S_AB = ê(Pr_A, Pu_B) with Pu_B = H(ID_B), then HKDF (one pairing, one T_HG)."""
    s_ab = pairing.modified_pairing(curve, my_pr, hashing.hash_to_point(curve, peer_id.encode()))
    return psk_from_shared(codec.enc_gt(s_ab), my_id, peer_id)


def psk_with_master_key(curve: CurveParams, k: int, id_a: str, id_b: str) -> bytes:
    """The BS's view: ê(Pu_A, Pu_B)^k, available to whoever holds k (V-UNIT-10)."""
    pu_a = hashing.hash_to_point(curve, id_a.encode())
    pu_b = hashing.hash_to_point(curve, id_b.encode())
    return psk_from_shared(codec.enc_gt(pairing.modified_pairing(curve, pu_a, pu_b) ** k), id_a, id_b)


def transcript_hash(hs1: bytes, hs2_without_tag: bytes) -> bytes:
    ledger.bump("T_H")
    return hashlib.sha256(hs1 + hs2_without_tag).digest()


@dataclass(frozen=True)
class SessionKeys:
    kc_r: bytes
    kc_i: bytes
    k_ir: bytes
    k_ri: bytes


def key_schedule(psk: bytes, z: Point, th: bytes, purpose: str) -> SessionKeys:
    if z.is_infinity():
        raise ValueError("Z is the point at infinity")
    okm = hkdf(bytes(psk) + codec.enc_point(z), th, LP(KEYS_LABEL, purpose.encode()), 128)
    return SessionKeys(okm[0:32], okm[32:64], okm[64:96], okm[96:128])


def tag_r(kc_r: bytes, th: bytes) -> bytes:
    return hmac256(kc_r, b"HS2" + th)


def tag_i(kc_i: bytes, th: bytes) -> bytes:
    return hmac256(kc_i, b"HS3" + th)


def hop_mac_key(k_cm_ch: bytes) -> bytes:
    """§4.6.6: MAC key for the CM->CH hop, derived from the CM-CH session's CM->CH key."""
    return hkdf(k_cm_ch, b"", b"hop-mac", 32)
