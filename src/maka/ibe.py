"""Enc/Dec instantiation (IA-03): Boneh-Franklin IBE in hybrid form.

RP9 Table 1 leaves Enc/Dec abstract ('asymmetric encryption/decryption of m using the key
k') -- AM-01. Since node keys have the shape Pu_i = H(ID_i), Pr_i = k*Pu_i, the natural
concrete scheme is Boneh-Franklin IBE:

    Enc(m, Pu_i):        u <-$ Z_r ; U = u*g ; K = KDF(e(Pu_i, K_pub)^u) ; V = AEAD_K(m) ; c=(U,V)
    Dec((U, V), Pr_i):   K = KDF(e(Pr_i, U)) ; m = AEAD^-1_K(V)

Correct because e(Pr_i, U) = e(k*Pu_i, u*g) = e(Pu_i, g)^(ku) = e(Pu_i, k*g)^u = e(Pu_i, K_pub)^u.

K_pub = k*g is scaffolding entailed by this choice -- NOT a missing RP9 parameter; every
parameter dump labels it accordingly ([IA-03 scaffolding]).
"""

from __future__ import annotations

from dataclasses import dataclass

from maka import hashing, ledger, pairing, rng, trace
from maka.aead import decrypt as aead_decrypt
from maka.aead import encrypt as aead_encrypt
from maka.curve import CurveParams, Point
from maka.field import fp2_to_bytes

DEM_KEY_BYTES = 32


@dataclass(frozen=True)
class Ciphertext:
    u_point: Point
    body: bytes  # AEAD(nonce || ct || tag) over the DEM plaintext


@ledger.counts("T_E/D")
def encrypt(curve: CurveParams, g: Point, message: bytes, recipient_pu: Point, k_pub: Point) -> Ciphertext:
    """Enc(message, Pu_recipient), under [IA-03]."""
    t = trace.active()
    u_scalar = rng.current().below(curve.r_group)
    u_point = u_scalar * g
    shared = pairing.modified_pairing(curve, recipient_pu, k_pub) ** u_scalar
    key = hashing.kdf(fp2_to_bytes(shared), b"MAKA-IBE-DEM", DEM_KEY_BYTES)
    body = aead_encrypt(key, message)
    if t.verbosity >= 2:
        t.register("IA-03", "Boneh-Franklin IBE hybrid: U=u*g, K=KDF(e(Pu,K_pub)^u), V=AEAD_K(m)")
        t.value("ibe.U", u_point)
        t.value("ibe.DEM_key_fingerprint", key[:8])
    return Ciphertext(u_point=u_point, body=body)


@ledger.counts("T_E/D")
def decrypt(curve: CurveParams, ciphertext: Ciphertext, recipient_pr: Point) -> bytes:
    """Dec(ciphertext, Pr_recipient), under [IA-03]."""
    t = trace.active()
    shared = pairing.modified_pairing(curve, recipient_pr, ciphertext.u_point)
    key = hashing.kdf(fp2_to_bytes(shared), b"MAKA-IBE-DEM", DEM_KEY_BYTES)
    if t.verbosity >= 2:
        t.value("ibe.DEM_key_fingerprint", key[:8])
    return aead_decrypt(key, ciphertext.body)
