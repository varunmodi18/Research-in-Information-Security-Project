"""Symmetric layer for sensed data (IA-06).

RP9 states only that shared keys 'are used for encryption and decryption'; SK_{i-BS} is a
G_2 element, not a symmetric key, so k_sym = KDF("MAKA-DATA" || ID_i || ID_BS || SK_{i-BS})
feeds AES-256-GCM. An adapter for demonstration, not a claim about MAKA -- marked [IA-06]
at every call site.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from maka import ledger, trace

NONCE_BYTES = 12


@ledger.counts("T_S")
def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Returns nonce || ciphertext_with_tag. `key` must be 32 bytes (AES-256)."""
    t = trace.active()
    from maka import rng

    nonce = rng.current().bytes(NONCE_BYTES)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    if t.verbosity >= 2:
        t.register("IA-06", "AES-256-GCM adapter over a KDF-derived symmetric key -- ours, "
                             "not a claim about RP9's abstract 'encryption/decryption'")
    return nonce + ct


@ledger.counts("T_S")
def decrypt(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    nonce, ct = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data)
