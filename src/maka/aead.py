"""Symmetric layer for sensed data (IA-06).

RP9 states only that shared keys 'are used for encryption and decryption'; SK_{i-BS} is a
G_2 element, not a symmetric key, so k_sym = KDF("MAKA-DATA" || ID_BS || ID_i || SK_{i-BS})
feeds AES-256-GCM. An adapter for demonstration, not a claim about MAKA -- marked [IA-06]
at every call site.

Associated data is mandatory (IMPLEMENTATION_PLAN.md M1-T8, I-10): every caller states what
the ciphertext is bound to. Callers that reuse a key across messages pass a counter nonce
(`counter_nonce`); single-use keys (IBE DEM keys) may let the nonce be drawn from maka.rng.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from maka import ledger, rng, trace

NONCE_BYTES = 12
MAX_SEQ = 2**64 - 1


def counter_nonce(seq: int) -> bytes:
    """0x00000000 || seq (8 bytes, big-endian). Unique per key as long as each sender uses each
    seq at most once with that key (IMPLEMENTATION_PLAN.md §4.6.6)."""
    if not 0 < seq <= MAX_SEQ:
        raise ValueError("sequence number out of range")
    return bytes(4) + seq.to_bytes(8, "big")


@ledger.counts("T_S")
def encrypt(key: bytes, plaintext: bytes, *, ad: bytes, nonce: bytes | None = None) -> bytes:
    """Returns nonce || ciphertext_with_tag. `key` must be 32 bytes (AES-256)."""
    t = trace.active()
    if nonce is None:
        nonce = rng.current().bytes(NONCE_BYTES)
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be {NONCE_BYTES} bytes")
    ct = AESGCM(key).encrypt(nonce, plaintext, ad)
    if t.verbosity >= 2:
        t.register("IA-06", "AES-256-GCM adapter over a KDF-derived symmetric key -- ours, "
                             "not a claim about RP9's abstract 'encryption/decryption'")
    return nonce + ct


@ledger.counts("T_S")
def decrypt(key: bytes, blob: bytes, *, ad: bytes) -> bytes:
    """Inverse of encrypt. Raises cryptography.exceptions.InvalidTag on any mismatch."""
    nonce, ct = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ct, ad)


def encrypt_seq(key: bytes, plaintext: bytes, *, ad: bytes, seq: int) -> bytes:
    """Counter-nonce encryption whose nonce is NOT transmitted: the receiver rebuilds it from the
    seq it already gets in the message (follow-up D6, saves NONCE_BYTES per message). Returns
    ciphertext_with_tag only."""
    return encrypt(key, plaintext, ad=ad, nonce=counter_nonce(seq))[NONCE_BYTES:]


def decrypt_seq(key: bytes, ciphertext: bytes, *, ad: bytes, seq: int) -> bytes:
    """Inverse of encrypt_seq. Raises InvalidTag on any mismatch, ValueError on a seq out of range."""
    return decrypt(key, counter_nonce(seq) + ciphertext, ad=ad)
