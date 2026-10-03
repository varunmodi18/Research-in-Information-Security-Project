"""HKDF-SHA256, HMAC-SHA256 and constant-time comparison (IMPLEMENTATION_PLAN.md §4.6.1, M4-T1).

All primitives come from `cryptography` (IA-01 permits it); comparison uses
`hmac.compare_digest`. Calls are counted in the ledger as T_HKDF and T_MAC.
"""

from __future__ import annotations

import hmac as _hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as _chmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from maka import ledger


@ledger.counts("T_HKDF")
def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(bytes(ikm))


@ledger.counts("T_MAC")
def hmac256(key: bytes, msg: bytes) -> bytes:
    h = _chmac.HMAC(bytes(key), hashes.SHA256())
    h.update(msg)
    return h.finalize()


def ct_equal(a: bytes, b: bytes) -> bool:
    return _hmac.compare_digest(bytes(a), bytes(b))
