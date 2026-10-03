"""Encrypted keystore persistence (IMPLEMENTATION_PLAN.md §4.4 rule 2, M3-T3).

Each entry is AES-256-GCM encrypted under the KEK with a fresh random nonce and associated
data LP(network_id, device_id, name), so a ciphertext cannot be moved to another device or
renamed. Only long-term entries are persisted: session and ephemeral entries (prefixes in
EPHEMERAL) never reach the disk, because after a restart every session is aborted anyway
(§4.8 recovery rule). Changes are buffered and written in the runtime's snapshot transaction.
"""

from __future__ import annotations

import threading

from cryptography.exceptions import InvalidTag
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from maka import aead, codec
from maka.rng import SystemSource
from maka.runtime.keystore import SecretClass
from maka_server import models

EPHEMERAL = ("sess:", "eph:", "hs:", "ksym", "r_ch")


def persistable(name: str) -> bool:
    return not name.startswith(EPHEMERAL)


def entry_ad(network_id: int, device_ident: str, name: str) -> bytes:
    return codec.LP(str(network_id).encode(), device_ident.encode(), name.encode())


class EncryptedKeystoreAdapter:
    def __init__(self, kek: bytes, network_id: int) -> None:
        self._kek = kek
        self.network_id = network_id
        self._pending: dict[tuple[str, str], tuple[str, bytes] | None] = {}
        self._lock = threading.Lock()

    # KeystoreAdapter protocol -------------------------------------------------------

    def save(self, device_id: str, name: str, cls: SecretClass, value: bytes) -> None:
        if persistable(name):
            with self._lock:
                self._pending[(device_id, name)] = (cls.value, bytes(value))

    def delete(self, device_id: str, name: str) -> None:
        with self._lock:
            self._pending[(device_id, name)] = None

    # persistence ------------------------------------------------------------------

    def flush(self, db: Session, device_row_ids: dict[str, int]) -> int:
        with self._lock:
            ops, self._pending = self._pending, {}
        for (ident, name), op in ops.items():
            dev_id = device_row_ids.get(ident)
            if dev_id is None:
                continue
            db.execute(delete(models.KeystoreEntry).where(models.KeystoreEntry.device_id == dev_id,
                                                          models.KeystoreEntry.name == name))
            if op is not None:
                cls, value = op
                nonce = SystemSource().bytes(aead.NONCE_BYTES)
                blob = aead.encrypt(self._kek, value, ad=entry_ad(self.network_id, ident, name), nonce=nonce)
                db.add(models.KeystoreEntry(device_id=dev_id, name=name, cls=cls,
                                            ciphertext=blob[aead.NONCE_BYTES:], nonce=nonce))
        return len(ops)

    def load(self, db: Session, device_row_id: int, ident: str) -> dict[str, tuple[SecretClass, bytes]]:
        out: dict[str, tuple[SecretClass, bytes]] = {}
        rows = db.scalars(select(models.KeystoreEntry).where(models.KeystoreEntry.device_id == device_row_id))
        for row in rows:
            try:
                value = aead.decrypt(self._kek, row.nonce + row.ciphertext,
                                     ad=entry_ad(self.network_id, ident, row.name))
            except InvalidTag as exc:
                raise RuntimeError(f"keystore entry {ident}/{row.name} failed to decrypt "
                                   "(wrong MAKA_KEK or tampered database)") from exc
            out[row.name] = (SecretClass(row.cls), value)
        return out
