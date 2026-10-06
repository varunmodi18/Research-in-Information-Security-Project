"""Per-device secret store (IMPLEMENTATION_PLAN.md §4.3, §4.4, M2-T2).

Values are held as `bytearray` so `destroy` can overwrite them with zeros before dropping
them. Python may still hold copies made while computing with a value (ints, bytes returned
by `get`); this is best-effort zeroisation, documented as a residual (I-09).

A persistence adapter (implemented in maka_server, M3-T3) mirrors every change; values are
encrypted there, never stored in clear (§4.4 rule 2).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from maka.runtime.errors import KeystoreError


class SecretClass(str, Enum):
    SECRET = "SECRET"
    PUBLIC = "PUBLIC"


class KeystoreAdapter(Protocol):
    def save(self, device_id: str, name: str, cls: SecretClass, value: bytes) -> None: ...
    def delete(self, device_id: str, name: str) -> None: ...


@dataclass
class _Entry:
    value: bytearray
    cls: SecretClass


class Keystore:
    def __init__(self, device_id: str, adapter: KeystoreAdapter | None = None) -> None:
        self.device_id = device_id
        self._entries: dict[str, _Entry] = {}
        self._adapter = adapter

    def attach(self, adapter: KeystoreAdapter | None, *, replay: bool = False) -> None:
        """Sets the persistence adapter. With replay=True the keystore pushes the entries it already
        holds (e.g. written during provisioning) to the adapter, so the server never has to read a
        keystore to persist it (follow-up E2)."""
        self._adapter = adapter
        if replay and adapter is not None:
            for name, entry in self._entries.items():
                adapter.save(self.device_id, name, entry.cls, bytes(entry.value))

    def put(self, name: str, value: bytes | bytearray, cls: SecretClass) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("keystore values are bytes (encode points with maka.codec)")
        if name in self._entries:
            self.destroy(name)
        self._entries[name] = _Entry(bytearray(value), SecretClass(cls))
        if self._adapter is not None:
            self._adapter.save(self.device_id, name, SecretClass(cls), bytes(value))

    def get(self, name: str) -> bytes:
        """Runtime-internal only; nothing in maka_server may call this (§4.3)."""
        entry = self._entries.get(name)
        if entry is None:
            raise KeystoreError(f"{self.device_id}: no keystore entry {name!r}")
        return bytes(entry.value)

    def has(self, name: str) -> bool:
        return name in self._entries

    def cls_of(self, name: str) -> SecretClass:
        return self._entries[name].cls

    def destroy(self, name: str) -> bool:
        """Overwrites the stored bytes with zeros, then removes the entry. Returns whether it existed."""
        entry = self._entries.pop(name, None)
        if entry is None:
            return False
        for i in range(len(entry.value)):
            entry.value[i] = 0
        if self._adapter is not None:
            self._adapter.delete(self.device_id, name)
        return True

    def destroy_prefix(self, prefix: str) -> int:
        names = [n for n in self._entries if n.startswith(prefix)]
        for n in names:
            self.destroy(n)
        return len(names)

    def destroy_all(self) -> None:
        for n in list(self._entries):
            self.destroy(n)

    def names(self) -> list[str]:
        return sorted(self._entries)

    def total_bytes(self, cls: SecretClass | None = None) -> int:
        return sum(len(e.value) for e in self._entries.values() if cls is None or e.cls == cls)

    def load_raw(self, entries: dict[str, tuple[SecretClass, bytes]]) -> None:
        """Restores entries from persistence without echoing them back to the adapter."""
        for name, (cls, value) in entries.items():
            self._entries[name] = _Entry(bytearray(value), SecretClass(cls))

    def snapshot(self) -> dict[str, bytes]:
        """A copy of every entry. Used only by adversary.capture (lab) and test hooks."""
        return {n: bytes(e.value) for n, e in self._entries.items()}
