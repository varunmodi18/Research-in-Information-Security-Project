"""Wire accountant: canonical serialisation and message-size accounting.

Realises: PLAN.md §6.3, P1.4. Two sizing modes:
- "paper": RP9 §7.2's abstraction (point = 320 bits, id/nonce = 160 bits) — reproduces Table 3.
- "actual": real encoded lengths of our concrete instantiation — an implementation diagnostic,
  never a correction to RP9 (see OB-03).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from maka import trace

PAPER_SIZES = {
    "id": 160,
    "nonce": 160,
    "point": 320,
}


class WireEncodable(Protocol):
    def paper_bits(self) -> int: ...
    def to_bytes(self) -> bytes: ...


@dataclass
class Sized:
    """Wraps a value with an explicit paper-model bit count, for fields with no natural
    `paper_bits()` (e.g. plain XOR operands, raw identifiers)."""

    value: Any
    bits: int

    def paper_bits(self) -> int:
        return self.bits

    def to_bytes(self) -> bytes:
        if isinstance(self.value, bytes):
            return self.value
        return repr(self.value).encode()


def _render_sized(obj: Sized, verbosity: int) -> str:
    return f"{trace.render(obj.value, verbosity)}  ({obj.bits} bits, paper model)"


trace.register_renderer("Sized", _render_sized)


def _paper_bits(item: Any) -> int:
    if hasattr(item, "paper_bits"):
        return item.paper_bits()
    if isinstance(item, Sized):
        return item.bits
    if isinstance(item, bytes):
        return len(item) * 8
    raise TypeError(f"{type(item)} has no paper_bits(); wrap it in wire.Sized(value, bits)")


def _actual_bytes(item: Any) -> bytes:
    if hasattr(item, "to_bytes") and not isinstance(item, int):
        return item.to_bytes()
    if isinstance(item, Sized):
        return item.to_bytes()
    if isinstance(item, bytes):
        return item
    raise TypeError(f"{type(item)} has no to_bytes()")


def size(items: list[Any], sizing: str = "paper") -> tuple[int, dict[str, int]]:
    """Returns (total_bits, itemisation) for a message made of `items`, each named implicitly
    by its position. Callers that want named itemisation should pass (name, item) pairs."""
    itemisation: dict[str, int] = {}
    total = 0
    for i, item in enumerate(items):
        name, value = item if isinstance(item, tuple) else (f"field{i}", item)
        bits = _paper_bits(value) if sizing == "paper" else len(_actual_bytes(value)) * 8
        itemisation[name] = bits
        total += bits
    return total, itemisation


def encode(items: list[tuple[str, Any]]) -> tuple[bytes, dict[str, int]]:
    """Canonical actual-wire encoding: length-prefixed concatenation. Returns (bytes, itemisation)."""
    out = bytearray()
    itemisation: dict[str, int] = {}
    for name, value in items:
        b = _actual_bytes(value)
        out += len(b).to_bytes(4, "big") + b
        itemisation[name] = len(b) * 8
    return bytes(out), itemisation
