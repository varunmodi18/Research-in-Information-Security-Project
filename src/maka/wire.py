"""Wire accountant: RP9 §7.2's paper-model message sizes.

Realises: PLAN.md §6.3, P1.4. "paper" sizing is RP9 §7.2's abstraction (point = 320 bits,
id/nonce = 160 bits) and reproduces Table 3. Real encodings and their lengths live in
maka.codec (IMPLEMENTATION_PLAN.md M1-T1); the actual-size diagnostic (OB-03) measures the
encoded frame payloads directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from maka import trace

PAPER_SIZES = {
    "id": 160,
    "nonce": 160,
    "point": 320,
}


@dataclass
class Sized:
    """Wraps a value with an explicit paper-model bit count, for fields with no natural
    `paper_bits()` (e.g. plain XOR operands, raw identifiers)."""

    value: Any
    bits: int

    def paper_bits(self) -> int:
        return self.bits


def _render_sized(obj: Sized, verbosity: int) -> str:
    return f"{trace.render(obj.value, verbosity)}  ({obj.bits} bits, paper model)"


trace.register_renderer("Sized", _render_sized)


def _paper_bits(item: Any) -> int:
    if hasattr(item, "paper_bits"):
        return int(item.paper_bits())
    if isinstance(item, bytes):
        return len(item) * 8
    raise TypeError(f"{type(item)} has no paper_bits(); wrap it in wire.Sized(value, bits)")


def size(items: list[Any]) -> tuple[int, dict[str, int]]:
    """Returns (total paper-model bits, itemisation) for a message made of `items`, given as
    (name, item) pairs or bare items (named by position)."""
    itemisation: dict[str, int] = {}
    total = 0
    for i, item in enumerate(items):
        name, value = item if isinstance(item, tuple) else (f"field{i}", item)
        bits = _paper_bits(value)
        itemisation[name] = bits
        total += bits
    return total, itemisation
