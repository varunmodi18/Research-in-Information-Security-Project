"""Seeded randomness source.

Realises: PLAN.md §0 rule 7 (determinism) and P0.3.

All randomness anywhere in this codebase flows through this module. A hygiene test
(tests/test_hygiene.py) forbids `random.` and `os.urandom` outside this file.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


def _default_seed() -> int:
    return int.from_bytes(hashlib.sha256(str(time.time_ns()).encode()).digest()[:8], "big")


@dataclass
class Rng:
    """A deterministic, seeded bit generator (SHA-256 counter mode).

    Not a claim of cryptographic-grade unpredictability beyond what SHA-256 counter mode
    provides; chosen so that a fixed seed reproduces byte-identical protocol runs (P13.8).
    """

    seed: int
    _counter: int = field(default=0, init=False)

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            h = hashlib.sha256()
            h.update((self.seed % (1 << 256)).to_bytes(32, "big"))
            h.update(self._counter.to_bytes(8, "big"))
            out.extend(h.digest())
            self._counter += 1
        return bytes(out[:n])

    def randint(self, lo: int, hi_exclusive: int) -> int:
        """Uniform integer in [lo, hi_exclusive)."""
        span = hi_exclusive - lo
        if span <= 0:
            raise ValueError("empty range")
        return lo + self.below(span)

    def below(self, n: int) -> int:
        """Uniform integer in [0, n) — the workhorse for scalar sampling."""
        if n <= 0:
            raise ValueError("n must be positive")
        nbytes = (n.bit_length() + 7) // 8 + 8
        val = int.from_bytes(self.bytes(nbytes), "big")
        return val % n

    def spawn(self, label: str) -> Rng:
        """Deterministic sub-stream, domain-separated by label."""
        h = hashlib.sha256()
        h.update(b"MAKA-RNG-SPAWN")
        h.update((self.seed % (1 << 256)).to_bytes(32, "big"))
        h.update(label.encode())
        sub_seed = int.from_bytes(h.digest(), "big")
        return Rng(seed=sub_seed)


_global_rng: Rng | None = None


def seed(value: int | None = None) -> Rng:
    """(Re-)initialise the process-global RNG. `None` draws a fresh, unreproducible seed."""
    global _global_rng
    _global_rng = Rng(seed=value if value is not None else _default_seed())
    return _global_rng


def current() -> Rng:
    global _global_rng
    if _global_rng is None:
        _global_rng = seed(0)
    return _global_rng


def run_id(seed_value: int, params: str, fixture: str) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"{stamp}-{seed_value}-{params}-{fixture}"
