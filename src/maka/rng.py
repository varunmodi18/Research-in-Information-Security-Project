"""Seeded randomness source.

Realises: PLAN.md §0 rule 7 (determinism) and P0.3; IMPLEMENTATION_PLAN.md §4.3 (SystemSource).

All randomness anywhere in this codebase flows through this module. A hygiene test
(tests/test_hygiene.py) forbids `random.` and `os.urandom` outside this file.

The current source is context-local (one per thread), so each network's worker thread can
run its own seeded or system source without interleaving with another network's.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Protocol


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


class RandomSource(Protocol):
    def bytes(self, n: int) -> bytes: ...
    def randint(self, lo: int, hi_exclusive: int) -> int: ...
    def below(self, n: int) -> int: ...
    def spawn(self, label: str) -> RandomSource: ...


class SystemSource:
    """Operating-system entropy for product networks (IMPLEMENTATION_PLAN.md §4.3). The only
    `os.urandom` call site in the codebase. Not reproducible by design."""

    def bytes(self, n: int) -> bytes:
        return os.urandom(n)

    def randint(self, lo: int, hi_exclusive: int) -> int:
        span = hi_exclusive - lo
        if span <= 0:
            raise ValueError("empty range")
        return lo + self.below(span)

    def below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        # 64 extra bits make the modulo bias negligible (< 2^-64)
        nbytes = (n.bit_length() + 7) // 8 + 8
        return int.from_bytes(os.urandom(nbytes), "big") % n

    def spawn(self, label: str) -> SystemSource:
        return SystemSource()


_current: ContextVar[RandomSource | None] = ContextVar("maka_rng", default=None)


def seed(value: int | None = None) -> Rng:
    """(Re-)initialise this context's RNG. `None` draws a fresh, unreproducible seed."""
    r = Rng(seed=value if value is not None else _default_seed())
    _current.set(r)
    return r


def use(source: RandomSource) -> RandomSource:
    """Makes `source` the current source for this context (thread)."""
    _current.set(source)
    return source


@contextmanager
def using(source: RandomSource) -> Iterator[RandomSource]:
    """Scopes `source` as the current source, restoring the previous one afterwards."""
    token = _current.set(source)
    try:
        yield source
    finally:
        _current.reset(token)


def current() -> RandomSource:
    source = _current.get()
    if source is None:
        source = seed(0)
    return source


def run_id(seed_value: int, params: str, fixture: str) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"{stamp}-{seed_value}-{params}-{fixture}"
