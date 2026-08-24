"""Operation ledger: counts primitive operations so cost tables are derived from a run.

Realises: PLAN.md §6.2, P1.3. Counters T_HG, T_SM, T_PA, T_E/D, T_P, T_S, T_H, T_MAC, scoped
by (entity, phase).
"""

from __future__ import annotations

import functools
from collections import defaultdict
from collections.abc import Callable
from contextvars import ContextVar
from typing import Self, TypeVar

OPS = ("T_HG", "T_SM", "T_PA", "T_E/D", "T_P", "T_S", "T_H", "T_MAC")

F = TypeVar("F", bound=Callable[..., object])


class Ledger:
    def __init__(self) -> None:
        self._counts: dict[tuple[str, str, str], int] = defaultdict(int)

    def incr(self, op: str, entity: str, phase: str, n: int = 1) -> None:
        if op not in OPS:
            raise ValueError(f"unknown ledger op {op!r}; extend maka.ledger.OPS deliberately")
        self._counts[(entity, phase, op)] += n

    def total(self, entity: str, phase: str | None = None) -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for (e, ph, op), n in self._counts.items():
            if e == entity and (phase is None or ph == phase):
                out[op] += n
        return dict(out)

    def as_rows(self) -> list[tuple[str, str, str, int]]:
        return [(e, ph, op, n) for (e, ph, op), n in sorted(self._counts.items()) if n]

    def reset(self) -> None:
        self._counts.clear()


_ledger = Ledger()
_scope: ContextVar[tuple[str, str] | None] = ContextVar("ledger_scope", default=None)


def current() -> Ledger:
    return _ledger


class LedgerScope:
    """Context manager binding (entity, phase) for `@counts` calls made inside it."""

    def __init__(self, entity: str, phase: str) -> None:
        self.entity = entity
        self.phase = phase
        self._token = None

    def __enter__(self) -> Self:
        self._token = _scope.set((self.entity, self.phase))
        return self

    def __exit__(self, *exc: object) -> None:
        assert self._token is not None
        _scope.reset(self._token)


class suppressed:
    """Context manager: `@counts`-decorated calls inside become no-ops, regardless of any
    enclosing LedgerScope. Used where an outer operation's ledger price (e.g. T_E/D for
    Enc/Dec) already prices an inner operation our concrete instantiation happens to use
    (e.g. IBE's internal pairing) -- RP9's Table 2 treats T_E/D and T_P as independent line
    items, so counting the inner call again as T_P would double-charge one RP9 operation."""

    def __enter__(self) -> Self:
        self._token = _scope.set(None)
        return self

    def __exit__(self, *exc: object) -> None:
        _scope.reset(self._token)


def bump(op: str, n: int = 1) -> None:
    """Increments `op` in the ledger under the active LedgerScope, if any. Used where a
    constituent operation (e.g. a point addition inside scalar multiplication) needs to be
    counted as a secondary cost without wrapping it in its own decorated function."""
    scope = _scope.get()
    if scope is not None:
        _ledger.incr(op, scope[0], scope[1], n)


def counts(op: str, n: int = 1) -> Callable[[F], F]:
    """Decorator: every call increments `op` in the ledger under the active LedgerScope."""

    def deco(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            scope = _scope.get()
            if scope is not None:
                _ledger.incr(op, scope[0], scope[1], n)
            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return deco
