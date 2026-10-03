"""Entity base: state plus dump_state() (P5.2).

dump_state() is an observability tool for demonstration transcripts, not the authority for
Table 4 storage figures -- see PLAN.md P12.4 (AM-07). Subclasses declare which attributes
are storage-relevant via STORAGE_FIELDS = [(attr_name, paper_bits), ...].

Every entity carries a verification status (I-07, IMPLEMENTATION_PLAN.md M1-T5): a peer whose
verification fails is marked `failed` and excluded from later phases.
"""

from __future__ import annotations

from typing import ClassVar

from maka import trace

OK = "ok"
FAILED = "failed"


class ProtocolError(RuntimeError):
    """A protocol precondition was violated (replaces bare `assert`, which `python -O` strips)."""


# SECRET-class attributes (IMPLEMENTATION_PLAN.md §4.4): print_state() shows only «secret:name».
SECRET_FIELDS = frozenset({"k", "pr_i", "pr_bs", "r_ch", "r_cm", "sk_cm_bs", "sk_ch_bs"})


class Entity:
    STORAGE_FIELDS: ClassVar[list[tuple[str, int]]] = []

    def __init__(self, identity: str) -> None:
        self.identity = identity
        self.status = OK
        self.failure_reason: str | None = None

    def mark_failed(self, reason: str, observer: str, peer: str | None = None) -> None:
        """Excludes this entity from later phases and emits ORIG_AUTH_FAIL at `observer`.

        `peer` is the identity `observer` failed to authenticate; it defaults to this entity.
        (A CM that cannot authenticate its CH excludes itself, with the CH as the peer.)"""
        t = trace.active()
        if self.status != FAILED:
            self.status = FAILED
            self.failure_reason = reason
        t.event("ORIG_AUTH_FAIL", observer, peer=peer or self.identity, reason=reason)

    @property
    def failed(self) -> bool:
        return self.status == FAILED

    def dump_state(self) -> list[tuple[str, object, int]]:
        rows = []
        for attr, bits in self.STORAGE_FIELDS:
            present = hasattr(self, attr) and getattr(self, attr) is not None
            value = getattr(self, attr, None) if present else "<deleted>"
            rows.append((attr, value, bits if present else 0))
        return rows

    def print_state(self) -> None:
        t = trace.active()
        rows = self.dump_state()
        total = sum(bits for _, _, bits in rows)
        def shown(name: str, val: object) -> str:
            if val == "<deleted>":
                return "<deleted>"
            if name in SECRET_FIELDS:
                return t.redacted(f"{self.identity}.{name}", val)
            return trace.render(val, t.verbosity)

        t.table(["field", "value", "bits"],
                [[name, shown(name, val), bits] for name, val, bits in rows],
                f"{self.identity} state (total {total} bits)")
