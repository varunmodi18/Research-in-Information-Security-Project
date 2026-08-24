"""Entity base: state plus dump_state() (P5.2).

dump_state() is an observability tool for demonstration transcripts, not the authority for
Table 4 storage figures -- see PLAN.md P12.4 (AM-07). Subclasses declare which attributes
are storage-relevant via STORAGE_FIELDS = [(attr_name, paper_bits), ...].
"""

from __future__ import annotations

from maka import trace


class Entity:
    STORAGE_FIELDS: list[tuple[str, int]] = []

    def __init__(self, identity: str) -> None:
        self.identity = identity

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
        t.table(["field", "value", "bits"],
                [[name, trace.render(val, t.verbosity) if val != "<deleted>" else val, bits]
                 for name, val, bits in rows],
                f"{self.identity} state (total {total} bits)")
