"""F-PAPER and F-NET topologies (P5.5, PLAN.md §4.3).

F-PAPER (1 BS, 1 CH, 1 CM) exists for an arithmetic reason: RP9's Table 3 figures reproduce
exactly, and only, for a single cluster head with a single member (see PLAN.md §4.3's bit
accounting). F-NET (1 BS, 3 CHs, 3 CMs each) illustrates the §2.3 architecture at scale;
its totals are reported only, never compared against RP9's published tables (AM-06).
"""

from __future__ import annotations

PAPER = "paper"
NET = "net"


def topology(name: str) -> dict[str, object]:
    if name == PAPER:
        return {"bs": "BS-01", "chs": {"CH-01": ["CM-0101"]}}
    if name == NET:
        return {"bs": "BS-01",
                 "chs": {f"CH-0{i}": [f"CM-0{i}0{j}" for j in range(1, 4)] for i in range(1, 4)}}
    raise ValueError(f"unknown fixture {name!r}; use fixtures.PAPER or fixtures.NET")


def assert_paper_table_allowed(fixture: str) -> None:
    """eval/ refuses Table 2-3 assertions on F-NET (AM-06): RP9 never states the topology its
    cost tables assume, so F-PAPER makes that assumption explicit and testable, and only
    F-PAPER's arithmetic is licensed to be compared against RP9's published tables."""
    if fixture != PAPER:
        raise ValueError(f"[AM-06] Table 2/3 assertions require fixture={PAPER!r}; "
                          f"RP9 never states the topology its cost tables assume, and F-NET's "
                          f"totals differ structurally (see PLAN.md §4.3). Got fixture={fixture!r}.")
