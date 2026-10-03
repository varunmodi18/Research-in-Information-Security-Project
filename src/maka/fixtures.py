"""F-PAPER and F-NET topologies (P5.5, PLAN.md §4.3).

F-PAPER (1 BS, 1 CH, 1 CM) exists for an arithmetic reason: RP9's Table 3 figures reproduce
exactly, and only, for a single cluster head with a single member (see PLAN.md §4.3's bit
accounting). F-NET (1 BS, 3 CHs, 3 CMs each) illustrates the §2.3 architecture at scale;
its totals are reported only, never compared against RP9's published tables (AM-06).
"""

from __future__ import annotations

PAPER = "paper"
SMALL = "small"
NET = "net"


def custom(chs: int, cms_per_ch: int) -> dict[str, object]:
    """1 BS, `chs` cluster heads with `cms_per_ch` members each (IMPLEMENTATION_PLAN.md FR-01:
    1-5 CHs, 1-8 CMs each). IDs follow the CH-0i / CM-0i0j pattern of the named fixtures."""
    if not (1 <= chs <= 5 and 1 <= cms_per_ch <= 8):
        raise ValueError("custom topology needs 1-5 CHs and 1-8 CMs per CH")
    return {"bs": "BS-01",
            "chs": {f"CH-0{i}": [f"CM-0{i}0{j}" for j in range(1, cms_per_ch + 1)]
                    for i in range(1, chs + 1)}}


def topology(name: str) -> dict[str, object]:
    """Named fixtures `paper` (1x1), `small` (1x3), `net` (3x3), or `custom-<chs>x<cms>`."""
    if name == PAPER:
        return custom(1, 1)
    if name == SMALL:
        return custom(1, 3)
    if name == NET:
        return custom(3, 3)
    if name.startswith("custom-"):
        chs, _, cms = name.removeprefix("custom-").partition("x")
        if chs.isdigit() and cms.isdigit():
            return custom(int(chs), int(cms))
    raise ValueError(f"unknown fixture {name!r}; use paper, small, net or custom-<chs>x<cms>")


def assert_paper_table_allowed(fixture: str) -> None:
    """eval/ refuses Table 2-3 assertions on F-NET (AM-06): RP9 never states the topology its
    cost tables assume, so F-PAPER makes that assumption explicit and testable, and only
    F-PAPER's arithmetic is licensed to be compared against RP9's published tables."""
    if fixture != PAPER:
        raise ValueError(f"[AM-06] Table 2/3 assertions require fixture={PAPER!r}; "
                          f"RP9 never states the topology its cost tables assume, and F-NET's "
                          f"totals differ structurally (see PLAN.md §4.3). Got fixture={fixture!r}.")
