"""RP9 §7.3, Table 4: storage cost (P12.4, revised by IMPLEMENTATION_PLAN.md M1-T9).

Two clearly separated outputs, never conflated:
1. Published-model reproduction: RP9's Table 4 exactly as printed.
2. State-derived values: the sum of a cluster member's `dump_state()` paper-model bit sizes at
   each phase boundary, reported next to RP9's figure. Nothing is hard-coded and no agreement
   is asserted: RP9 states no retention/deletion policy ("a sensor node can delete or add some
   values into its memory"), and this implementation deletes only k (AM-07).
"""

from __future__ import annotations

from maka import fixtures, params, trace
from maka.entities.base import Entity
from maka.protocol import (
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
    p5_session_key_agreement,
)

PHASES = ["After key generation", "After node registration", "After node authentication",
          "After session key agreement"]
PUBLISHED = [1440, 2240, 640, 160]  # RP9 Table 4, rows 1-4


def derive(entity: Entity) -> int:
    """Bits the entity currently stores, from its declared STORAGE_FIELDS."""
    return sum(bits for _, _, bits in entity.dump_state())


def derive_rows(params_name: str = "toy") -> list[int]:
    """Runs F-PAPER phase by phase and derives one Table 4 value per phase boundary."""
    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    cm = next(iter(net.cluster_members["CH-01"].values()))
    steps = [
        lambda: p2_key_generation.run(net),
        lambda: p3_node_registration.run(net, fixtures.PAPER, secure_pseudo_ids=False),
        lambda: p4_node_authentication.run(net, fixtures.PAPER),
        lambda: p5_session_key_agreement.run(net, fixtures.PAPER),
    ]
    rows = []
    for step in steps:
        step()
        rows.append(derive(cm))
    return rows


def run(params_name: str = "demo") -> list[int]:
    t = trace.active()
    t.section("7.3", "Table 4: storage cost")

    t.step("P12.4 (1)", "Published-model reproduction -- RP9's Table 4, exactly as printed")
    t.table(["row", "phase", "bits"], [[i + 1, ph, b] for i, (ph, b) in enumerate(zip(PHASES, PUBLISHED))],
            "RP9 Table 4 (published)")

    t.step("P12.4 (2)", "State-derived values: CM dump_state() at each phase boundary")
    derived = derive_rows(params_name)
    t.table(["row", "phase", "RP9 (bits)", "derived (bits)", "relation"],
            [[i + 1, PHASES[i], PUBLISHED[i], derived[i],
              "equal" if derived[i] == PUBLISHED[i] else "differs (AM-07)"]
             for i in range(len(PHASES))],
            "Table 4: RP9 vs. derived from this implementation's stored state")
    t.underspecified("Table 4 retention policy",
                      "RP9 states no retention policy for individual variables, so which values a "
                      "node deletes after each phase is not specified. This implementation keeps "
                      "every received or computed value and deletes only k; its derived totals "
                      "therefore grow monotonically while RP9's fall to 640 and 160 bits. No "
                      "agreement is forced. See AM-07.")
    return derived
