"""RP9 §7.2, Table 3: communication cost from wire.py on F-PAPER (P12.3).

Rows 1-3 sum the paper-model bits of each phase's frames. Row 4 counts *every* frame sent
between the start and end of §5.5, so it would detect a session-key message if one existed
(IMPLEMENTATION_PLAN.md M1-T9, I-12). Row 2 differs from RP9 by the documented IA-14 addition
(ID_CH in each PSEUDO_CH_CM, +160 bits per member). Also prints the --sizing actual column,
labelled as an implementation diagnostic (OB-03), never a correction to RP9.
"""

from __future__ import annotations

from maka import fixtures, params, trace
from maka.network import Network
from maka.protocol import (
    data_transmission,
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
    p5_session_key_agreement,
)

PUBLISHED = {"key generation": 640, "registration": 1760, "authentication": 2400,
             "session key agreement": 0}
LABELS = {"key generation": ["PUB_CH", "PUB_CM"],
          "registration": ["BEACON", "PSEUDO_BS_CH", "PSEUDO_CH_CM"],
          "authentication": ["EM1", "EM2", "EM3"]}
# Documented differences between this implementation and RP9's published row, per member.
DELTA_PER_MEMBER = {"registration": (p3_node_registration.ID_CH_BITS, "IA-14: ID_CH in PSEUDO_CH_CM")}


def measure(net: Network, p5_bits: int) -> dict[str, int]:
    totals = {phase: net.channel.total_bits(labels) for phase, labels in LABELS.items()}
    totals["session key agreement"] = p5_bits
    return totals


def run(params_name: str = "demo", sizing: str = "paper") -> dict[str, int]:
    t = trace.active()
    t.section("7.2", "Table 3: communication cost (paper sizing)")
    fixtures.assert_paper_table_allowed(fixtures.PAPER)

    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER, secure_pseudo_ids=False)
    p4_node_authentication.run(net, fixtures.PAPER)
    p5_start = len(net.channel.frames)
    p5_session_key_agreement.run(net, fixtures.PAPER)
    p5_bits = net.channel.bits_since(p5_start)
    data_transmission.run(net)

    n = sum(len(m) for m in net.cluster_members.values())
    totals = measure(net, p5_bits)
    rows = []
    for phase, published in PUBLISHED.items():
        per_member, why = DELTA_PER_MEMBER.get(phase, (0, ""))
        expected = published + per_member * n
        actual = totals[phase]
        rows.append([phase, published, actual, f"+{per_member * n} ({why})" if per_member else "0",
                     "PASS" if actual == expected else "FAIL"])
        t.check(f"Table 3 '{phase}' == {published}{f' + {per_member}*{n} [{why}]' if per_member else ''} bits",
                actual == expected, expected, actual)

    t.table(["phase", "published", "measured", "documented delta", "verdict"], rows,
            "Table 3 (paper sizing)")

    if sizing == "actual":
        actual_bits = sum(len(f.payload) * 8 for f in net.channel.frames  # type: ignore[arg-type]
                          if not f.injected and isinstance(f.payload, bytes))
        t.value("total bits, --sizing actual (OB-03)", actual_bits,
                note="real encoded bytes of every frame -- implementation diagnostic, NOT a correction to RP9")

    return totals
