"""RP9 §7.2, Table 3: communication cost from wire.py on F-PAPER (P12.3).

Asserts 640/1760/2400/0. Also prints the --sizing actual column, labelled as an
implementation diagnostic (OB-03), never a correction to RP9.
"""

from __future__ import annotations

from maka import fixtures, params, trace
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
          "authentication": ["EM1", "EM2", "EM3"],
          "session key agreement": ["SESSION_KEY_MSG"]}


def run(params_name: str = "demo", sizing: str = "paper") -> dict[str, int]:
    t = trace.active()
    t.section("7.2", "Table 3: communication cost (paper sizing)")
    fixtures.assert_paper_table_allowed(fixtures.PAPER)

    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)
    p5_session_key_agreement.run(net, fixtures.PAPER)
    data_transmission.run(net)

    totals = {}
    rows = []
    for phase, published in PUBLISHED.items():
        actual = net.channel.total_bits(LABELS[phase])
        totals[phase] = actual
        rows.append([phase, published, actual, "PASS" if actual == published else "FAIL"])
        t.check(f"Table 3 '{phase}' == {published} bits", actual == published, published, actual)

    t.table(["phase", "published", "ledger-derived", "verdict"], rows, "Table 3 (paper sizing)")

    if sizing == "actual":
        actual_bits = net.channel.total_bits()
        t.value("total bits, --sizing actual (OB-03)", actual_bits,
                note="implementation diagnostic (OB-03) -- NOT a correction to RP9")

    return totals
