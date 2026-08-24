"""S2/S3: `maka run --fixture paper|net -vv` -- the complete MAKA protocol, all five phases,
plus the AM-05 halt.

Realises: PLAN.md P13.1 (d2_maka_full).
"""

from __future__ import annotations

from maka import params, trace
from maka.protocol import (
    data_transmission,
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
    p5_session_key_agreement,
)


def run(params_name: str = "demo", fixture: str = "paper", verbosity: int = 2) -> None:
    t = trace.active()
    t.banner("D2 -- MAKA, full protocol", f"params={params_name} fixture={fixture}")
    p = params.get(params_name)

    net = p1_initialization.run(p.curve, p.g, fixture)
    t.section(0, "Network topology")
    t.step("network", "\n" + net.render_ascii())

    p2_key_generation.run(net)
    p3_node_registration.run(net, fixture)
    p4_node_authentication.run(net, fixture)
    p5_session_key_agreement.run(net, fixture)
    data_transmission.run(net)

    t.section("summary", "Per-entity state dumps")
    net.bs.print_state()
    for ch in net.cluster_heads.values():
        ch.print_state()
        for cm in net.cluster_members[ch.identity].values():
            cm.print_state()

    t.section("ledger", "Operation ledger summary")
    from maka import ledger

    rows = ledger.current().as_rows()
    t.table(["entity", "phase", "op", "count"], [list(r) for r in rows], "Ledger (all entities/phases)")


if __name__ == "__main__":
    from maka import rng

    trace.init(run_id="d2-standalone", verbosity=2)
    rng.seed(0)
    run(params_name="toy", fixture="paper", verbosity=2)
