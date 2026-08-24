"""S4: `maka icmds --attacks all` -- ICMDS plus the seven §4 attacks.

Realises: PLAN.md P10.4.
"""

from __future__ import annotations

from attacks.icmds import (
    a1_replay,
    a2_dos,
    a3_ch_impersonation,
    a4_no_mutual_auth,
    a5_sybil,
    a6_node_capture,
    a7_sk_impossible,
)
from maka import params, trace


def run(params_name: str = "demo", verbosity: int = 2) -> None:
    t = trace.active()
    t.banner("D3 -- ICMDS and its cryptanalysis", "RP9 §3-§4")
    p = params.get(params_name)

    results = []
    for section, mod in (("§4.1", a1_replay), ("§4.2", a2_dos), ("§4.3", a3_ch_impersonation),
                          ("§4.4", a4_no_mutual_auth), ("§4.5", a5_sybil),
                          ("§4.6", a6_node_capture), ("§4.7", a7_sk_impossible)):
        verdict = mod.run(p.curve, p.g)
        results.append([mod.__name__.rsplit(".", 1)[-1], section, verdict])

    t.section("verdict-table", "Attack verdict summary")
    t.table(["module", "RP9 section", "verdict"], results, "ICMDS cryptanalysis (§4)")


if __name__ == "__main__":
    from maka import rng

    trace.init(run_id="d3-standalone", verbosity=2)
    rng.seed(0)
    run(params_name="toy", verbosity=2)
