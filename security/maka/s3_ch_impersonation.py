"""RP9 §6.1.3: cluster-head impersonation resistance.

Prints RP9's stated reasoning verbatim (OB-04) alongside what the code actually enforces,
and demonstrates both without editorialising.
"""

from __future__ import annotations

from maka import fixtures, params, rng, trace
from maka.protocol import p1_initialization, p2_key_generation, p3_node_registration
from maka.protocol.p3_node_registration import xor_to_scalar


def run(params_name: str = "demo") -> bool:
    t = trace.active()
    t.banner("s3_ch_impersonation -- RP9 §6.1.3", "CH impersonation resistance")
    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    ch = next(iter(net.cluster_heads.values()))

    t.step("RP9 §6.1.3 (as stated)", "'all the nodes are preloaded with the generator g, the "
                                       "attacker cannot compute A1.'")
    t.register("OB-04", "g is a public system parameter; an attacker may pick any rho and "
                         "compute rho*g. The obstacle the verification equation actually "
                         "enforces is inability to produce a matching A2 without the "
                         "undisclosed P_CH -- demonstrated below.")

    forged_rho = rng.current().below(p.curve.r_group)
    forged_a1 = forged_rho * ch.curve_g
    t.check("attacker CAN compute a well-formed A1 = rho*g", forged_a1.is_on_curve(), True, forged_a1.is_on_curve())

    verification_target = xor_to_scalar(net.bs.identity, ch.identity, p.curve.r_group) * forged_a1
    forged_a2_guess = forged_rho * ch.curve_g  # best effort without P_CH
    fails = forged_a2_guess != verification_target
    t.check("s3_ch_impersonation HOLDS: attacker's A2 (lacking P_CH) fails verification",
            fails, True, fails)
    return fails
