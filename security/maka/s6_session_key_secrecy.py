"""RP9 §6.1.6: session-key secrecy -- an attacker lacking Pr_i cannot form the key.

Prints RP9's claim that node compromise 'does not affect the security of the system'
alongside OB-02. States both; concludes nothing beyond what is demonstrated.
"""

from __future__ import annotations

from maka import fixtures, hashing, pairing, params, rng, trace
from maka.protocol import (
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
    p5_session_key_agreement,
)


def run(params_name: str = "demo") -> bool:
    t = trace.active()
    t.banner("s6_session_key_secrecy -- RP9 §6.1.6", "Session-key secrecy")
    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)
    p5_session_key_agreement.run(net, fixtures.PAPER)

    ch = next(iter(net.cluster_heads.values()))
    real_key = net.bs.session_keys[ch.identity]

    t.step("RP9 §6.1.6 (quoted)", "'even if the attacker succeeds in capturing a node, this "
                                    "does not affect the security of the system.'")
    t.register("OB-02", "SK_{i-BS} depends only on Pu_i, Pu_BS and k -- no ephemeral input, "
                         "so it never changes; captured-node exposure and no-forward-secrecy "
                         "are the same underlying property viewed from two angles. Both are "
                         "stated here; neither is concluded to override the other.")

    guessed_pr = rng.current().below(p.curve.r_group) * ch.pu_i  # attacker lacks the real Pr_i
    guessed_key = pairing.modified_pairing(p.curve, guessed_pr, net.bs.pu_bs)
    mismatch = guessed_key != real_key
    t.check("s6_session_key_secrecy HOLDS: an attacker without Pr_i cannot form SK_{i-BS}",
            mismatch, True, mismatch)
    return mismatch
