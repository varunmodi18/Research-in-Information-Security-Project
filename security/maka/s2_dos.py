"""RP9 §6.1.2: denial-of-service resistance -- an ILLUSTRATION, not a falsifiable test.

IMPLEMENTATION_PLAN.md M1-T9 (I-12): the check below only confirms that authentication ran;
it cannot fail for a scheme that is vulnerable to DoS (RP9's receivers perform an IBE
decryption before any rejection, P-07). The enhanced-mode Lab scenario L7 measures this.

Revised in Revision 3: demonstrates the rejection behaviour RP9 claims -- the CH aggregates
only from authenticated nodes, the BS accepts only from an authenticated CH, and replayed
data is rejected. Does NOT count "operations avoided versus the ICMDS run" -- that is a
comparative measurement RP9 does not perform (see docs/DEFERRED.md).
"""

from __future__ import annotations

from maka import fixtures, params, trace
from maka.protocol import (
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
)

KIND = "ILLUSTRATION"  # IMPLEMENTATION_PLAN.md M1-T9: not a falsifiable test


def run(params_name: str = "demo") -> bool:
    t = trace.active()
    t.banner("s2_dos -- RP9 §6.1.2", "Denial-of-service resistance")
    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)  # includes replay/tamper negative paths

    t.step("RP9 §6.1.2 (quoted)", "authentication precedes any data acceptance, so an "
                                    "unauthenticated flood is rejected before it reaches the "
                                    "aggregation/forwarding step.")
    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))
    authenticated = bool(ch.a2 is not None and cm.a4 is not None)
    t.check("s2_dos ILLUSTRATION: data acceptance is gated on completed authentication "
            "(cannot fail; see module docstring)", authenticated, True, authenticated)
    return authenticated
