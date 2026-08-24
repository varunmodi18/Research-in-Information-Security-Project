"""RP9 §6.1.4: mutual authentication -- both directions verified (references the P8.6 matrix)."""

from __future__ import annotations

from maka import fixtures, params, trace
from maka.protocol import (
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
)
from maka.protocol.p3_node_registration import xor_to_scalar


def run(params_name: str = "demo") -> bool:
    t = trace.active()
    t.banner("s4_mutual_authentication -- RP9 §6.1.4", "Mutual authentication, both directions")
    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)  # emits the P8.6 matrix

    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))
    r = p.curve.r_group
    cm_verifies_ch = xor_to_scalar(net.bs.identity, ch.identity, r) * ch.a1 == ch.a2
    ch_verifies_cm = xor_to_scalar(ch.identity, cm.identity, r) * cm.a3 == cm.a4

    both = cm_verifies_ch and ch_verifies_cm
    t.check("s4_mutual_authentication HOLDS: both directions verified", both, True, both)
    return both
