"""P8 DoD: all assertions pass; negative paths print unambiguous failures; matrix renders."""

from __future__ import annotations

from maka import fixtures, params, rng, trace
from maka.protocol import (
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
)


def _build():
    rng.seed(3)
    trace.init(run_id="test-p4", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    return net


def test_authentication_table3_row3_on_paper() -> None:
    net = _build()
    p4_node_authentication.run(net, fixtures.PAPER)
    assert net.channel.total_bits(["EM1", "EM2", "EM3"]) == 2400


def test_mutual_authentication_holds() -> None:
    net = _build()
    p4_node_authentication.run(net, fixtures.PAPER)
    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))
    from maka.protocol.p3_node_registration import xor_to_scalar

    r = net.bs.curve.r_group
    assert xor_to_scalar(net.bs.identity, ch.identity, r) * ch.a1 == ch.a2
    assert xor_to_scalar(ch.identity, cm.identity, r) * cm.a3 == cm.a4


def test_er01_a4_uses_r_cm_not_r_ch() -> None:
    """ER-01: A4 must be r_CM * P_CM (computable by the CM), not RP9's printed r_CH * P_CM."""
    net = _build()
    p4_node_authentication.run(net, fixtures.PAPER)
    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))
    assert cm.a4 == cm.r_cm * cm.p_cm
    assert cm.a4 != ch.r_ch * cm.p_cm  # the literal (uncomputable-by-CM) reading would differ
