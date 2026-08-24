"""P7 DoD: Table 3 row 2 exact on F-PAPER; F-NET reports without asserting; duplicate-beacon
rejection prints."""

from __future__ import annotations

import pytest

from maka import fixtures, params, rng, trace
from maka.protocol import p1_initialization, p2_key_generation, p3_node_registration


def _build(fixture: str, seed: int = 1):
    rng.seed(seed)
    trace.init(run_id=f"test-p3-{fixture}-{seed}", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixture)
    p2_key_generation.run(net)
    return net


def test_registration_table3_row2_on_paper() -> None:
    net = _build(fixtures.PAPER)
    p3_node_registration.run(net, fixtures.PAPER)
    assert net.channel.total_bits(["BEACON"]) == 800
    assert net.channel.total_bits(["PSEUDO_BS_CH"]) == 640
    assert net.channel.total_bits(["PSEUDO_CH_CM"]) == 320


def test_registration_runs_on_net_fixture_without_hard_assertion() -> None:
    net = _build(fixtures.NET)
    p3_node_registration.run(net, fixtures.NET)  # should not raise
    assert net.channel.total_bits(["BEACON"]) > 0


def test_pseudo_identities_are_correct_xor_scalar_multiples() -> None:
    net = _build(fixtures.PAPER)
    p3_node_registration.run(net, fixtures.PAPER)
    ch = next(iter(net.cluster_heads.values()))
    from maka.protocol.p3_node_registration import xor_to_scalar

    expected = xor_to_scalar(net.bs.identity, ch.identity, net.bs.curve.r_group) * ch.curve_g
    assert ch.p_ch == expected
