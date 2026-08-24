"""P5/P6 DoD: both fixtures construct; Fig. 1 renders; state dumps print; F-NET refuses
paper-table assertions; k provably gone after keygen."""

from __future__ import annotations

import pytest

from maka import fixtures, params, rng, trace
from maka.protocol import p1_initialization, p2_key_generation


def test_both_fixtures_construct() -> None:
    rng.seed(0)
    trace.init(run_id="test-fixtures", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    p = params.get("toy")
    net_paper = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    assert len(net_paper.cluster_heads) == 1
    assert len(net_paper.cluster_members["CH-01"]) == 1

    net_net = p1_initialization.run(p.curve, p.g, fixtures.NET)
    assert len(net_net.cluster_heads) == 3
    assert all(len(members) == 3 for members in net_net.cluster_members.values())


def test_network_ascii_render() -> None:
    rng.seed(0)
    trace.init(run_id="test-render", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    rendered = net.render_ascii()
    assert "BS-01" in rendered and "CH-01" in rendered and "CM-0101" in rendered


def test_net_fixture_refuses_paper_table_assertion() -> None:
    with pytest.raises(ValueError, match="AM-06"):
        fixtures.assert_paper_table_allowed(fixtures.NET)
    fixtures.assert_paper_table_allowed(fixtures.PAPER)  # must not raise


def test_master_key_destroyed_after_keygen() -> None:
    rng.seed(0)
    trace.init(run_id="test-keygen", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    assert net.bs.k is None
    for ch in net.cluster_heads.values():
        assert ch.k is None
        for cm in net.cluster_members[ch.identity].values():
            assert cm.k is None


def test_state_dump_reflects_destroyed_key() -> None:
    rng.seed(0)
    trace.init(run_id="test-dump", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    ch = next(iter(net.cluster_heads.values()))
    rows = ch.dump_state()
    k_row = next(r for r in rows if r[0] == "k")
    assert k_row[1] == "<deleted>"
    assert k_row[2] == 0
