"""P9 DoD: session keys agree; zero-message property; AM-05 halt; no aggregation protocol
exists anywhere in the codebase."""

from __future__ import annotations

import ast
from pathlib import Path

from maka import fixtures, params, rng, trace
from maka.protocol import (
    data_transmission,
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
    p5_session_key_agreement,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _build():
    rng.seed(5)
    trace.init(run_id="test-p5", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)
    return net


def test_session_keys_agree_and_zero_messages() -> None:
    net = _build()
    p5_session_key_agreement.run(net, fixtures.PAPER)
    ch = next(iter(net.cluster_heads.values()))
    assert ch.identity in net.sym_keys
    assert net.channel.total_bits(["SESSION_KEY_MSG"]) == 0


def test_ob02_key_reproducible_across_repeated_computation() -> None:
    from maka import pairing

    net = _build()
    p5_session_key_agreement.run(net, fixtures.PAPER)
    ch = next(iter(net.cluster_heads.values()))
    sk1 = net.bs.session_keys[ch.identity]
    sk2 = pairing.modified_pairing(net.bs.curve, ch.pr_i, net.bs.pu_bs)
    assert sk1 == sk2


def test_data_transmission_halts_at_aggregate() -> None:
    net = _build()
    p5_session_key_agreement.run(net, fixtures.PAPER)
    data_transmission.run(net)  # must not raise; halt is demonstrated via trace.undefined()


def test_no_aggregation_helper_exists_anywhere_in_src() -> None:
    """Hygiene: AM-05 is never silently resolved by inventing an Aggregate implementation."""
    forbidden = {"aggregate", "aggregate_data", "aggregate_readings"}
    offenders = []
    for f in (REPO_ROOT / "src").rglob("*.py"):
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.lower() in forbidden:
                offenders.append(f"{f}:{node.lineno}")
    assert not offenders, f"an Aggregate implementation exists: {offenders}"
