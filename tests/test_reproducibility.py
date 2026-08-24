"""P13.8: two same-seed runs of the full MAKA protocol produce byte-identical JSONL event
streams, modulo volatile fields (`ts`)."""

from __future__ import annotations

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

from .golden_util import diff_jsonl, load_jsonl


def _full_run(out_dir: Path, run_id: str, seed: int) -> Path:
    rng.seed(seed)
    t = trace.init(run_id=run_id, out_dir=out_dir, color=False, verbosity=1)
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)
    p5_session_key_agreement.run(net, fixtures.PAPER)
    data_transmission.run(net)
    t.close()
    return out_dir / f"{run_id}.jsonl"


def test_two_same_seed_full_protocol_runs_are_identical(tmp_path: Path) -> None:
    path_a = _full_run(tmp_path / "a", "repro", seed=123)
    path_b = _full_run(tmp_path / "b", "repro", seed=123)
    diffs = diff_jsonl(load_jsonl(path_a), load_jsonl(path_b))
    assert not diffs, diffs


def test_different_seeds_produce_different_output(tmp_path: Path) -> None:
    path_a = _full_run(tmp_path / "a", "repro", seed=1)
    path_b = _full_run(tmp_path / "b", "repro", seed=2)
    diffs = diff_jsonl(load_jsonl(path_a), load_jsonl(path_b))
    assert diffs  # different seeds must diverge somewhere
