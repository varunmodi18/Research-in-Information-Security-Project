"""Detectors, split-by-run evaluation, the CLI and the committed results (docs/BEHAVIOUR.md).
Needs the `[ml]` extra (installed in CI)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

pytest.importorskip("sklearn")

import numpy as np

from maka.behaviour import __main__ as cli
from maka.behaviour import dataset, traffic
from maka.behaviour import evaluate as ev
from maka.behaviour.detectors import IsolationForestDetector, ZScoreDetector

ROOT = Path(__file__).resolve().parents[2]
COMMITTED = ROOT / "artifacts" / "behaviour"
SHORT = traffic.TrafficConfig(observe_steps=200, fault_start=60, fault_duration=100)


@pytest.fixture(scope="module")
def tiny() -> tuple[list[dict[str, object]], dict[str, object]]:
    return dataset.build(dataset.DatasetConfig(benign_seeds=10, fault_seeds=2, topologies=("small",), traffic=SHORT))


def test_split_is_by_run() -> None:
    ids = [f"{t}/benign/{1000 + i}" for t in ("small", "net") for i in range(40)]
    ids += [f"small/excessive_rekey/default/{5000 + i}" for i in range(10)]
    split = ev.split_runs(ids * 3)  # each run contributes many windows
    assert set(split) == set(ids)
    for topo in ("small", "net"):
        counts = {s: sum(1 for r, x in split.items() if x == s and r.startswith(f"{topo}/benign"))
                  for s in (ev.TRAIN, ev.VALIDATION, ev.TEST)}
        assert counts == {ev.TRAIN: 24, ev.VALIDATION: 8, ev.TEST: 8}
    assert all(split[r] == ev.TEST for r in ids if "/benign/" not in r)  # faults only in test
    seeds = {}
    for rid, part in split.items():
        assert seeds.setdefault(rid, part) == part  # no run, so no seed, in two splits
    assert ev.split_runs(list(reversed(ids))) == split  # independent of input order


def test_detectors_fit_and_score_deterministically(tiny: tuple[list[dict[str, object]], dict[str, object]]) -> None:
    rows, _ = tiny
    for make in (ZScoreDetector, lambda: IsolationForestDetector(seed=3)):
        a, b = make().fit(rows).calibrate(rows), make().fit(rows).calibrate(rows)
        assert np.array_equal(a.score(rows), b.score(rows)) and a.threshold == b.threshold
        # calibrated on these rows for 1 % false alarms: at most 1 % of each role's rows is flagged
        flags = a.flag(rows)
        for role in ("CM", "CH"):
            idx = [i for i, r in enumerate(rows) if r["role"] == role]
            assert flags[idx].mean() <= 0.01 + 1e-9


def test_zscore_flags_a_feature_unseen_in_training() -> None:
    """The baseline's floored sigma lets a never-varying feature raise an alert; this is why it
    sees lossy forwarding (seq gaps never occur in benign training) where the Isolation Forest,
    which cannot split on a constant feature, does not (docs/BEHAVIOUR.md §Results)."""
    from maka.behaviour.features import FEATURES

    base = {"role": "CH", **dict.fromkeys(FEATURES, 1), "seq_gaps_at_bs": 0}
    train = [dict(base, frames_sent=s) for s in (1, 2, 3, 2, 1, 2, 3, 2) * 8]
    odd = dict(base, frames_sent=2, seq_gaps_at_bs=3)
    z = ZScoreDetector().fit(train).calibrate(train)
    forest = IsolationForestDetector(seed=0).fit(train).calibrate(train)
    assert z.flag([odd])[0] and z.stats.top_features(odd)[0]["feature"] == "seq_gaps_at_bs"
    assert not forest.flag([odd])[0]


def test_cli_all_end_to_end_on_a_tiny_config(tmp_path: Path) -> None:
    t0 = time.monotonic()
    assert cli.main(["all", "--out", str(tmp_path), "--benign-seeds", "6", "--fault-seeds", "1",
                     "--topologies", "small", "--observe-steps", "200", "--date", "2000-01-01"]) == 0
    assert time.monotonic() - t0 < 60
    res = json.loads((tmp_path / "results_2000-01-01.json").read_text())
    assert res["experimental"] is True and {r["detector"] for r in res["results"]} == {
        "z-score baseline", "Isolation Forest"}
    assert {(r["fault"], r["variant"]) for r in res["results"]} == {
        (f.kind, f.variant) for f in traffic.FAULT_VARIANTS.values()}
    assert (tmp_path / "results_2000-01-01.md").read_text().startswith("# Behavioural monitoring (experimental)")
    for e in res["explanations"]:
        assert len(e["top_features"]) == 3


def _latest() -> Path:
    return max(COMMITTED.glob("results_*.json"))


def test_committed_results_match_the_committed_dataset() -> None:
    """Training and evaluating on the committed dataset gives exactly the committed results."""
    res = json.loads(_latest().read_text())
    manifest = json.loads((COMMITTED / "manifest.json").read_text())
    rows = dataset.read(COMMITTED / "dataset.csv")
    assert ev.evaluate(rows, ev.train(rows), manifest, res["date"]) == res
    assert (COMMITTED / f"results_{res['date']}.md").read_text() == ev.markdown(res)


@pytest.mark.slow
def test_committed_dataset_is_regenerable() -> None:
    """`python -m maka.behaviour build` reproduces the committed dataset and manifest byte for byte."""
    rows, manifest = dataset.build(dataset.DatasetConfig())
    assert manifest == json.loads((COMMITTED / "manifest.json").read_text())
    assert rows == dataset.read(COMMITTED / "dataset.csv")
