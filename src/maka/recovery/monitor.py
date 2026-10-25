"""The behaviour monitor as cluster-head recovery uses it (docs/RECOVERY.md §Detection).

- The trigger always uses the z-score baseline, implemented here in pure Python and fitted on the
  committed behaviour dataset exactly as `maka.behaviour.detectors.ZScoreDetector` is (train runs,
  σ floored at 0.5, threshold = the "higher" 99th percentile of the validation runs). It needs no
  [ml] extra. It is the detector that sees lossy forwarding (docs/BEHAVIOUR.md §Results); the
  Isolation Forest is nearly blind to it.
- The trust component of the candidate ranking uses the Isolation Forest when the [ml] extra is
  installed (trained on the same committed dataset), else the z-score baseline; every result says
  which was used.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from maka.behaviour import dataset, features

REPO_ROOT = Path(__file__).resolve().parents[3]
COMMITTED_DATASET = REPO_ROOT / "artifacts" / "behaviour" / "dataset.csv"
Z_BASELINE = "z-score baseline"
ISOLATION_FOREST = "Isolation Forest"
SIGMA_FLOOR = 0.5
TARGET_FA = 0.01


def _quantile_higher(values: Sequence[float], q: float) -> float:
    """numpy.quantile(values, q, method="higher")."""
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(q * (len(ordered) - 1)))]


@dataclass(frozen=True)
class ZBaseline:
    """Per-role feature mean and floored standard deviation, and a per-role threshold."""

    mean: Mapping[str, tuple[float, ...]]
    std: Mapping[str, tuple[float, ...]]
    threshold: Mapping[str, float]

    @classmethod
    def fit(cls, train: Sequence[Mapping[str, Any]], validation: Sequence[Mapping[str, Any]]) -> ZBaseline:
        mean: dict[str, tuple[float, ...]] = {}
        std: dict[str, tuple[float, ...]] = {}
        for role in features.ROLES:
            rows = [r for r in train if r["role"] == role]
            cols = [[float(r[f]) for r in rows] for f in features.FEATURES]
            mu = tuple(sum(c) / len(c) for c in cols)
            mean[role] = mu
            std[role] = tuple(max(math.sqrt(sum((x - m) ** 2 for x in c) / len(c)), SIGMA_FLOOR)
                              for c, m in zip(cols, mu, strict=True))
        partial = cls(mean, std, {})
        threshold = {role: _quantile_higher([partial.score(r) for r in validation if r["role"] == role], 1 - TARGET_FA)
                     for role in features.ROLES}
        return cls(mean, std, threshold)

    def z(self, row: Mapping[str, Any]) -> list[float]:
        role = row["role"]
        return [(float(row[f]) - m) / s for f, m, s in zip(features.FEATURES, self.mean[role], self.std[role], strict=True)]

    def score(self, row: Mapping[str, Any]) -> float:
        return max(abs(v) for v in self.z(row))

    def flag(self, row: Mapping[str, Any]) -> bool:
        return self.score(row) > self.threshold[row["role"]]


def _committed_split(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing: run `python -m maka.behaviour build` (docs/BEHAVIOUR.md)")
    rows = dataset.read(path)
    split = dataset.split_runs([r["run_id"] for r in rows])
    return ([r for r in rows if split[r["run_id"]] == dataset.TRAIN],
            [r for r in rows if split[r["run_id"]] == dataset.VALIDATION])


@lru_cache(maxsize=1)
def baseline(path: Path = COMMITTED_DATASET) -> ZBaseline:
    return ZBaseline.fit(*_committed_split(path))


@dataclass(frozen=True)
class Scorer:
    """An anomaly score per device-window and the per-role threshold it is calibrated to."""

    name: str
    score: Callable[[Sequence[Mapping[str, Any]]], list[float]]
    threshold: Mapping[str, float]


@lru_cache(maxsize=1)
def trust_scorer(path: Path = COMMITTED_DATASET) -> Scorer:
    """The Isolation Forest if the [ml] extra is installed, else the z-score baseline."""
    try:
        from maka.behaviour import evaluate
    except ImportError:
        z = baseline(path)
        return Scorer(Z_BASELINE, lambda rows: [z.score(r) for r in rows], dict(z.threshold))
    model = evaluate.train(dataset.read(path))
    forest = model["detectors"][1]
    return Scorer(ISOLATION_FOREST, lambda rows: [float(v) for v in forest.score(list(rows))], dict(forest.threshold))


def windows(log: Sequence[Any], events: Sequence[Any], roles: Mapping[str, str], *, start: int, end: int,
            window: int = 20) -> list[dict[str, Any]]:
    """Feature rows of the complete windows in [start, end)."""
    return features.extract(log, events, roles, start=start, n_windows=max(0, (end - start) // window), window=window)


def suspected(flags: Sequence[bool], k: int = 2, m: int = 3) -> bool:
    """The CH-suspected rule: flagged in at least k of the last m windows."""
    return sum(1 for f in flags[-m:] if f) >= k
