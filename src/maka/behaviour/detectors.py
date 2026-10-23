"""Anomaly detectors for device-windows (docs/BEHAVIOUR.md §Detectors). Needs the `[ml]` extra.

Both detectors are trained per role (CM, CH) on benign training windows only and calibrated on
benign validation windows: the threshold is the (1 - target_fa) quantile of the validation
scores (an observed score), and a window is flagged when its score is strictly above it, so at most
target_fa of the calibration windows are flagged.

- ZScoreDetector (baseline): per-feature mean and standard deviation; the score is the largest
  absolute z-score over the features. The standard deviation is floored at SIGMA_FLOOR (half a
  count): most features are small counts, and a feature that never varies in training would
  otherwise give an infinite z-score for a difference of one event.
- IsolationForestDetector: scikit-learn's IsolationForest; the score is -score_samples (higher
  is more anomalous).

Both are deterministic for a fixed seed. Alerts only: nothing here acts on a device.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from maka.behaviour.features import FEATURES, ROLES

SIGMA_FLOOR = 0.5
TARGET_FA = 0.01


def matrix(rows: Sequence[dict[str, Any]]) -> np.ndarray:
    return np.array([[float(r[f]) for f in FEATURES] for r in rows], dtype=float).reshape(-1, len(FEATURES))


def by_role(rows: Sequence[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """The rows of each role that has any."""
    out = {role: [r for r in rows if r["role"] == role] for role in ROLES}
    return {role: rs for role, rs in out.items() if rs}


@dataclass
class ZStats:
    """Per-role feature means and (floored) standard deviations from benign training windows."""

    mean: dict[str, np.ndarray] = field(default_factory=dict)
    std: dict[str, np.ndarray] = field(default_factory=dict)

    def fit(self, rows: Sequence[dict[str, Any]]) -> ZStats:
        for role, rs in by_role(rows).items():
            x = matrix(rs)
            self.mean[role] = x.mean(axis=0)
            self.std[role] = np.maximum(x.std(axis=0), SIGMA_FLOOR)
        return self

    def z(self, role: str, x: np.ndarray) -> np.ndarray:
        return np.asarray((x - self.mean[role]) / self.std[role])

    def top_features(self, row: dict[str, Any], k: int = 3) -> list[dict[str, Any]]:
        """The k features with the largest absolute z-score: a simple explanation of an alert."""
        z = self.z(row["role"], matrix([row]))[0]
        order = np.argsort(-np.abs(z), kind="stable")[:k]
        return [{"feature": FEATURES[i], "value": int(row[FEATURES[i]]), "z": round(float(z[i]), 2)} for i in order]


class Detector:
    name = ""

    def __init__(self) -> None:
        self.threshold: dict[str, float] = {}

    def fit(self, rows: Sequence[dict[str, Any]]) -> Detector:
        raise NotImplementedError

    def _score(self, role: str, x: np.ndarray) -> np.ndarray:
        raise NotImplementedError

    def score(self, rows: Sequence[dict[str, Any]]) -> np.ndarray:
        out = np.zeros(len(rows))
        for role in ROLES:
            idx = [i for i, r in enumerate(rows) if r["role"] == role]
            if idx:  # a role absent from training raises KeyError here: it cannot be scored
                out[idx] = self._score(role, matrix([rows[i] for i in idx]))
        return out

    def calibrate(self, rows: Sequence[dict[str, Any]], target_fa: float = TARGET_FA) -> Detector:
        for role, rs in by_role(rows).items():
            # "higher": the threshold is an observed score, so strictly more than it is at most
            # target_fa of the calibration windows (interpolation could exceed the target)
            self.threshold[role] = float(np.quantile(self._score(role, matrix(rs)), 1 - target_fa, method="higher"))
        return self

    def flag(self, rows: Sequence[dict[str, Any]]) -> np.ndarray:
        scores = self.score(rows)
        thr = np.array([self.threshold[r["role"]] for r in rows])
        return np.asarray(scores > thr)


class ZScoreDetector(Detector):
    name = "z-score baseline"

    def __init__(self) -> None:
        super().__init__()
        self.stats = ZStats()

    def fit(self, rows: Sequence[dict[str, Any]]) -> ZScoreDetector:
        self.stats.fit(rows)
        return self

    def _score(self, role: str, x: np.ndarray) -> np.ndarray:
        return np.asarray(np.abs(self.stats.z(role, x)).max(axis=1))


class IsolationForestDetector(Detector):
    name = "Isolation Forest"

    def __init__(self, seed: int = 0, n_estimators: int = 200) -> None:
        super().__init__()
        self.seed, self.n_estimators = seed, n_estimators
        self.models: dict[str, IsolationForest] = {}

    def fit(self, rows: Sequence[dict[str, Any]]) -> IsolationForestDetector:
        for role, rs in by_role(rows).items():
            model = IsolationForest(n_estimators=self.n_estimators, random_state=self.seed)
            self.models[role] = model.fit(matrix(rs))
        return self

    def _score(self, role: str, x: np.ndarray) -> np.ndarray:
        return np.asarray(-self.models[role].score_samples(x))
