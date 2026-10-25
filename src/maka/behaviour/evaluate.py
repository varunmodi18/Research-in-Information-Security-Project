"""Split-by-run training and evaluation (docs/BEHAVIOUR.md §Evaluation). Needs the `[ml]` extra.

Runs, not windows, are split, so no seed contributes windows to two splits: benign runs of each
topology are shuffled with a fixed seed into train / validation / test (60/20/20); fault runs are
used only in test. Detectors are fitted on train and calibrated on validation (1 % target false
alarms on benign windows). Reported per fault variant and detector: precision, recall and F1 over
all device-windows of that variant's test runs; false alarms per 1,000 non-faulty windows of those
runs; detection delay in windows from the start of the fault to the first alert on the faulty
device. False alarms per 1,000 device-windows on the benign test runs are reported per detector.
"""

from __future__ import annotations

import json
import statistics
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn

from maka.behaviour import dataset
from maka.behaviour.dataset import (  # pure Python: the recovery monitor uses it without [ml]
    FRACTIONS,
    SPLIT_SEED,
    TEST,
    TRAIN,
    VALIDATION,
    split_runs,
)
from maka.behaviour.detectors import (
    SIGMA_FLOOR,
    TARGET_FA,
    Detector,
    IsolationForestDetector,
    ZScoreDetector,
    ZStats,
)

MODEL_SEED = 0

FRAMING = ("Experimental. MAKA-E establishes who a device is; this monitor looks for authenticated devices that "
           "behave abnormally, which cryptography cannot rule out (docs/RESIDUAL_RISKS.md R-07, R-12). It runs at "
           "the base station on frames and security events the system already records, and only raises alerts: it "
           "never revokes, rekeys or blocks anything. The abnormal behaviour is injected faults in our own "
           "simulator, so these numbers do not transfer to real deployments.")
LIMITATIONS = [
    "Simulated data only: toy parameters, one frame per scheduler step, no radio loss or timing realism.",
    "Our own injected faults (excessive rekeying, lossy forwarding), chosen by us; other abnormal behaviour is untested.",
    "Alerts only: the monitor never revokes, rekeys or blocks a device, and an alert is not proof of misbehaviour.",
    "The near-normal rekey variant shows the limit: behaviour close to normal is mostly not detected.",
    "Thresholds are set for 1 % false alarms on benign validation windows; real traffic would need recalibration.",
    ("Small samples (20 fault runs per variant, 16 benign test runs): a different random stream during development "
    "gave noticeably different numbers, so differences of a few points between the detectors are not meaningful."),
]


def train(rows: Sequence[dict[str, Any]], seed: int = MODEL_SEED) -> dict[str, Any]:
    split = split_runs([r["run_id"] for r in rows])
    tr = [r for r in rows if split[r["run_id"]] == TRAIN]
    va = [r for r in rows if split[r["run_id"]] == VALIDATION]
    detectors: list[Detector] = [ZScoreDetector().fit(tr).calibrate(va),
                                 IsolationForestDetector(seed=seed).fit(tr).calibrate(va)]
    return {"detectors": detectors, "stats": ZStats().fit(tr), "split": split, "seed": seed,
            "sklearn": sklearn.__version__}


def save_model(model: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load_model(path: Path) -> dict[str, Any]:
    model: dict[str, Any] = joblib.load(path)  # our own artefact, written by save_model
    return model


def _rate(n: int, d: int) -> float:
    return round(1000 * n / d, 2) if d else 0.0


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return round(prec, 3), round(rec, 3), round(f1, 3)


def evaluate(rows: Sequence[dict[str, Any]], model: dict[str, Any], manifest: dict[str, Any], date: str) -> dict[str, Any]:
    split: dict[str, str] = model["split"]
    test = [r for r in rows if split[r["run_id"]] == TEST]
    fault_windows = {r["run_id"]: (r["fault_device"], set(r["fault_windows"])) for r in manifest["runs"]}
    stats: ZStats = model["stats"]
    benign_fa: dict[str, Any] = {}
    results: list[dict[str, Any]] = []
    explanations: list[dict[str, Any]] = []
    feature_counts: dict[str, Counter[str]] = {}
    variants = sorted({(r["kind"], r["variant"]) for r in test if r["kind"] != dataset.BENIGN})
    for det in model["detectors"]:
        flags = det.flag(test)
        flagged = {i for i, f in enumerate(flags) if f}
        benign_idx = [i for i, r in enumerate(test) if r["kind"] == dataset.BENIGN]
        by_topo = {}
        for topo in sorted({test[i]["topology"] for i in benign_idx}):
            idx = [i for i in benign_idx if test[i]["topology"] == topo]
            by_topo[topo] = {"per_1000": _rate(len(flagged & set(idx)), len(idx)), "windows": len(idx)}
        benign_fa[det.name] = {"per_1000": _rate(len(flagged & set(benign_idx)), len(benign_idx)),
                               "flagged": len(flagged & set(benign_idx)), "windows": len(benign_idx),
                               "by_topology": by_topo}
        for kind, variant in variants:
            idx = [i for i, r in enumerate(test) if r["kind"] == kind and r["variant"] == variant]
            pos = [i for i in idx if test[i]["label"] == 1]
            neg = [i for i in idx if test[i]["label"] == 0]
            tp, fn = len(flagged & set(pos)), len(set(pos) - flagged)
            fp = len(flagged & set(neg))
            delays: list[int | None] = []
            for rid in sorted({test[i]["run_id"] for i in idx}):
                device, windows = fault_windows[rid]
                hits = sorted(test[i]["window"] for i in pos if i in flagged and test[i]["run_id"] == rid
                              and test[i]["device"] == device)
                delays.append(hits[0] - min(windows) if hits else None)
            found = [d for d in delays if d is not None]
            prec, rec, f1 = _prf(tp, fp, fn)
            results.append({"fault": kind, "variant": variant, "detector": det.name, "precision": prec,
                            "recall": rec, "f1": f1, "tp": tp, "fp": fp, "fn": fn, "false_alarms_per_1000_other_windows":
                            _rate(fp, len(neg)), "detected_runs": len(found), "runs": len(delays),
                            "median_delay_windows": statistics.median(found) if found else None,
                            "delays_windows": delays})
        if isinstance(det, IsolationForestDetector):
            for i in sorted(flagged):
                row = test[i]
                top = stats.top_features(row)
                explanations.append({"run_id": row["run_id"], "device": row["device"], "role": row["role"],
                                     "window": row["window"], "label": row["label"], "top_features": top})
                if row["label"] == 1:
                    feature_counts.setdefault(f"{row['kind']}/{row['variant']}", Counter()).update(
                        t["feature"] for t in top)
    n_split = Counter(split.values())
    return {
        "date": date, "experimental": True, "framing": FRAMING, "limitations": LIMITATIONS,
        "config": {"dataset": manifest["config"], "target_false_alarm_rate": TARGET_FA, "sigma_floor": SIGMA_FLOOR,
                   "isolation_forest": {"n_estimators": model["detectors"][1].n_estimators, "seed": model["seed"]},
                   "split_seed": SPLIT_SEED, "split_fractions_benign": list(FRACTIONS), "sklearn": model["sklearn"],
                   "numpy": np.__version__},
        "split": {"runs": dict(n_split), "test_windows": len(test)},
        "thresholds": {d.name: d.threshold for d in model["detectors"]},
        "benign_false_alarms": benign_fa, "results": results,
        "explanation_feature_counts": {k: dict(v.most_common()) for k, v in sorted(feature_counts.items())},
        "explanations": explanations,
    }


def markdown(res: dict[str, Any]) -> str:
    lines = [f"# Behavioural monitoring (experimental): results {res['date']}", "", res["framing"], "",
             "Regenerate: `python -m maka.behaviour all` (docs/BEHAVIOUR.md).", "",
             "## Per injected fault", "",
             ("| Fault | Variant | Detector | Precision | Recall | F1 | False alarms /1k (other windows) | "
             "Detected runs | Median delay (windows) |"), "|---|---|---|---:|---:|---:|---:|---:|---:|"]
    for r in res["results"]:
        delay = "—" if r["median_delay_windows"] is None else f"{r['median_delay_windows']:g}"
        lines.append(f"| {r['fault']} | {r['variant']} | {r['detector']} | {r['precision']:.3f} | {r['recall']:.3f} | "
                     f"{r['f1']:.3f} | {r['false_alarms_per_1000_other_windows']:.1f} | "
                     f"{r['detected_runs']}/{r['runs']} | {delay} |")
    lines += ["", "## False alarms on benign test runs", "",
              "| Detector | Per 1,000 device-windows | Flagged / windows | By topology |", "|---|---:|---:|---|"]
    for name, fa in res["benign_false_alarms"].items():
        topo = ", ".join(f"{t}: {v['per_1000']:.1f}" for t, v in fa["by_topology"].items())
        lines.append(f"| {name} | {fa['per_1000']:.1f} | {fa['flagged']}/{fa['windows']} | {topo} |")
    lines += ["", "## Isolation Forest explanations", "",
              ("Top-3 features by z-score, counted over correctly flagged windows (every flagged window is listed "
              "in the JSON file):"), ""]
    for key, counts in res["explanation_feature_counts"].items():
        lines.append(f"- {key}: " + ", ".join(f"{f} ({n})" for f, n in counts.items()))
    lines += ["", "## Limitations", ""] + [f"- {x}" for x in res["limitations"]]
    lines += ["", f"Runs per split: {res['split']['runs']}. Thresholds: {json.dumps(res['thresholds'])}.", ""]
    return "\n".join(lines)


def write_results(res: dict[str, Any], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    jpath, mpath = out_dir / f"results_{res['date']}.json", out_dir / f"results_{res['date']}.md"
    jpath.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    mpath.write_text(markdown(res), encoding="utf-8")
    return jpath, mpath
