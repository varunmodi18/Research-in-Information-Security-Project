"""Dataset builder (docs/BEHAVIOUR.md §Data generation).

Benign runs (default 40 seeds per topology) and fault runs (default 10 seeds per fault variant
per topology) on the `small` and `net` topologies, toy parameters. Each device-window becomes one
row; a row is labelled 1 when it is the faulty device's window overlapping the fault span, from
the fault config (ground truth), else 0. Output: a CSV (no new dependency) and a JSON manifest
with every seed and the full configuration, so the dataset can be regenerated exactly.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from maka.behaviour import features, traffic

TOPOLOGIES = ("small", "net")
BENIGN = "benign"
META = ("run_id", "topology", "seed", "kind", "variant", "device", "role", "window", "label")
COLUMNS = META + features.FEATURES
BENIGN_SEED_BASE, FAULT_SEED_BASE = 1000, 5000


@dataclass(frozen=True)
class DatasetConfig:
    benign_seeds: int = 40
    fault_seeds: int = 10
    topologies: tuple[str, ...] = TOPOLOGIES
    variants: tuple[str, ...] = tuple(traffic.FAULT_VARIANTS)
    traffic: traffic.TrafficConfig = field(default_factory=traffic.TrafficConfig)


def run_specs(cfg: DatasetConfig) -> list[tuple[str, str, int, traffic.Fault | None]]:
    """(run_id, topology, seed, fault) for every run, in a fixed order."""
    specs: list[tuple[str, str, int, traffic.Fault | None]] = []
    for topo in cfg.topologies:
        for i in range(cfg.benign_seeds):
            seed = BENIGN_SEED_BASE + i
            specs.append((f"{topo}/{BENIGN}/{seed}", topo, seed, None))
        for v, name in enumerate(cfg.variants):
            for i in range(cfg.fault_seeds):
                seed = FAULT_SEED_BASE + 100 * v + i
                specs.append((f"{topo}/{name}/{seed}", topo, seed, traffic.FAULT_VARIANTS[name]))
    return specs


def rows_for(run_id: str, record: traffic.RunRecord) -> list[dict[str, Any]]:
    fault_windows = record.fault_windows()
    kind = record.fault.kind if record.fault else BENIGN
    variant = record.fault.variant if record.fault else ""
    out = []
    for row in features.extract(record.log, record.events, record.roles, start=record.observe_start,
                                n_windows=record.n_windows, window=record.config.window):
        label = int(row["device"] == record.fault_device and row["window"] in fault_windows)
        out.append({"run_id": run_id, "topology": record.topology, "seed": record.seed, "kind": kind,
                    "variant": variant, "label": label, **row})
    return out


def build(cfg: DatasetConfig) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    for run_id, topo, seed, fault in run_specs(cfg):
        record = traffic.run(topo, seed, cfg.traffic, fault)
        rows += rows_for(run_id, record)
        runs.append({"run_id": run_id, **record.manifest(),
                     "fault_windows": sorted(record.fault_windows())})
    manifest = {"config": _jsonable(asdict(cfg)), "features": list(features.FEATURES), "columns": list(COLUMNS),
                "rows": len(rows), "positive_rows": sum(r["label"] for r in rows), "runs": runs}
    return rows, manifest


def write(rows: list[dict[str, Any]], manifest: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "dataset.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(COLUMNS), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return path


def read(path: Path) -> list[dict[str, Any]]:
    ints = {"seed", "window", "label", *features.FEATURES}
    with path.open(newline="", encoding="utf-8") as fh:
        return [{k: int(v) if k in ints else v for k, v in row.items()} for row in csv.DictReader(fh)]


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value
