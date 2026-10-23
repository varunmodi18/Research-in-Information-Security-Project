"""Traffic driver, injected faults, labels and dataset structure (docs/BEHAVIOUR.md)."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from maka.behaviour import dataset, features, traffic

SHORT = traffic.TrafficConfig(observe_steps=200, fault_start=60, fault_duration=100)


def _sum(record: traffic.RunRecord, device: str, feature: str, windows: set[int] | None = None) -> int:
    rows = features.extract(record.log, record.events, record.roles, start=record.observe_start,
                            n_windows=record.n_windows, window=record.config.window)
    return sum(r[feature] for r in rows if r["device"] == device and (windows is None or r["window"] in windows))


def test_benign_run_is_normal_and_deterministic() -> None:
    a = traffic.run("small", 11, SHORT)
    b = traffic.run("small", 11, SHORT)
    assert [(f.src, f.dst, f.payload) for r in a.log for f in r.emitted] == \
           [(f.src, f.dst, f.payload) for r in b.log for f in r.emitted]
    assert a.fault is None and a.fault_windows() == set() and a.n_windows == 10
    rows = features.extract(a.log, a.events, a.roles, start=a.observe_start, n_windows=a.n_windows)
    assert sum(r["seq_gaps_at_bs"] for r in rows) == 0  # nothing is lost without a fault
    assert sum(r["readings_accepted_at_bs"] for r in rows) > 0


def test_excessive_rekey_fault_only_inside_its_span() -> None:
    rec = traffic.run("small", 11, SHORT, traffic.FAULT_VARIANTS["excessive_rekey/default"])
    assert rec.fault_device in {"CM-0101", "CM-0102", "CM-0103"}
    assert rec.fault_steps == (rec.observe_start + 60, rec.observe_start + 160)
    assert rec.fault_windows() == set(range(3, 8))
    inside = _sum(rec, rec.fault_device, "handshakes_initiated", rec.fault_windows())
    outside = _sum(rec, rec.fault_device, "handshakes_initiated", set(range(10)) - rec.fault_windows())
    assert inside >= 10 and outside <= 3, (inside, outside)


def test_lossy_forwarding_fault_leaves_readings_out_and_shows_as_gaps() -> None:
    rec = traffic.run("small", 11, SHORT, traffic.FAULT_VARIANTS["lossy_forwarding/default"])
    assert rec.fault_device == "CH-01" and rec.notes["readings_left_out"] > 0
    ch = rec.fault_device
    gaps_in = _sum(rec, ch, "seq_gaps_at_bs", rec.fault_windows())
    assert gaps_in > 0 and _sum(rec, ch, "seq_gaps_at_bs", set(range(3))) == 0
    # the same run without the fault forwards everything
    clean = traffic.run("small", 11, SHORT, replace(traffic.FAULT_VARIANTS["lossy_forwarding/default"],
                                                    forward_fraction=1.0))
    assert clean.notes["readings_left_out"] == 0 and _sum(clean, ch, "seq_gaps_at_bs") == 0


def test_labels_come_from_the_fault_config() -> None:
    rec = traffic.run("small", 11, SHORT, traffic.FAULT_VARIANTS["lossy_forwarding/default"])
    rows = dataset.rows_for("small/lossy_forwarding/default/11", rec)
    positive = {(r["device"], r["window"]) for r in rows if r["label"] == 1}
    assert positive == {(rec.fault_device, k) for k in rec.fault_windows()}


def test_dataset_rows_hold_public_counts_only(tmp_path: Path) -> None:
    cfg = dataset.DatasetConfig(benign_seeds=2, fault_seeds=1, topologies=("small",), traffic=SHORT)
    rows, manifest = dataset.build(cfg)
    assert len(manifest["runs"]) == 2 + len(traffic.FAULT_VARIANTS)
    path = dataset.write(rows, manifest, tmp_path)
    back = dataset.read(path)
    assert back == rows
    assert path.read_text().splitlines()[0].split(",") == list(dataset.COLUMNS)
    for r in back:
        assert set(r) == set(dataset.COLUMNS)
        assert all(isinstance(r[f], int) and r[f] >= 0 for f in features.FEATURES)
        assert re.fullmatch(r"(CM|CH)-\d+", r["device"]) and r["label"] in (0, 1)
        assert re.fullmatch(r"small/[a-z_]+(/[a-z_]+)?/\d+", r["run_id"])
    assert dataset.build(cfg) == (rows, manifest)  # regenerable exactly from the config
