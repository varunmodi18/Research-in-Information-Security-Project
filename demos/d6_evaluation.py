"""S7: `maka eval --all --fixture paper` -- Tables 2-6, Figures 10-11, accounting
cross-checks, the Table 4 under-specification report.

Realises: PLAN.md P12.
"""

from __future__ import annotations

import csv
from pathlib import Path

from eval import communication, comparison, computation, figures, storage

from maka import trace

TABLES_DIR = Path("artifacts/tables")


def run(params_name: str = "demo", fixture: str = "paper", sizing: str = "paper") -> None:
    t = trace.active()
    t.banner("D6 -- Evaluation", "RP9 §7.1-7.3, §8")

    computation.run(params_name)
    communication.run(params_name, sizing)
    storage.run(params_name)
    comparison.run(params_name)
    figures.run()

    _write_csvs()


def _write_csvs() -> None:
    t = trace.active()
    TABLES_DIR.mkdir(parents=True, exist_ok=True)

    with open(TABLES_DIR / "table3_communication.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["phase", "bits"])
        for phase, bits in communication.PUBLISHED.items():
            w.writerow([phase, bits])

    with open(TABLES_DIR / "table4_storage.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["row", "bits"])
        for i, b in enumerate(storage.PUBLISHED):
            w.writerow([i + 1, b])

    with open(TABLES_DIR / "table5_comparison.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scheme", "formula", "published_ms", "flag"])
        for name, formula, published, flag in comparison.TABLE5:
            w.writerow([name, formula, published, flag])

    with open(TABLES_DIR / "table6_features.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scheme"] + comparison.F_LABELS)
        for name, cells in comparison.TABLE6.items():
            w.writerow([name] + cells)

    t.step("CSV export", f"Tables 3-6 written to {TABLES_DIR}/")


if __name__ == "__main__":
    from maka import rng

    trace.init(run_id="d6-standalone", verbosity=2)
    rng.seed(0)
    run(params_name="toy")
