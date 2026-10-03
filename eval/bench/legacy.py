"""M0-T4: wall-clock time of the legacy reference path (`python -m maka.cli run`).

    python -m eval.bench.legacy --out docs/baseline/legacy_run

Each (fixture, params) run is a fresh subprocess, so import and parameter bootstrap are
included -- the same cost a user of `maka.cli run` pays. Median of `--repeats` runs.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from eval.bench.timing import machine


def time_run(fixture: str, params_name: str, repeats: int) -> dict[str, object]:
    samples = []
    for _ in range(repeats):
        with tempfile.TemporaryDirectory() as tmp:
            start = time.perf_counter()
            subprocess.run([sys.executable, "-m", "maka.cli", "run", "--params", params_name,
                            "--fixture", fixture, "--no-color", "--out", tmp],
                           check=True, capture_output=True)
            samples.append(time.perf_counter() - start)
    return {"fixture": fixture, "params": params_name, "repeats": repeats,
            "median_s": statistics.median(samples), "min_s": min(samples), "max_s": max(samples)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fixtures", nargs="+", default=["paper", "net"])
    ap.add_argument("--params", default="demo")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", default="docs/baseline/legacy_run")
    args = ap.parse_args(argv)

    rows = [time_run(f, args.params, args.repeats) for f in args.fixtures]
    meta = machine()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps({"meta": meta, "results": rows}, indent=2) + "\n",
                                        encoding="utf-8")
    lines = ["# Legacy full-run timings (`python -m maka.cli run`)", "",
             f"Commit `{meta['commit']}` · {meta['cpu']} · {meta['os']} · Python {meta['python']}.",
             "Fresh subprocess per run (includes interpreter start-up and imports).", "",
             "| fixture | params | runs | median (s) | min (s) | max (s) |",
             "|---|---|---:|---:|---:|---:|"]
    lines += [f"| {r['fixture']} | {r['params']} | {r['repeats']} | {r['median_s']:.2f} | "
              f"{r['min_s']:.2f} | {r['max_s']:.2f} |" for r in rows]
    summary = "\n".join(lines) + "\n"
    out.with_suffix(".md").write_text(summary, encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
