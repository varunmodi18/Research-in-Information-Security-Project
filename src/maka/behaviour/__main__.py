"""`python -m maka.behaviour build|train|evaluate|all` (docs/BEHAVIOUR.md §Regenerating).

build     runs the simulations and writes dataset.csv + manifest.json
train     fits and calibrates both detectors on the train/validation runs -> model.joblib
evaluate  scores the test runs -> results_<date>.json and results_<date>.md
all       the three in sequence (the one command that regenerates everything)

`train` and `evaluate` need the `[ml]` extra.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from dataclasses import replace
from pathlib import Path

from maka.behaviour import dataset, traffic

DEFAULT_OUT = Path("artifacts/behaviour")


def _config(args: argparse.Namespace) -> dataset.DatasetConfig:
    cfg = dataset.DatasetConfig(benign_seeds=args.benign_seeds, fault_seeds=args.fault_seeds,
                                topologies=tuple(args.topologies))
    if args.observe_steps is not None:
        t = cfg.traffic
        scale = args.observe_steps / t.observe_steps
        cfg = replace(cfg, traffic=replace(t, observe_steps=args.observe_steps,
                                           fault_start=int(t.fault_start * scale),
                                           fault_duration=int(t.fault_duration * scale)))
    return cfg


def _say(text: str) -> None:
    sys.stdout.write(text + "\n")  # no bare print() under src/ (tests/test_hygiene.py)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m maka.behaviour", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("build", "train", "evaluate", "all"))
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--benign-seeds", type=int, default=dataset.DatasetConfig.benign_seeds)
    parser.add_argument("--fault-seeds", type=int, default=dataset.DatasetConfig.fault_seeds)
    parser.add_argument("--topologies", nargs="+", default=list(dataset.TOPOLOGIES), choices=dataset.TOPOLOGIES)
    parser.add_argument("--observe-steps", type=int, default=None,
                   help=f"steps per run (default {traffic.TrafficConfig.observe_steps}); the fault span scales with it")
    parser.add_argument("--date", default=datetime.date.today().isoformat(), help="date in the results file name")
    args = parser.parse_args(argv)
    out: Path = args.out
    if args.command in ("build", "all"):
        rows, manifest = dataset.build(_config(args))
        path = dataset.write(rows, manifest, out)
        _say(f"dataset: {path} ({manifest['rows']} rows, {manifest['positive_rows']} labelled abnormal, "
              f"{len(manifest['runs'])} runs)")
    if args.command in ("train", "all"):
        from maka.behaviour import evaluate as ev

        model = ev.train(dataset.read(out / "dataset.csv"))
        ev.save_model(model, out / "model.joblib")
        _say(f"model: {out / 'model.joblib'} (thresholds {json.dumps({d.name: d.threshold for d in model['detectors']})})")
    if args.command in ("evaluate", "all"):
        from maka.behaviour import evaluate as ev

        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        res = ev.evaluate(dataset.read(out / "dataset.csv"), ev.load_model(out / "model.joblib"), manifest, args.date)
        jpath, mpath = ev.write_results(res, out)
        _say(f"results: {jpath}, {mpath}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
