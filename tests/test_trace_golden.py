"""P1.6: a fixed toy scenario through the trace engine reproduces byte-identical events
(modulo `ts`) across runs, and against a committed golden file."""

from __future__ import annotations

from pathlib import Path

from maka import trace

from .golden_util import diff_jsonl, load_jsonl

GOLDEN_DIR = Path(__file__).parent / "golden"
GOLDEN_DIR.mkdir(exist_ok=True)
GOLDEN_FILE = GOLDEN_DIR / "toy_scenario.jsonl"


def _run_toy_scenario(out_dir: Path, run_id: str) -> Path:
    t = trace.Tracer(run_id=run_id, out_dir=out_dir, color=False, verbosity=2)
    t.banner("Toy scenario", "P1.6 golden harness")
    t.section(1, "Arithmetic")
    t.step("tester", "computing 2 + 2")
    t.value("result", 4)
    t.check("2 + 2 == 4", True, 4, 4)
    t.register("IA-01", "language and dependency policy")
    t.close()
    return out_dir / f"{run_id}.jsonl"


def test_two_runs_are_byte_identical_modulo_ts(tmp_path: Path) -> None:
    path_a = _run_toy_scenario(tmp_path / "a", "toy")
    path_b = _run_toy_scenario(tmp_path / "b", "toy")
    diffs = diff_jsonl(load_jsonl(path_a), load_jsonl(path_b))
    assert not diffs, diffs


def test_matches_golden_transcript(tmp_path: Path) -> None:
    produced = _run_toy_scenario(tmp_path / "run", "toy")
    if not GOLDEN_FILE.exists():
        GOLDEN_FILE.write_text(produced.read_text(encoding="utf-8"), encoding="utf-8")
    diffs = diff_jsonl(load_jsonl(produced), load_jsonl(GOLDEN_FILE))
    assert not diffs, diffs
