"""Golden-transcript comparison harness. Realises PLAN.md P1.6.

Diffs a fresh JSONL event stream against a committed golden file, field-by-field, treating
`ts` (wall-clock) as the only volatile field.
"""

from __future__ import annotations

import json
from pathlib import Path

VOLATILE_FIELDS = {"ts"}


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def strip_volatile(event: dict) -> dict:
    return {k: v for k, v in event.items() if k not in VOLATILE_FIELDS}


def diff_jsonl(actual: list[dict], golden: list[dict]) -> list[str]:
    diffs = []
    if len(actual) != len(golden):
        diffs.append(f"event count differs: actual={len(actual)} golden={len(golden)}")
    for i, (a, g) in enumerate(zip(actual, golden)):
        sa, sg = strip_volatile(a), strip_volatile(g)
        if sa != sg:
            diffs.append(f"event {i} differs:\n  actual={sa}\n  golden={sg}")
    return diffs
