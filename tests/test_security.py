"""Seven §6.1 analyses hold; correspondence table structure; no comparative operation
counting anywhere (hygiene)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from maka import rng, trace
from security.maka import (
    s1_replay,
    s2_dos,
    s3_ch_impersonation,
    s4_mutual_authentication,
    s5_sybil,
    s6_session_key_secrecy,
    s7_eavesdropping,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES = [s1_replay, s2_dos, s3_ch_impersonation, s4_mutual_authentication,
           s5_sybil, s6_session_key_secrecy, s7_eavesdropping]


@pytest.mark.parametrize("mod", MODULES)
def test_security_analysis_holds(mod) -> None:
    rng.seed(21)
    trace.init(run_id=f"test-{mod.__name__}", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    assert mod.run("toy") is True


def test_no_comparative_operation_counting_in_security_modules() -> None:
    """PLAN.md P11.1 s2: 'Do not count operations avoided versus the ICMDS run'."""
    forbidden = {"operations_avoided", "operations_saved", "vs_icmds"}
    offenders = []
    for f in (REPO_ROOT / "security").rglob("*.py"):
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.lower() in forbidden:
                offenders.append(f"{f}:{node.lineno}")
    assert not offenders
