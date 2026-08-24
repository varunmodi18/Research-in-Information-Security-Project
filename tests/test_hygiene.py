"""Hygiene tests, per PLAN.md §10.

Grows across phases; only the checks meaningful at the current phase are enabled below.
Each check documents which PLAN.md line requires it, so it is never mistaken for a matter
of taste.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"


def _py_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


def test_no_bare_print_under_src() -> None:
    """PLAN.md §6.1: 'No bare print( anywhere under src/; enforced by a lint test.'"""
    offenders = []
    for f in _py_files(SRC):
        if f.name == "trace.py":
            continue  # trace.py is the one sanctioned print() call site
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                offenders.append(f"{f}:{node.lineno}")
    assert not offenders, f"bare print() found under src/: {offenders}"


def test_no_unseeded_randomness_outside_rng_module() -> None:
    """PLAN.md §0 rule 7 / P1.5: all randomness flows through maka.rng."""
    pattern = re.compile(r"\brandom\.|os\.urandom")
    offenders = []
    for f in _py_files(SRC):
        if f.name == "rng.py":
            continue
        text = f.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(str(f))
    assert not offenders, f"unseeded randomness outside rng.py: {offenders}"


def test_no_timestamps_in_protocol_phases() -> None:
    """PLAN.md P1.5: 'no time.time() inside src/maka/protocol/'."""
    protocol_dir = SRC / "maka" / "protocol"
    if not protocol_dir.exists():
        return
    offenders = []
    for f in _py_files(protocol_dir):
        if "time.time(" in f.read_text(encoding="utf-8"):
            offenders.append(str(f))
    assert not offenders, f"timestamp usage inside protocol/: {offenders}"


def test_no_bare_p_binding_under_src() -> None:
    """PLAN.md IA-02: 'a hygiene test forbids a bare p binding under src/'.

    RP9's p (curve base-field modulus) and ICMDS-P's p (order of G1/G2) are distinct objects
    (see PLAN.md §5.3 IA-02 domain-naming table); code must name them p_field / r_group.
    """
    offenders = []
    for f in _py_files(SRC):
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "p" and isinstance(node.ctx, ast.Store):
                offenders.append(f"{f}:{node.lineno}")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                    if arg.arg == "p":
                        offenders.append(f"{f}:{node.lineno} (param)")
    assert not offenders, f"bare 'p' binding found under src/: {offenders}"
