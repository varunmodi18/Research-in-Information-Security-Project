"""Seven §4 outcomes reproduced -- §4.1-§4.5 succeed, §4.6 succeeds under its stated premise,
§4.7 is a structural failure. Also: the §4.6 seeded key state is unreachable from
icmds.session_key.decrypt (no such literal-decryption function exists / produces it), and no
energy/exhaustion model exists anywhere in the codebase."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from attacks.icmds import (
    a1_replay,
    a2_dos,
    a3_ch_impersonation,
    a4_no_mutual_auth,
    a5_sybil,
    a6_node_capture,
    a7_sk_impossible,
)
from maka import params, rng, trace

REPO_ROOT = Path(__file__).resolve().parent.parent


def _fresh(run_id: str) -> None:
    rng.seed(9)
    trace.init(run_id=run_id, out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)


@pytest.mark.parametrize("mod,expect_substr", [
    (a1_replay, "SUCCEEDS"),
    (a2_dos, "SUCCEEDS"),
    (a3_ch_impersonation, "SUCCEEDS"),
    (a4_no_mutual_auth, "SUCCEEDS"),
    (a5_sybil, "SUCCEEDS"),
    (a6_node_capture, "SUCCEEDS UNDER THE STATED PREMISE"),
])
def test_attack_verdicts(mod, expect_substr: str) -> None:
    _fresh(f"test-{mod.__name__}")
    p = params.get("toy")
    verdict = mod.run(p.curve, p.g)
    assert expect_substr in verdict


def test_a7_is_structural_failure_not_generic_error() -> None:
    _fresh("test-a7")
    p = params.get("toy")
    verdict = a7_sk_impossible.run(p.curve, p.g)
    assert "STRUCTURAL FAILURE" in verdict
    assert "OB-06" in verdict


def test_a7_literal_branch_halt_is_a_recorded_register_condition() -> None:
    """The literal-branch halt must name a register ID (OB-06/AM-09), never a generic error."""
    _fresh("test-a7-halt")
    p = params.get("toy")
    halt_id = a7_sk_impossible._literal_branch(p.curve, p.g)
    assert halt_id in ("OB-06", "AM-09")


def test_no_energy_or_exhaustion_model_anywhere_in_src() -> None:
    forbidden_names = {"battery", "energy_capacity", "time_to_failure", "exhaustion_threshold"}
    offenders = []
    for root in (REPO_ROOT / "src", REPO_ROOT / "attacks", REPO_ROOT / "security"):
        for f in root.rglob("*.py"):
            tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.Name)) and getattr(node, "id", getattr(node, "name", "")).lower() in forbidden_names:
                    offenders.append(str(f))
    assert not offenders, f"an energy/exhaustion model exists: {offenders}"


def test_a6_seeded_key_never_produced_by_session_key_decrypt() -> None:
    """icmds.session_key exposes no `decrypt` that yields a session key from a real ciphertext
    without the OB-06/AM-09 obstructions -- the a6 premise is seeded, not derived."""
    from icmds import session_key

    assert not hasattr(session_key, "decrypt"), (
        "a literal session_key.decrypt() must not exist without also halting on OB-06/AM-09; "
        "a6_node_capture's premise must remain seeded, never derived from it"
    )
