"""BAN goals checked against RP9's goal statements (V-EVAL-03); HLPSL syntax valid."""

from __future__ import annotations

from formal.avispa import syntax_check
from formal.ban import maka_proof
from formal.ban.engine import Belief

from maka import trace


def test_ban_goal_verdicts() -> None:
    """M1-T9: Goals 3-4 are derived; Goals 1-2 (beliefs about SK_BS-CH) are unreachable."""
    trace.init(run_id="test-ban", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    results = maka_proof.run()
    assert results == {1: maka_proof.UNREACHABLE, 2: maka_proof.UNREACHABLE,
                       3: maka_proof.REACHED, 4: maka_proof.REACHED}


def test_v_eval_03_altered_expected_belief_fails() -> None:
    trace.init(run_id="test-ban-mut", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    derived = maka_proof.derive()
    altered = dict(maka_proof.EXPECTED)
    altered[3] = Belief("CM", "CH |= (A1,A2,Nc_CM)")
    altered[4] = Belief("BS", "CM |= (A3,A4,Nc_CM)")
    verdicts = maka_proof.verdicts(derived, altered)
    assert verdicts[3] == maka_proof.NOT_REACHED
    assert verdicts[4] == maka_proof.NOT_REACHED


def test_hlpsl_syntax_valid() -> None:
    errors = syntax_check.check()
    assert not errors, errors


def test_hlpsl_declares_five_roles() -> None:
    text = syntax_check.HLPSL_PATH.read_text(encoding="utf-8")
    for role in ("basestation", "clusterhead", "clustermember", "session", "environment"):
        assert f"role {role}" in text


# -- IMPLEMENTATION_PLAN.md M7-T1..T3 ------------------------------------------------------

def _kinds(name: str) -> list[tuple[str, str]]:
    return [(f.kind, f.where) for f in syntax_check.lint(syntax_check.HERE / name)]


def test_transcription_shows_rp9_printed_defects() -> None:
    found = _kinds("rp9_transcribed.hlpsl")
    assert ("lhs-action", "clustermember transition 2") in found  # D1
    assert ("lhs-action", "clusterhead transition 3") in found  # D2
    assert ("lhs-action", "clusterhead transition 4") in found  # D1
    assert ("vacuous-goal", "sec3") in found  # D7


def test_fixed_and_enhanced_models_are_structurally_clean() -> None:
    assert _kinds("rp9_fixed.hlpsl") == [("vacuous-goal", "sec3")]  # D7 kept and reported
    assert _kinds("maka_e.hlpsl") == []


def test_v_formal_01_03_results_or_not_run_recorded() -> None:
    import json

    here = syntax_check.HERE
    assert (here / "NOT_RUN.md").exists()  # HLPSL / CL-AtSe: not obtained (M7-T1 decision)
    summary = json.loads((here / "results" / "SUMMARY.json").read_text(encoding="utf-8"))
    outcome = {(m, r["sessions"]): r["summary"] for m, runs in summary["results"].items() for r in runs}
    assert outcome[("maka_e_ake", 1)] == outcome[("maka_e_ake", 2)] == outcome[("maka_e_ake", 3)] == "NO_ATTACK_FOUND"
    assert outcome[("maka_e_ake_nopsk_control", 1)] == "ATTACK_FOUND"
    assert outcome[("rp9_auth_honest_ch", 1)] == "ATTACK_FOUND"
    assert outcome[("rp9_auth_outsider", 1)] == "NO_ATTACK_FOUND"
    assert outcome[("rp9_auth_outsider", 2)] == "ATTACK_FOUND"
    for model, runs in summary["results"].items():
        for r in runs:
            raw = (here / "results" / f"{model}.sessions{r['sessions']}.txt").read_text(encoding="utf-8")
            assert r["summary"] in raw
