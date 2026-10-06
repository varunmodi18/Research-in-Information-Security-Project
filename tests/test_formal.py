"""BAN goals checked against RP9's goal statements (V-EVAL-03); HLPSL syntax valid."""

from __future__ import annotations

import json
from typing import Any

from formal.avispa import summarize_avispa, syntax_check
from formal.ban import maka_proof
from formal.ban.engine import Belief

from maka import trace

AVISPA = syntax_check.HERE / "results" / "avispa"
OFMC, CL225, CL234 = "OFMC (2006/02/13)", "CL-AtSe 2.2-5", "CL-AtSe 2.3-4"


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
    # rp9_fixed fixes only what a tool rejects (D1, D8): D2 is accepted by both translators and both
    # back-ends, so the lint still flags it; D7 is kept and reported.
    assert _kinds("rp9_fixed.hlpsl") == [("lhs-action", "clusterhead transition 3"), ("vacuous-goal", "sec3")]
    assert _kinds("rp9_executable.hlpsl") == _kinds("rp9_insider.hlpsl") == [("vacuous-goal", "sec3")]
    assert _kinds("maka_e.hlpsl") == _kinds("maka_e_nopsk_control.hlpsl") == []


# -- follow-up Part C: real AVISPA runs (V-FORMAL-01..03) and the OFMC 2024 AnB runs -----------------

def _avispa() -> dict[str, Any]:
    return json.loads((AVISPA / "SUMMARY.json").read_text(encoding="utf-8"))


def _run(model: dict[str, Any], goal: str, backend: str) -> dict[str, Any]:
    (run,) = [r for r in model["runs"] if r["goal"] == goal and r["backend"] == backend]
    return run


def _executes(model: dict[str, Any]) -> set[str]:
    return {t for t, v in model["executability_ofmc2006"].items() if v == "executes"}


def test_v_formal_avispa_outputs_exist_and_parse() -> None:
    """SUMMARY.json is exactly what the committed raw outputs parse to; every run finished."""
    summary = _avispa()
    assert summarize_avispa.summarize() == summary
    assert set(summary["models"]) == set(summarize_avispa.MODELS)
    for name, model in summary["models"].items():
        assert model["runs"], name
        for run in model["runs"]:
            assert (syntax_check.HERE / run["file"]).is_file()
            assert run["verdict"] in ("SAFE", "UNSAFE", "REFUSED", "ERROR", "TIMEOUT"), (name, run)
        assert model["executability_ofmc2006"], name
    assert (AVISPA / "calibration_span_testsuite.txt").is_file()


def test_v_formal_01_rp9_as_printed() -> None:
    m = _avispa()["models"]["rp9_transcribed"]
    assert m["translation"]["64"]["accepted"]
    assert not m["translation"]["32"]["accepted"] and "hash_func" in m["translation"]["32"]["errors"][0]
    ofmc = _run(m, "all goals", OFMC)
    assert ofmc["verdict"] == "SAFE"  # RP9 Fig. 9: SAFE, 1501 visited nodes, depth 7 plies
    assert (ofmc["statistics"]["visited_nodes"], ofmc["statistics"]["depth_plies"]) == (1501, 7)
    for backend in (CL225, CL234):
        assert _run(m, "all goals", backend)["verdict"] == "REFUSED"  # "request in left-hand side." (D1)
    assert _executes(m) == {"cm1", "ch1", "bs1"}  # so every goal holds vacuously (OB-11)


def test_v_formal_02_rp9_fixed_and_executable() -> None:
    models = _avispa()["models"]
    fixed = models["rp9_fixed"]
    assert fixed["translation"]["32"]["accepted"]  # D8 was the only translator rejection
    ofmc = _run(fixed, "all goals", OFMC)
    assert ofmc["verdict"] == "SAFE" and ofmc["statistics"]["visited_nodes"] == 1501
    assert _run(fixed, "all goals", CL225)["verdict"] == "SAFE"
    assert _executes(fixed) == {"cm1", "ch1", "bs1"}
    executable = models["rp9_executable"]
    assert _executes(executable) == set(executable["executability_ofmc2006"]) == set(fixed["executability_ofmc2006"])
    assert len(_executes(executable)) == 8  # every transition of every role can run
    assert _run(executable, "all goals", OFMC)["verdict"] == "UNSAFE"
    for goal in ("auth-em1", "auth-em2", "auth-em3"):
        assert _run(executable, goal, OFMC)["verdict"] == "UNSAFE"
    insider = models["rp9_insider"]
    assert _run(insider, "all goals", OFMC)["verdict"] == "UNSAFE"


def test_v_formal_03_maka_e() -> None:
    models = _avispa()["models"]
    m = models["maka_e"]
    assert _executes(m) == set(m["executability_ofmc2006"]) == {"i1", "i2", "r1", "r2"}
    typed = [r for r in m["runs"] if "untyped" not in r["backend"]]
    assert {r["goal"] for r in typed} == {"all goals", "auth-n_i", "auth-n_r", "secrecy-k_ir", "secrecy-k_ri"}
    assert {r["verdict"] for r in typed} == {"SAFE"}
    assert _run(m, "all goals", OFMC + ", untyped")["verdict"] == "SAFE"
    # Recorded finding: in the untyped model CL-AtSe shifts a field boundary and attacks n_r. The
    # implementation's length-prefixed, fixed-width fields exclude it (tests/enhanced/test_ake.py
    # ::test_untyped_boundary_shift_in_hs1/hs2_is_rejected).
    untyped = _run(m, "all goals", CL225 + ", untyped")
    assert untyped["verdict"] == "UNSAFE" and "n_r" in untyped["violated"]
    control = models["maka_e_nopsk_control"]
    assert {r["verdict"] for r in control["runs"]} == {"UNSAFE"}
    assert _executes(control) == set(control["executability_ofmc2006"])


def test_v_formal_anb_results() -> None:
    here = syntax_check.HERE
    summary = json.loads((here / "results" / "SUMMARY.json").read_text(encoding="utf-8"))
    assert summarize_avispa.summarize_anb() == summary
    outcome = {(m, r["sessions"]): r["summary"] for m, runs in summary["results"].items() for r in runs}
    assert outcome[("maka_e_ake", 1)] == outcome[("maka_e_ake", 2)] == outcome[("maka_e_ake", 3)] == "NO_ATTACK_FOUND"
    assert outcome[("maka_e_ake_nopsk_control", 1)] == "ATTACK_FOUND"
    assert outcome[("rp9_auth_honest_ch", 1)] == "ATTACK_FOUND"
    assert outcome[("rp9_auth_outsider", 1)] == "NO_ATTACK_FOUND"
    assert outcome[("rp9_auth_outsider", 2)] == "ATTACK_FOUND"
    # forward secrecy (Part C3.1): no attack at 1 session; at 2 the leak is of a session completed
    # after the compromise (formal/avispa/README.md); the no-DH control is attacked at both
    assert outcome[("maka_e_ake_fs", 1)] == "NO_ATTACK_FOUND"
    assert outcome[("maka_e_ake_fs", 2)] == "ATTACK_FOUND"
    assert outcome[("maka_e_ake_fs_nodh_control", 1)] == outcome[("maka_e_ake_fs_nodh_control", 2)] == "ATTACK_FOUND"
    for runs in summary["results"].values():
        for r in runs:
            assert r["summary"] in (here / r["file"]).read_text(encoding="utf-8")


def test_v_formal_evaluation_data_matches_outputs() -> None:
    """The Evaluation page's two formal tables show exactly the committed outputs."""
    from maka_server.services import evaluation

    data = evaluation.avispa_rows()
    assert data["obtained"]
    summary = _avispa()
    expected = {(name, r["backend"]) for name, m in summary["models"].items() for r in m["runs"] if r["goal"] == "all goals"}
    assert {(r["model"], r["backend"]) for r in data["rows"]} == expected
    for row in data["rows"]:
        parsed = summarize_avispa.parse_run((evaluation.REPO_ROOT / row["file"]).read_text(encoding="utf-8"))
        assert (row["verdict"], row["statistics"]) == (parsed["verdict"], parsed.get("statistics", {}))
    anb = json.loads((evaluation.FORMAL_DIR / "results" / "SUMMARY.json").read_text(encoding="utf-8"))
    assert anb == summarize_avispa.summarize_anb()


def test_v_formal_readme_tables_are_the_committed_outputs() -> None:
    """formal/avispa/README.md's results block is generated, and must equal what the raw outputs give."""
    block = summarize_avispa.readme_block()
    assert block == summarize_avispa.render(summarize_avispa.summarize(), summarize_avispa.summarize_anb())
    assert "| `maka_e` |" in block and "OFMC 2024 (AnB models)" in block
