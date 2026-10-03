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
