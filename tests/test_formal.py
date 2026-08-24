"""BAN goals reachable; HLPSL syntax valid."""

from __future__ import annotations

from formal.avispa import syntax_check
from formal.ban import maka_proof
from maka import trace


def test_ban_all_four_goals_reached() -> None:
    trace.init(run_id="test-ban", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    results = maka_proof.run()
    assert set(results) == {1, 2, 3, 4}
    assert all(results.values())


def test_hlpsl_syntax_valid() -> None:
    errors = syntax_check.check()
    assert not errors, errors


def test_hlpsl_declares_five_roles() -> None:
    text = syntax_check.HLPSL_PATH.read_text(encoding="utf-8")
    for role in ("basestation", "clusterhead", "clustermember", "session", "environment"):
        assert f"role {role}" in text
