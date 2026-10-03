"""V-LAB-01 (M6-T4): every scenario runs in both modes on a fresh lab network (small, toy,
seed 20260927), produces a verdict with linked evidence, and matches IMPLEMENTATION_PLAN.md
§3.6 -- or the mismatch is recorded in docs/OPEN_ISSUES.md."""

from __future__ import annotations

import re

import pytest

from maka.lab import scenarios as sc

CASES = [(s.id, mode) for s in sc.ALL for mode in sc.MODES]


@pytest.mark.parametrize(("sid", "mode"), CASES)
def test_v_lab_01(sid: str, mode: str) -> None:
    scenario = sc.BY_ID[sid]
    run = scenario.execute(mode, params="toy", topology="small", seed=sc.DEFAULT_SEED)
    v = run.verdict
    assert v is not None and v.result in (sc.SUCCEEDED, sc.BLOCKED)
    assert v.evidence_frame_ids or v.event_indices, "a verdict needs linked evidence"
    known = {e.frame.frame_id for e in run.net.scheduler.bus.transcript}
    assert set(v.evidence_frame_ids) <= known
    assert all(0 <= i < len(run.net.scheduler.events) for i in v.event_indices)
    assert v.result == scenario.expected[mode], (sid, mode, v.explanation)


def test_l5_reports_secret_names_only() -> None:
    for mode in sc.MODES:
        v = sc.BY_ID["L5"].execute(mode).verdict
        assert v is not None and v.secrets_obtained
        for name in v.secrets_obtained:
            assert re.fullmatch(r"[a-z_]+(:[A-Za-z0-9-]+)*(:[a-z]+)?|sess:[0-9a-f]{32}:[a-z]+", name), name
    original = sc.BY_ID["L5"].execute(sc.ORIGINAL).verdict
    enhanced = sc.BY_ID["L5"].execute(sc.ENHANCED).verdict
    assert original.measurements["master_key_captured"] and not enhanced.measurements["master_key_captured"]
    assert "CM-0102" in original.measurements["decrypted_devices"]
    assert enhanced.measurements["decrypted_devices"] == [] and not enhanced.measurements["past_session_keys_derived"]


def test_scenarios_are_deterministic_for_a_seed() -> None:
    a = sc.BY_ID["L3"].execute(sc.ENHANCED).net.scheduler.bus.transcript
    b = sc.BY_ID["L3"].execute(sc.ENHANCED).net.scheduler.bus.transcript
    assert [e.frame.payload for e in a] == [e.frame.payload for e in b]
