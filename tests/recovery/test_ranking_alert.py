"""Candidate ranking, the behaviour monitor's baseline and the "CH suspected" alert (docs/RECOVERY.md)."""

from __future__ import annotations

import pytest

from maka.behaviour import dataset, features
from maka.behaviour.traffic import LossyForwardingCH
from maka.enhanced import network as en
from maka.recovery import controller, monitor, ranking
from maka.runtime.events import SecurityEvent

E = ranking.Evidence


def test_score_formula_and_components() -> None:
    a = E("CM-A", anomaly=(0.2, 0.4), accepted=9, gaps=1, rejections=0)
    b = E("CM-B", anomaly=(0.0, 0.0), accepted=4, gaps=4, rejections=2)
    ranked = ranking.rank([a, b])
    by = {c.ident: c for c in ranked}
    assert by["CM-A"].trust == pytest.approx(0.7) and by["CM-A"].reliability == pytest.approx(0.9)
    assert by["CM-A"].rejections_norm == 0 and by["CM-A"].score == pytest.approx(0.5 * 0.7 + 0.4 * 0.9)
    assert by["CM-B"].trust == 1.0 and by["CM-B"].reliability == 0.5 and by["CM-B"].rejections_norm == 1.0
    assert by["CM-B"].score == pytest.approx(0.5 + 0.2 - 0.1)
    assert [c.ident for c in ranked] == ["CM-A", "CM-B"]  # 0.71 > 0.60
    assert ranked[0].as_dict()["score"] == round(ranked[0].score, 4)


def test_ties_are_broken_by_identity_and_empty_evidence_is_handled() -> None:
    same = {"anomaly": (0.5,), "accepted": 1, "gaps": 0, "rejections": 0}
    assert [c.ident for c in ranking.rank([E("CM-9", **same), E("CM-1", **same), E("CM-5", **same)])] == [
        "CM-1", "CM-5", "CM-9"]
    silent = ranking.rank([E("CM-X", anomaly=(), accepted=0, gaps=0, rejections=0)])[0]
    assert silent.trust == 0.0 and silent.reliability == 0.0 and silent.score == 0.0  # no evidence, no credit
    assert ranking.rank([]) == []


def test_evidence_from_rows_and_events() -> None:
    def row(dev: str, k: int, acc: int, gaps: int) -> dict[str, object]:
        return {"device": dev, "role": "CM", "window": k, **dict.fromkeys(features.FEATURES, 0),
                "readings_accepted_at_bs": acc, "seq_gaps_at_bs": gaps}
    rows = [row("CM-1", 0, 2, 0), row("CM-1", 1, 1, 1), row("CM-2", 0, 0, 0), row("CM-2", 1, 3, 0)]
    scores = [0.5, 3.0, 0.0, 1.0]  # threshold 2.0 -> normalised 0.25, 1.0 (clipped), 0.0, 0.5
    events = [SecurityEvent("BAD_TAG", "CH-01", step=15, peer="CM-2"),
              SecurityEvent("UNAUTHORISED_PEER", "BS-01", step=16, peer="CM-2"),
              SecurityEvent("SESSION_SUPERSEDED", "CH-01", step=17, peer="CM-2", details={"by": "x"}),  # a rekey
              SecurityEvent("BAD_TAG", "CH-01", step=99, peer="CM-1"),  # outside the span
              SecurityEvent("BAD_TAG", "CM-1", step=15, peer="CM-1")]  # its own event, not caused
    ev = {e.ident: e for e in ranking.evidence(["CM-1", "CM-2"], rows, scores, 2.0, events, start=0, end=40)}
    assert ev["CM-1"] == E("CM-1", anomaly=(0.25, 1.0), accepted=3, gaps=1, rejections=0)
    assert ev["CM-2"] == E("CM-2", anomaly=(0.0, 0.5), accepted=3, gaps=0, rejections=2)


def test_suspected_rule() -> None:
    assert monitor.suspected([False, True, True])
    assert monitor.suspected([True, False, True, False, True], 2, 3)
    assert not monitor.suspected([True, True, False, False, True], 2, 3)
    assert not monitor.suspected([True], 2, 3) and not monitor.suspected([])
    assert monitor.suspected([True], 1, 1)


def test_pure_python_baseline_matches_the_numpy_detector() -> None:
    pytest.importorskip("sklearn")
    from maka.behaviour.detectors import ZScoreDetector

    rows = dataset.read(monitor.COMMITTED_DATASET)
    split = dataset.split_runs([r["run_id"] for r in rows])
    tr = [r for r in rows if split[r["run_id"]] == dataset.TRAIN]
    va = [r for r in rows if split[r["run_id"]] == dataset.VALIDATION]
    ours, numpy_det = monitor.baseline(), ZScoreDetector().fit(tr).calibrate(va)
    for role in features.ROLES:
        assert ours.threshold[role] == pytest.approx(numpy_det.threshold[role], rel=1e-9)
    sample = [r for r in rows if split[r["run_id"]] == dataset.TEST][:500]
    assert [ours.flag(r) for r in sample] == list(numpy_det.flag(sample))


def _drive(net: en.EnhancedNetwork, windows: int) -> list[controller.ClusterStatus]:
    start, history = net.scheduler.step_no, []
    for _ in range(windows):
        for cm in ("CM-0101", "CM-0102", "CM-0103"):
            net.send_reading(cm, "21.0")
        net.step(20)
        history.append(controller.assess(net, start)[0])
    return history


def test_alert_on_a_lossy_ch_never_acts() -> None:
    net = en.build("toy", "small", seed=3)
    net.onboard()
    lossy = LossyForwardingCH.convert(net.device("CH-01"), 0.3, fault_seed=3)  # lab-only, in place
    assert net.device("CH-01").current_session("BS-01", "CH-BS") is not None  # sessions kept
    history = _drive(net, 12)
    assert lossy.left_out > 0
    first = next(i for i, s in enumerate(history) if s.suspected)
    status = history[first]
    assert status.ch == "CH-01" and sum(status.flags) >= 2
    assert [c.ident for c in status.candidates] and status.candidates == sorted(
        status.candidates, key=lambda c: (-c.score, c.ident))
    assert status.trust_detector in (monitor.ISOLATION_FOREST, monitor.Z_BASELINE)
    d = status.as_dict()
    assert d["recommended"] == status.candidates[0].ident and d["trigger_detector"] == monitor.Z_BASELINE
    # alert only: nothing changed in the network
    bs = net.bs()
    assert bs.cluster_ch["CH-01"] == "CH-01" and bs.registry["CH-01"].status != "revoked"
    assert not any(e.type in ("CH_PROMOTED", "DEVICE_REVOKED") for e in net.scheduler.events)


def test_no_alert_on_honest_chs_after_onboarding() -> None:
    for seed in range(3):
        net = en.build("toy", "small", seed=seed)
        net.onboard()
        assert not any(s.suspected for s in _drive(net, 15)), seed


def test_conversion_is_off_by_default_and_forwards_everything_at_one() -> None:
    net_ch = en.build("toy", "small", seed=4)
    net_ch.onboard()
    fresh = LossyForwardingCH("X-01", "X-01", net_ch.device("CH-01").keystore, net_ch.device("CH-01").rng,
                              net_ch.cfg, member_config=[])
    assert fresh.forward_fraction == 1.0  # constructed: no fault until the driver sets one
    lossy = LossyForwardingCH.convert(net_ch.device("CH-01"), 1.0, fault_seed=4)
    mark = len(net_ch.scheduler.events)
    _drive(net_ch, 3)
    net_ch.run()
    assert lossy.left_out == 0
    assert sum(1 for e in net_ch.scheduler.events[mark:] if e.type == "DATA_ACCEPTED") == 9  # 3 windows x 3 CMs
