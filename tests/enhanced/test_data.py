"""M4-T6: data path -- V-POS-04, V-ADV-08, V-ADV-09, per-reading cost and size (§6.6)."""

from __future__ import annotations

from collections import defaultdict

import pytest

from maka.enhanced import messages as m
from maka.enhanced import network as en
from maka.runtime import adversary

from .util import SEED, events, frames, mark, onboarded


@pytest.mark.slow
def test_v_pos_04_twenty_readings_per_cm_on_net() -> None:
    net = onboarded("net")
    for i in range(20):
        for cm in net.cms():
            net.send_reading(cm.identity, f'{{"n": {i}}}')
        net.run()
    got = defaultdict(list)
    for r in net.readings():
        got[r["device"]].append(r["seq"])
    assert {cm: seqs for cm, seqs in got.items()} == {cm.identity: list(range(1, 21)) for cm in net.cms()}
    _ch_holds_no_cm_bs_key(net)


def test_v_pos_04_small() -> None:
    net = onboarded("small")
    for _ in range(3):
        for cm in net.cms():
            net.send_reading(cm.identity, "21.4")
        net.run()
    assert sorted((r["device"], r["seq"]) for r in net.readings()) == [
        (cm, s) for cm in ("CM-0101", "CM-0102", "CM-0103") for s in (1, 2, 3)]
    _ch_holds_no_cm_bs_key(net)


def _ch_holds_no_cm_bs_key(net: en.EnhancedNetwork) -> None:
    cm_bs_keys = set()
    for cm in net.cms():
        s = cm.current_session(net.bs_id, m.CM_BS)
        cm_bs_keys |= {cm.keystore.get(s.key("send")), cm.keystore.get(s.key("recv"))}
    for ch in net.chs():
        assert all(s.purpose != m.CM_BS for s in ch.sessions.values())
        assert not cm_bs_keys & set(ch.keystore.snapshot().values())


def test_per_reading_cost_and_size() -> None:
    net = onboarded("paper")
    before = net.ledger.total("CM-0101")
    value = '{"kind": "simulated reading", "temperature_c": 21.4}'
    net.send_reading("CM-0101", value)
    after = net.ledger.total("CM-0101")
    delta = {op: after.get(op, 0) - before.get(op, 0) for op in set(after) | set(before)}
    assert delta.get("T_P", 0) == 0 and delta.get("T_SM", 0) == 0 and delta.get("T_SM_val", 0) == 0
    assert delta.get("T_S", 0) + delta.get("T_MAC", 0) <= 2
    net.run()
    data_cm = frames(net, "DATA_CM", src="CM-0101")[0]
    assert len(data_cm.payload) <= len(value) + 120


def test_v_adv_08_replayed_data_rejected() -> None:
    net = onboarded("paper")
    net.send_reading("CM-0101", "21.4")
    net.run()
    captured = frames(net, "DATA_CM", src="CM-0101")[0]
    t0 = mark(net)
    net.scheduler.bus.inject(captured, net.scheduler.step_no)
    net.run()
    assert [e.type for e in events(net, "REPLAY_REJECTED", t0)] == ["REPLAY_REJECTED"]
    assert not events(net, "DATA_ACCEPTED", t0)


def test_v_adv_09_reordered_data() -> None:
    net = onboarded("paper")
    net.scheduler.bus.add_interceptor(adversary.Delay(adversary.label_is("DATA_CM"), n=2, limit=1))
    t0 = mark(net)
    net.send_reading("CM-0101", "first")
    net.send_reading("CM-0101", "second")
    net.run()
    assert [e.details["seq"] for e in events(net, "DATA_ACCEPTED", t0)] == [2]
    assert [e.details["seq"] for e in events(net, "REPLAY_REJECTED", t0)] == [1]


def test_unauthenticated_cm_cannot_send() -> None:
    net = en.build("toy", "paper", seed=SEED)
    r = net.send_reading("CM-0101", "too early")
    assert r.reason == "UNAUTHENTICATED_PEER" and not r.emitted
