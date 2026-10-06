"""M4-T6: data path -- V-POS-04, V-ADV-08, V-ADV-09, per-reading cost and size (§6.6)."""

from __future__ import annotations

from collections import defaultdict

import pytest

from maka.enhanced import messages as m
from maka.enhanced import network as en
from maka.runtime import adversary
from maka.runtime.bus import Frame

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
    # 114 bytes: 116 before the follow-up, minus the 12-byte nonce no longer sent (D6), plus the
    # LP-prefixed 8-byte hop_seq (D1). The §6.6 threshold stays 120.
    assert len(data_cm.payload) == len(value) + 114 <= len(value) + 120


def test_d6_sealed_messages_do_not_carry_the_nonce() -> None:
    net = onboarded("paper")
    net.send_reading("CM-0101", "21.4")
    net.run()
    _, _, inner, _ = m.decode_data_cm(frames(net, "DATA_CM", src="CM-0101")[0].payload)
    sec = m.decode_secure(inner)
    assert len(sec.ct) == len("21.4") + 16  # ciphertext + GCM tag; the nonce 0^32||seq is rebuilt
    assert [r["value"] for r in net.readings()] == ["21.4"]


def test_v_adv_08_replayed_data_rejected() -> None:
    """D1: the CH rejects the replayed DATA_CM on its hop_seq, before batching it."""
    net = onboarded("paper")
    net.send_reading("CM-0101", "21.4")
    net.run()
    captured = frames(net, "DATA_CM", src="CM-0101")[0]
    t0 = mark(net)
    net.scheduler.bus.inject(captured, net.scheduler.step_no)
    net.run()
    assert [(e.type, e.device) for e in events(net, "REPLAY_REJECTED", t0)] == [("REPLAY_REJECTED", "CH-01")]
    assert not events(net, "BATCH_SENT", t0) and not events(net, "DATA_ACCEPTED", t0)


def test_d1_hop_seq_is_covered_by_the_hop_mac() -> None:
    """Rewriting hop_seq to make a replay look fresh breaks the hop tag."""
    net = onboarded("paper")
    net.send_reading("CM-0101", "21.4")
    net.run()
    sid, hop_seq, inner, tag = m.decode_data_cm(frames(net, "DATA_CM", src="CM-0101")[0].payload)
    t0 = mark(net)
    net.scheduler.bus.inject(Frame("CM-0101", "CH-01", "DATA_CM", m.encode_data_cm(sid, hop_seq + 1, inner, tag)),
                             net.scheduler.step_no)
    net.run()
    assert [(e.type, e.device, e.details.get("reason")) for e in events(net, "BAD_TAG", t0)] == [
        ("BAD_TAG", "CH-01", "hop MAC")]
    assert not events(net, "BATCH_SENT", t0)


def test_d1_hop_seq_strictly_increasing_per_session() -> None:
    net = onboarded("paper")
    for v in ("a", "b", "c"):
        net.send_reading("CM-0101", v)
    net.run()
    assert [m.decode_data_cm(f.payload)[1] for f in frames(net, "DATA_CM", src="CM-0101")] == [1, 2, 3]
    assert net.device("CH-01").current_session("CM-0101", m.CM_CH).hop_last == 3
    assert [r["value"] for r in net.readings()] == ["a", "b", "c"]


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
