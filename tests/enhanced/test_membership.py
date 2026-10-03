"""M4-T5: membership, designation, relay -- V-POS-02, V-ADV-10, V-ADV-13, V-ADV-15."""

from __future__ import annotations

from collections import Counter

from maka import codec
from maka.enhanced import messages as m
from maka.enhanced import network as en
from maka.lab import attacker
from maka.original_rt import messages as om
from maka.original_rt import network as onet
from maka.runtime import adversary
from maka.runtime.bus import Frame

from .util import SEED, adversary_rng, events, inject, mark, onboarded


def test_v_pos_02_full_onboarding_on_net() -> None:
    net = onboarded("net")
    initiators = Counter((s.purpose) for d in net.scheduler.devices.values() for s in d.sessions.values()
                         if s.role == "I" and s.state == "ESTABLISHED")
    assert initiators == {m.CH_BS: 3, m.CM_BS: 9, m.CM_CH: 9}
    for cm in net.cms():
        assert cm.designated == cm.cluster and cm.status == "active"
    assert all(d.status == "active" for d in net.scheduler.devices.values())
    assert len(events(net, "HANDSHAKE_OK")) == 21 and len(events(net, "KEY_CONFIRMED")) == 21


def test_v_adv_13_ch_claims_fake_and_foreign_members() -> None:
    net = en.build("toy", "net", seed=SEED)
    net.device("CH-01").member_config += ["CM-9999", "CM-0201"]  # a malicious CH's claim
    net.onboard()
    rejected = {e.peer for e in events(net, "CLAIM_REJECTED")}
    assert rejected == {"CM-9999", "CM-0201"}
    assert net.device("CH-01").grant == {"CM-0101", "CM-0102", "CM-0103"}
    ch = net.device("CH-01")
    t0 = mark(net)
    hs1 = attacker.forge_hs1(ch.curve, ch.g, adversary_rng(), "CM-0201", "CH-01", m.CM_CH).payload
    inject(net, "CM-0201", "CH-01", hs1)
    net.run()
    assert [e.type for e in net.scheduler.events[t0:]] == ["UNAUTHORISED_PEER"]


def test_v_adv_15_cm_refuses_non_designated_ch() -> None:
    net = onboarded("net")
    cm = net.device("CM-0101")
    t0 = mark(net)
    hs1 = attacker.forge_hs1(cm.curve, cm.g, adversary_rng(), "CH-02", "CM-0101", m.CM_CH).payload
    inject(net, "CH-02", "CM-0101", hs1)
    net.run()
    assert [(e.type, e.device) for e in net.scheduler.events[t0:]] == [("NOT_DESIGNATED", "CM-0101")]
    r = net.rekey("CM-0101", "CH-02")[0]  # nor will it start one towards a non-designated CH
    assert r.reason == "NOT_DESIGNATED"


def test_v_adv_10_insider_impersonation_enhanced_blocked_100_of_100() -> None:
    """CM-0101 (insider, using its own keystore) poses as CH-01 to CM-0102."""
    net = onboarded("small")
    insider = net.device("CM-0101")
    stolen = insider.keystore.snapshot()
    guesses = [stolen["psk:CH-01"], insider.psk("CM-0102"), stolen["psk:BS-01"]]
    victim_hs1 = adversary.Record(lambda f: f.label == "HS1" and f.src == "CM-0102" and f.dst == "CH-01")
    net.scheduler.bus.add_interceptor(victim_hs1)
    net.scheduler.bus.add_interceptor(adversary.Drop(lambda f: f.label == "HS1" and f.src == "CM-0102"))
    r = adversary_rng()
    accepted = 0
    for attempt in range(100):
        net.rekey("CM-0102", "CH-01")
        net.step(1)
        hs1 = victim_hs1.frames[-1].payload
        t0 = mark(net)
        inject(net, "CH-01", "CM-0102", attacker.forge_hs2(insider.curve, insider.g, r, hs1, guesses[attempt % 3]))
        net.step(1)
        accepted += len([e for e in events(net, "KEY_CONFIRMED", t0) if e.device == "CM-0102"])
        assert net.scheduler.log[-1].reason == "BAD_TAG"
    assert accepted == 0


def test_v_adv_10_insider_impersonation_original_succeeds_100_of_100() -> None:
    """The same attack against RP9 (P-01): forged A1/A2 need only public values."""
    net = onet.build("toy", "small", seed=SEED)
    net.onboard()
    insider = net.device("CM-0101")
    k_pub = codec.load_point(insider.curve, insider.keystore.get("k_pub"))
    r = adversary_rng()
    accepted = 0
    for _ in range(100):
        forged = attacker.forge_rp9_em1(insider.curve, insider.g, r, k_pub, "BS-01", "CH-01", "CM-0102")
        before = len(net.scheduler.events)
        net.scheduler.bus.inject(Frame("CH-01", "CM-0102", om.EM1, forged), net.scheduler.step_no)
        net.run()
        accepted += len([e for e in net.scheduler.events[before:]
                         if e.type == "ORIG_AUTH_OK" and e.device == "CM-0102"])
    assert accepted == 100
