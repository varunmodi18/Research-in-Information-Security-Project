"""M4-T8 checkpoint: L3, L4, L6 are blocked in MAKA-E and still succeed against RP9; enhanced
onboarding of net/demo meets NFR-PERF-01."""

from __future__ import annotations

import time

import pytest

from maka import codec, hashing, ibe
from maka.enhanced import network as en
from maka.lab import attacker
from maka.original_rt import messages as om
from maka.original_rt import network as onet
from maka.runtime import adversary
from maka.runtime.bus import Frame

from .util import SEED, adversary_rng, events


def test_l4_fake_bs_succeeds_against_rp9() -> None:
    """P-03: in RP9 nothing authenticates the BS to the CH. A fake BS answers the beacon with
    pseudo-identities of its choosing, sealed to H(ID_CH) with the public K_pub."""
    net = onet.build("toy", "paper", seed=SEED)
    net.scheduler.bus.add_interceptor(adversary.Drop(adversary.label_is(om.PSEUDO_BS_CH)))
    net.start_onboarding()
    net.run()
    ch = net.device("CH-01")
    r = adversary_rng()
    fake_p_ch = r.randint(1, ch.curve.r_group) * ch.g
    fake_p_cm = r.randint(1, ch.curve.r_group) * ch.g
    k_pub = codec.load_point(ch.curve, ch.keystore.get("k_pub"))
    forged = codec.encode_ibe(ibe.encrypt(ch.curve, ch.g, codec.encode_pseudo_bs_ch(fake_p_ch, [fake_p_cm]),
                                          hashing.hash_to_point(ch.curve, b"CH-01"), k_pub))
    with net.context():
        net.scheduler.bus.inject(Frame("BS-01", "CH-01", om.PSEUDO_BS_CH, forged), net.scheduler.step_no)
    net.run()
    assert ch.p_ch == fake_p_ch  # the CH accepted the fake BS's values: ATTACK SUCCEEDED


def test_l4_fake_bs_blocked_in_enhanced() -> None:
    net = en.build("toy", "paper", seed=SEED)
    rec = adversary.Record(lambda f: f.label == "HS1" and f.dst == "BS-01")
    net.scheduler.bus.add_interceptor(rec)
    net.scheduler.bus.add_interceptor(adversary.Drop(lambda f: f.label == "HS1" and f.dst == "BS-01", limit=1))
    net.start_onboarding()
    ch = net.device("CH-01")
    # A fake BS (no Pr_BS) answers the captured HS1 with its best guess at PSK_CH,BS.
    forged = attacker.forge_hs2(ch.curve, ch.g, adversary_rng(), rec.frames[0].payload, b"\x00" * 32)
    net.scheduler.bus.inject(Frame("BS-01", "CH-01", "HS2", forged), net.scheduler.step_no)
    net.step(1)
    assert net.scheduler.log[-1].reason == "BAD_TAG"


def test_l6_fake_member_succeeds_against_rp9() -> None:
    """P-10: a malicious CH lists a member that does not exist; the BS registers it."""
    net = onet.build("toy", "paper", seed=SEED)
    ch = net.device("CH-01")
    ch.members["CM-FAKE"] = hashing.hash_to_point(ch.curve, b"CM-FAKE")
    ch.expected_members.append("CM-FAKE")
    net.onboard()
    assert "CM-FAKE" in net.device("BS-01").clusters["CH-01"]  # ATTACK SUCCEEDED


def test_l6_fake_member_blocked_in_enhanced() -> None:
    net = en.build("toy", "paper", seed=SEED)
    net.device("CH-01").member_config.append("CM-FAKE")
    net.onboard()
    assert [e.peer for e in events(net, "CLAIM_REJECTED")] == ["CM-FAKE"]
    assert "CM-FAKE" not in net.device("CH-01").grant


@pytest.mark.slow
def test_nfr_perf_01_enhanced_onboarding_net_demo() -> None:
    start = time.perf_counter()
    net = en.build("demo", "net", seed=SEED)
    net.onboard()
    elapsed = time.perf_counter() - start
    assert all(d.status == "active" for d in net.scheduler.devices.values())
    legacy_net_demo = 17.49  # docs/baseline/legacy_run.md
    assert elapsed <= 60 and elapsed <= 1.5 * legacy_net_demo, elapsed
    pairings = {cm.identity: net.ledger.total(cm.identity).get("T_P", 0) for cm in net.cms()}
    assert max(pairings.values()) <= 2, pairings
