"""M2-T4..T6: original (RP9) mode on the runtime -- V-ORIG-01..07, V-RT-04, V-ARCH-01, and
the Lab-capability checks L1-L3 for the M2-T6 checkpoint."""

from __future__ import annotations

import pytest

from maka import codec, hashing, ibe
from maka.original_rt import messages as m
from maka.original_rt import network as onet
from maka.protocol.p3_node_registration import xor_to_scalar
from maka.runtime import adversary
from maka.runtime.bus import PRODUCT, Bus, Frame
from maka.runtime.device import ACTIVE, FAILED, Device
from maka.runtime.errors import ModeNotAllowed
from maka.runtime.scheduler import Scheduler

SEED = 20260927


def _onboarded(topology: str = "paper", **kw) -> onet.OriginalNetwork:  # type: ignore[no-untyped-def]
    net = onet.build("toy", topology, seed=SEED, **kw)
    net.onboard()
    return net


def _events(net: onet.OriginalNetwork, etype: str) -> list:  # type: ignore[type-arg]
    return [e for e in net.scheduler.events if e.type == etype]


# -- V-ORIG-01..03 ------------------------------------------------------------------

@pytest.mark.parametrize("topology", ["paper", "small", "net"])
def test_v_orig_01_03_honest_runs(topology: str) -> None:
    net = _onboarded(topology)
    bs = net.device(net.bs_id)
    for ch_id, cms in net.chs().items():
        ch = net.device(ch_id)
        assert ch.status == ACTIVE and ch.authenticated_members == set(cms)
        assert ch_id in bs.authenticated_chs
        for cm_id in cms:
            cm = net.device(cm_id)
            assert cm.status == ACTIVE and cm.ch_verified and cm.id_ch == ch_id
    assert not _events(net, "ORIG_AUTH_FAIL") and not _events(net, "DECODE_ERROR")


def test_k_is_gone_from_every_keystore_after_keygen() -> None:
    net = _onboarded("small")
    assert all(not d.keystore.has("k") for d in net.scheduler.devices.values())


# -- V-ORIG-04 ------------------------------------------------------------------------

def test_v_orig_04_secure_pseudo_ids_hide_the_points() -> None:
    net = _onboarded("small")
    bs = net.device(net.bs_id)
    secrets = [codec.enc_point(p) for p in bs.pseudo_ids.values()]
    pseudo = [e.frame for e in net.scheduler.bus.transcript
              if e.frame.label in (m.PSEUDO_BS_CH, m.PSEUDO_CH_CM)]
    assert len(pseudo) == 1 + 3
    for frame in pseudo:
        assert not any(s in frame.payload for s in secrets)


def test_clear_mode_sends_points_in_clear() -> None:
    net = _onboarded("paper", secure_pseudo_ids=False)
    p_ch = net.device(net.bs_id).pseudo_ids["CH-01"]
    frame = next(e.frame for e in net.scheduler.bus.transcript if e.frame.label == m.PSEUDO_BS_CH)
    assert codec.enc_point(p_ch) in frame.payload


# -- V-ORIG-05 ------------------------------------------------------------------------

def test_v_orig_05_bs_output_independent_of_ch_object_state() -> None:
    expected = dict(_onboarded("small").device("BS-01").pseudo_ids)
    net = onet.build("toy", "small", seed=SEED)

    def corrupt(result):  # type: ignore[no-untyped-def]
        if any(f.label == m.BEACON for f in result.emitted):
            ch = net.device("CH-01")
            ch.members = {**ch.members, "EVIL-1": ch.g}
    net.scheduler.hooks.append(corrupt)
    net.onboard()
    assert net.device("BS-01").pseudo_ids == expected


# -- V-ORIG-06 / V-ORIG-07 ----------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3])
def test_v_orig_06_ch_ledger_formula(n: int) -> None:
    net = onet.build("toy", f"custom-1x{n}", seed=SEED, secure_pseudo_ids=False)
    net.onboard()
    auth = net.ledger.total("CH-01", "authentication")
    assert auth["T_SM"] == 2 + n and auth["T_E/D"] == 2 * n + 1
    labels = [e.frame.label for e in net.scheduler.bus.transcript]
    assert labels.count(m.EM2) == 1 and labels.count(m.EM1) == n


def test_v_orig_07_parity_with_rp9_tables_2_and_3() -> None:
    net = _onboarded("paper", secure_pseudo_ids=False)
    for role, ident, ed in (("CM", "CM-0101", 2), ("CH", "CH-01", 4)):
        totals = net.ledger.total(ident)
        assert (totals["T_HG"], totals["T_SM"], totals["T_E/D"], totals["T_P"]) == (1, 4, ed, 1), role
    bits = {phase: sum(e.frame.paper_bits for e in net.scheduler.bus.transcript if e.frame.label in labels)
            for phase, labels in m.TABLE3_LABELS.items()}
    assert bits == {"key generation": 640, "registration": 1760 + 160, "authentication": 2400}


# -- V-RT-04 / V-ARCH-01 ---------------------------------------------------------------------

def _frame_log(net: onet.OriginalNetwork) -> list[tuple[int, str, str, str, bytes]]:
    return [(r.step, r.frame.src, r.to, r.frame.label, r.frame.payload)
            for r in net.scheduler.log if r.frame is not None]


def test_v_rt_04_seeded_runs_are_identical() -> None:
    assert _frame_log(_onboarded("small")) == _frame_log(_onboarded("small"))
    other = onet.build("toy", "small", seed=SEED + 1)
    other.onboard()
    assert _frame_log(other) != _frame_log(_onboarded("small"))


FORBIDDEN = (Device, Scheduler, Bus, onet.OriginalNetwork)


def _references(obj: object, owner: Device, depth: int, seen: set[int], path: str) -> list[str]:
    if depth > 4 or id(obj) in seen:
        return []
    seen.add(id(obj))
    if obj is not owner and isinstance(obj, FORBIDDEN):
        return [path]
    if isinstance(obj, (str, bytes, bytearray, int, float, bool, type(None))):
        return []
    children: list[tuple[str, object]] = []
    if isinstance(obj, dict):
        children = [(f"{path}[{k!r}]", v) for k, v in obj.items()] + [(f"{path}.key", k) for k in obj]
    elif isinstance(obj, (list, tuple, set, frozenset)):
        children = [(f"{path}[{i}]", v) for i, v in enumerate(obj)]
    elif hasattr(obj, "__dict__"):
        children = [(f"{path}.{k}", v) for k, v in vars(obj).items()]
    out = []
    for p, child in children:
        out += _references(child, owner, depth + 1, seen, p)
    return out


def test_v_arch_01_devices_hold_no_cross_references() -> None:
    net = _onboarded("net")
    for dev in net.scheduler.devices.values():
        assert _references(dev, dev, 0, set(), dev.identity) == [], dev.identity


def test_original_mode_refuses_product_networks() -> None:
    with pytest.raises(ModeNotAllowed):
        onet.build("toy", "paper", kind=PRODUCT, seed=1)


# -- M2-T6: Lab capabilities L1-L3 in original mode ---------------------------------------

def test_l1_replayed_em1_is_blocked() -> None:
    net = onet.build("toy", "paper", seed=SEED)
    rec = adversary.Record(adversary.label_is(m.EM1))
    net.scheduler.bus.add_interceptor(rec)
    net.onboard()
    captured = rec.frames[0]
    ok_before = len(_events(net, "ORIG_AUTH_OK"))
    net.scheduler.bus.inject(captured, net.scheduler.step_no)
    net.run()
    assert [e.type for e in net.scheduler.log[-1].events] == ["REPLAY_REJECTED"]
    assert len(_events(net, "ORIG_AUTH_OK")) == ok_before


def test_l2_tampered_em1_is_blocked() -> None:
    net = onet.build("toy", "paper", seed=SEED)
    net.scheduler.bus.add_interceptor(adversary.Modify(adversary.label_is(m.EM1), adversary.flip_byte()))
    net.onboard()
    cm = net.device("CM-0101")
    assert not cm.ch_verified and cm.status == FAILED
    assert _events(net, "DECODE_ERROR")[0].peer == "CH-01"


def test_l3_insider_impersonates_ch_and_succeeds_in_original_mode() -> None:
    """P-01: CM-0101 (an insider) forges the CH's proof for CM-0102 from public values only."""
    net = _onboarded("small")
    insider = net.device("CM-0101")
    victim_id = "CM-0102"
    curve, g = insider.curve, insider.g
    # Everything used below is public: g, the IDs, K_pub, and H(victim ID).
    rho = 1234567
    a1 = rho * g
    a2 = rho * (xor_to_scalar("BS-01", "CH-01", curve.r_group) * g)
    plaintext = codec.encode_auth(a1, a2, bytes(range(20)))
    victim_pu = hashing.hash_to_point(curve, victim_id.encode())
    k_pub = codec.load_point(curve, insider.keystore.get("k_pub"))
    with net.context():
        forged = codec.encode_ibe(ibe.encrypt(curve, g, plaintext, victim_pu, k_pub))
    before = len(_events(net, "ORIG_AUTH_OK"))
    net.scheduler.bus.inject(Frame("CH-01", victim_id, m.EM1, forged), net.scheduler.step_no)
    net.run()
    accepted = [e for e in _events(net, "ORIG_AUTH_OK")[before:] if e.device == victim_id]
    assert accepted and accepted[0].peer == "CH-01"  # the attack SUCCEEDS (documents P-01)
