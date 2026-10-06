"""Follow-up E3: forged CLUSTER_OPEN, bad hop MAC, MEMBERSHIP_MISMATCH, forged SESSION_UNKNOWN x50, and
the largest custom topology the console accepts (1 BS, 5 CH, 8 CM each). Residual risk R-13 cites
the hint tests."""

from __future__ import annotations

import pytest

from maka.enhanced import messages as m
from maka.enhanced import network as en

from .util import SEED, events, frames, inject, mark, onboarded


def _delivered(net: en.EnhancedNetwork, since: int) -> list[tuple[str, str]]:
    return [(e.peer, e.details["via"]) for e in events(net, "DATA_ACCEPTED", since)]


# -- forged CLUSTER_OPEN (an unauthenticated hint, R-13) ------------------------------------------

def test_forged_cluster_open_from_another_ch_changes_nothing() -> None:
    net = onboarded("net")
    cm = net.device("CM-0101")
    before = {k: s.sid for k, s in ((k, cm.current_session(*k)) for k in (("BS-01", m.CM_BS), ("CH-01", m.CM_CH)))}
    t0 = mark(net)
    inject(net, "CH-02", "CM-0101", m.encode_open("CH-02", 99))  # names its sender, as a real one must
    net.run()
    # at most one extra CM-BS handshake, relayed via CH-02, which refuses a member outside its grant
    assert len([f for f in frames(net, "RELAY:HS1", src="CM-0101") if f.dst == "CH-02"]) <= 1 + 3
    assert {e.device for e in events(net, "UNAUTHORISED_PEER", t0)} <= {"CH-02"}
    assert cm.designated == "CH-01" and cm.relay_ch == "CH-01"
    assert {k: cm.current_session(*k).sid for k in before} == before  # sessions untouched
    t1 = mark(net)
    net.rekey("CM-0101", "BS-01")  # later handshakes still go through the designated CH
    net.run()
    net.send_reading("CM-0101", "after forged open")
    net.run()
    assert _delivered(net, t1) == [("CM-0101", "CH-01")]


def test_forged_cluster_open_naming_another_sender_is_rejected() -> None:
    net = onboarded("small")
    t0 = mark(net)
    inject(net, "CH-01", "CM-0101", m.encode_open("CH-99", 0))
    net.run()
    assert [(e.type, e.device) for e in net.scheduler.events[t0:]] == [("DECODE_ERROR", "CM-0101")]


# -- bad hop MAC ---------------------------------------------------------------------------------

@pytest.mark.parametrize("how", ["flipped tag", "another member's hop key"])
def test_bad_hop_mac_is_rejected_at_the_ch_before_batching(how: str) -> None:
    from maka.kdf import hmac256

    net = onboarded("small")
    net.send_reading("CM-0101", "21.4")
    net.run()
    sid, hop_seq, inner, tag = m.decode_data_cm(frames(net, "DATA_CM", src="CM-0101")[0].payload)
    if how == "flipped tag":
        bad = tag[:-1] + bytes([tag[-1] ^ 1])
    else:
        other = net.device("CM-0102")
        bad = hmac256(other.keystore.get(other.current_session("CH-01", m.CM_CH).key("hop")),
                      m.hop_mac_input(sid, hop_seq + 1, inner))
    t0 = mark(net)
    inject(net, "CM-0101", "CH-01", m.encode_data_cm(sid, hop_seq + 1, inner, bad))
    net.run()
    assert [(e.type, e.device, e.details["reason"]) for e in net.scheduler.events[t0:]] == [
        ("BAD_TAG", "CH-01", "hop MAC")]
    assert net.device("CH-01").current_session("CM-0101", m.CM_CH).hop_last == hop_seq  # not advanced


# -- MEMBERSHIP_MISMATCH -------------------------------------------------------------------------------

def test_membership_mismatch_a_ch_batching_another_clusters_member() -> None:
    """A compromised CH-02 (its own keys, white-box) batches a genuine reading of CM-0101, which
    belongs to CH-01's cluster. The BS refuses it: CM-0101 is not granted to CH-02."""
    net = onboarded("net")
    net.scheduler.bus.add_interceptor(_drop_first_data_cm("CM-0101"))
    net.send_reading("CM-0101", "diverted")
    net.run()
    inner = _dropped_inner(net)  # a genuine inner frame CH-01 never forwarded
    ch2 = net.device("CH-02")
    with net.context():
        sealed = ch2.seal(ch2.current_session("BS-01", m.CH_BS), m.DATA_BATCH, m.encode_batch([("CM-0101", inner)]))
    t0 = mark(net)
    inject(net, "CH-02", "BS-01", sealed)
    net.run()
    assert [(e.type, e.device, e.peer, e.details.get("ch")) for e in net.scheduler.events[t0:]] == [
        ("MEMBERSHIP_MISMATCH", "BS-01", "CM-0101", "CH-02")]
    assert not events(net, "DATA_ACCEPTED", t0)
    # positive control: the same sealed inner frame through its own CH is accepted
    t1 = mark(net)
    ch1 = net.device("CH-01")
    with net.context():
        legit = ch1.seal(ch1.current_session("BS-01", m.CH_BS), m.DATA_BATCH, m.encode_batch([("CM-0101", inner)]))
    inject(net, "CH-01", "BS-01", legit)
    net.run()
    assert _delivered(net, t1) == [("CM-0101", "CH-01")]


def _drop_first_data_cm(src: str):  # type: ignore[no-untyped-def]
    from maka.runtime import adversary

    return adversary.Drop(lambda f: f.label == "DATA_CM" and f.src == src, limit=1)


def _dropped_inner(net: en.EnhancedNetwork) -> bytes:
    (entry,) = [e for e in net.scheduler.bus.transcript if e.fate == "dropped" and e.frame.label == "DATA_CM"]
    return m.decode_data_cm(entry.frame.payload)[2]


# -- forged SESSION_UNKNOWN x50 (R-13) ----------------------------------------------------------------

def test_fifty_forged_session_unknown_spaced_cost_exactly_one_handshake() -> None:
    """A notice naming the CM's real current session triggers one fresh handshake; once that has
    replaced the session, the remaining 49 name a superseded session and are ignored."""
    net = onboarded("small")
    cm = net.device("CM-0101")
    s = cm.current_session("CH-01", m.CM_CH)
    t0 = mark(net)
    hs1_before = len(frames(net, "HS1", src="CM-0101", dst="CH-01"))
    for _ in range(50):
        inject(net, "CH-01", "CM-0101", m.encode_session_unknown(s.sid, "CH-01", "CM-0101"))
        net.run()
    assert len(frames(net, "HS1", src="CM-0101", dst="CH-01")) - hs1_before == 1
    assert len(events(net, "KEY_ROTATED", t0)) == 2  # one rekey, seen by both sides
    net.send_reading("CM-0101", "still works")
    net.run()
    assert [r["value"] for r in net.readings()] == ["still works"]


def test_fifty_forged_session_unknown_in_a_burst_cost_one_rekey() -> None:
    """All 50 at once: still one rekey. The burst occupies the bus (one frame per step network-wide),
    so that handshake may time out and be retried, but only within its own retry budget."""
    net = onboarded("small")
    cm = net.device("CM-0101")
    s = cm.current_session("CH-01", m.CM_CH)
    t0 = mark(net)
    hs1_before = len(frames(net, "HS1", src="CM-0101", dst="CH-01"))
    for _ in range(50):
        inject(net, "CH-01", "CM-0101", m.encode_session_unknown(s.sid, "CH-01", "CM-0101"))
    net.run()
    assert 1 <= len(frames(net, "HS1", src="CM-0101", dst="CH-01")) - hs1_before <= 1 + net.cfg.max_retries
    assert len(events(net, "KEY_ROTATED", t0)) == 2
    t1 = mark(net)
    for i in range(50):  # sids the CM never had: rejected, no handshake at all
        inject(net, "CH-01", "CM-0101", m.encode_session_unknown(bytes([i]) * 16, "CH-01", "CM-0101"))
    net.run()
    assert len(events(net, "UNKNOWN_SESSION", t1)) == 50 and not events(net, "KEY_ROTATED", t1)
    assert not frames(net, "HS1", src="CM-0101")[hs1_before + 1 + net.cfg.max_retries:]


# -- the largest custom topology ----------------------------------------------------------------------

def test_largest_custom_topology_5x8() -> None:
    net = en.build("toy", "custom-5x8", seed=SEED)
    assert len(net.scheduler.devices) == 1 + 5 + 5 * 8
    net.onboard()
    assert all(d.status == "active" for d in net.scheduler.devices.values())
    assert len(events(net, "HANDSHAKE_OK")) == 5 + 40 + 40
    for cm in net.cms():
        net.send_reading(cm.identity, f"from {cm.identity}")
    net.run()
    got = {(r["device"], r["value"]) for r in net.readings()}
    assert got == {(cm.identity, f"from {cm.identity}") for cm in net.cms()}
    vias = {e.peer: e.details["via"] for e in events(net, "DATA_ACCEPTED")}
    assert all(vias[cm.identity] == cm.designated for cm in net.cms())
