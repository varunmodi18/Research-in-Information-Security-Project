"""Promotion of a member to cluster head (docs/RECOVERY.md, IA-20, E-14)."""

from __future__ import annotations

from typing import cast

import pytest

from maka.enhanced import network as en
from maka.enhanced.lifecycle import EnhancedCH, EnhancedCM
from maka.runtime import adversary
from maka.runtime.bus import Frame

SEED = 20260927


def _onboarded(topology: str = "small") -> en.EnhancedNetwork:
    net = en.build("toy", topology, seed=SEED)
    net.onboard()
    for cm in net.cms():
        net.send_reading(cm.identity, "before")
    net.run()
    return net


def _members(net: en.EnhancedNetwork, cluster: str) -> list[str]:
    return sorted(cm.identity for cm in net.cms() if net.bs().registry[cm.identity].cluster == cluster)


@pytest.mark.parametrize("topology", ["small", "net"])
def test_promoted_member_becomes_ch_and_members_recover(topology: str) -> None:
    net = _onboarded(topology)
    epoch = net.bs().epoch
    net.promote("CH-01", "CM-0102")
    net.run()
    bs, ch = net.bs(), net.device("CM-0102")
    assert isinstance(ch, EnhancedCH) and ch.status == "active"
    assert bs.registry["CM-0102"].role == "CH" and bs.cluster_ch["CH-01"] == "CM-0102"
    assert bs.registry["CH-01"].status == "revoked" and net.device("CH-01").status == "revoked"
    assert bs.epoch > epoch  # revocation and designation each advance the registry epoch
    assert next(e for e in net.scheduler.events if e.type == "CH_PROMOTED").details["replaced"] == "CH-01"
    members = _members(net, "CH-01")
    assert members == ["CM-0101", "CM-0103"]
    for m in members:
        cm = cast(EnhancedCM, net.device(m))
        assert cm.status == "active" and cm.designated == "CM-0102" and cm.relay_ch == "CM-0102"
        assert cm.current_session("CM-0102", "CM-CH") is not None
    # readings flow through the new cluster head
    mark = len(net.scheduler.events)
    for m in members:
        net.send_reading(m, "after")
    net.run()
    accepted = [e for e in net.scheduler.events[mark:] if e.type == "DATA_ACCEPTED"]
    assert sorted(e.peer for e in accepted) == members and {e.details["via"] for e in accepted} == {"CM-0102"}
    # other clusters are untouched
    if topology == "net":
        assert all(net.device(ch_id).status == "active" for ch_id in ("CH-02", "CH-03"))


def test_k_stays_at_the_bs_and_no_session_keys_remain_for_the_old_ch() -> None:
    net = _onboarded()
    old_ch_sessions = {d.identity: [s for s in d.sessions.values() if s.peer == "CH-01"]
                       for d in net.scheduler.devices.values() if d.identity != "CH-01"}  # type: ignore[attr-defined]
    promoted_cm_sessions = list(cast(EnhancedCM, net.device("CM-0102")).sessions.values())
    net.promote("CH-01", "CM-0102")
    net.run()
    assert [i for i, d in net.scheduler.devices.items() if d.keystore.has("k")] == ["BS-01"]
    for ident, sessions in old_ch_sessions.items():
        dev = net.scheduler.devices[ident]
        assert not dev.keystore.has("psk:CH-01"), ident
        for s in sessions:
            for kind in ("send", "recv", "hop"):
                assert not dev.keystore.has(s.key(kind)), (ident, s.sid_hex, kind)
        live = [s for s in getattr(dev, "sessions", {}).values() if s.peer == "CH-01" and s.state == "ESTABLISHED"]
        assert live == [], ident
    # the promoted node keeps only Pr and new CH-role material: its CM-role session keys are gone
    ks = net.device("CM-0102").keystore
    assert ks.has("pr")
    for s in promoted_cm_sessions:
        assert not any(ks.has(s.key(kind)) for kind in ("send", "recv", "hop")), s.sid_hex


@pytest.mark.parametrize(("cluster", "member", "why"), [
    ("CH-01", "CM-0201", "foreign"),     # a member of another cluster
    ("CH-01", "CH-02", "not a member"),  # another cluster head
    ("CH-01", "BS-01", "not a member"),
    ("CH-09", "CM-0101", "unknown cluster"),
])
def test_only_a_member_of_the_same_cluster_can_be_promoted(cluster: str, member: str, why: str) -> None:
    net = _onboarded("net")
    before = (net.bs().epoch, {k: (v.role, v.status) for k, v in net.bs().registry.items()})
    with pytest.raises(ValueError):
        net.promote(cluster, member)
    assert (net.bs().epoch, {k: (v.role, v.status) for k, v in net.bs().registry.items()}) == before, why
    assert net.device("CH-01").status == "active"


def test_a_revoked_or_inactive_member_cannot_be_promoted() -> None:
    net = _onboarded()
    net.revoke("CM-0103")
    net.run()
    with pytest.raises(ValueError):
        net.promote("CH-01", "CM-0103")
    # the BS refuses on its own too: an unauthenticated member (no CM-BS session) is not promoted
    net.bs().drop_peer("CM-0101")
    epoch = net.bs().epoch
    with pytest.raises(ValueError, match="refused"):
        net.promote("CH-01", "CM-0101")
    assert net.bs().epoch == epoch and net.bs().registry["CM-0101"].role == "CM"
    assert any(e.type == "UNAUTHORISED_PEER" and e.peer == "CM-0101" for e in net.scheduler.events)


def test_the_old_ch_is_refused_afterwards() -> None:
    net = _onboarded()
    rec = adversary.Record(lambda f: f.label == "DATA_BATCH" and f.src == "CH-01")
    net.scheduler.bus.add_interceptor(rec)
    net.send_reading("CM-0101", "recorded")
    net.run()
    old_batch = rec.frames[-1]
    net.promote("CH-01", "CM-0102")
    net.run()
    mark = len(net.scheduler.events)
    # its handshake with the BS is refused at the ID check
    with net.context():
        net.scheduler.command("CH-01", "start_onboarding")
    net.run()
    refused = [e for e in net.scheduler.events[mark:] if e.device == "BS-01" and e.peer == "CH-01"]
    assert refused and all(e.type == "UNAUTHORISED_PEER" for e in refused)
    # a batch sealed under its old CH-BS session is rejected: the BS destroyed that session
    with net.context():
        frame = net.scheduler.bus.inject(Frame("CH-01", "BS-01", "DATA_BATCH", old_batch.payload),
                                         net.scheduler.step_no)
    net.run()
    linked = [e.type for e in net.scheduler.events if e.frame_id == frame.frame_id and e.device == "BS-01"]
    assert linked == ["UNKNOWN_SESSION"]
