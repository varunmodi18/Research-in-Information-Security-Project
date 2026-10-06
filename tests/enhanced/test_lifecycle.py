"""M4-T7: revocation, rekey, reprovisioning -- V-LIFE-01..04, V-CAP-01, V-CAP-02 (L5)."""

from __future__ import annotations

import pytest

from maka.enhanced import messages as m
from maka.enhanced import network as en
from maka.enhanced.device import SEQ_LIMIT
from maka.enhanced.provisioning import MasterKeyLeak
from maka.lab import attacker
from maka.runtime import adversary
from maka.runtime.keystore import SecretClass

from .util import adversary_rng, events, inject, mark, onboarded


def test_v_life_01_revoke_cm() -> None:
    net = onboarded("small")
    t0 = mark(net)
    net.revoke("CM-0102")
    bs = net.bs()
    assert all(s.peer != "CM-0102" or s.state != "ESTABLISHED" for s in bs.sessions.values())
    assert not bs.keystore.has("psk:CM-0102")
    net.step(1)  # one delivery: the REVOKE_NOTICE
    ch = net.device("CH-01")
    assert all(s.peer != "CM-0102" or s.state != "ESTABLISHED" for s in ch.sessions.values())
    assert "CM-0102" not in ch.grant and not ch.keystore.has("psk:CM-0102")
    net.run()
    assert events(net, "REVOKE_ACKED", t0)
    assert net.device("CM-0102").status == "revoked"
    t1 = mark(net)
    cm = net.device("CM-0102")
    inject(net, "CM-0102", "BS-01", attacker.forge_hs1(cm.curve, cm.g, adversary_rng(), "CM-0102", "BS-01", m.CM_BS).payload)
    net.run()
    assert [e.type for e in net.scheduler.events[t1:]] == ["UNAUTHORISED_PEER"]
    t2 = mark(net)
    net.send_reading("CM-0102", "still here")
    net.run()
    assert [e.type for e in net.scheduler.events[t2:]] == ["UNAUTHENTICATED_PEER"]


def test_v_life_02_revoke_ch_and_designate_replacement() -> None:
    net = onboarded("small")
    net.revoke("CH-01")
    net.run()
    assert net.bs().cluster_ch["CH-01"] is None
    net.reprovision("CH-01", "CH-01-r1")
    net.run()
    for cm in net.cms():
        assert cm.designated == "CH-01-r1" and cm.status == "active", cm.identity
    t0 = mark(net)
    for cm in net.cms():
        net.send_reading(cm.identity, "via new CH")
    net.run()
    assert {e.details["via"] for e in events(net, "DATA_ACCEPTED", t0)} == {"CH-01-r1"}
    with pytest.raises(ValueError):
        net.provision_device("CH-01", "CH", "CH-01")  # a revoked identity is never reused


def test_v_life_03_missed_notice_window_closes_on_grant_refresh() -> None:
    """D3: a CH that missed REVOKE_NOTICE keeps the revoked member only until its periodic grant
    refresh (MAKA_GRANT_REFRESH_STEPS, default 50) -- no rekey of anything is needed."""
    net = onboarded("small")
    assert net.cfg.grant_refresh_steps == 50
    net.scheduler.bus.add_interceptor(adversary.Drop(adversary.label_is("REVOKE_NOTICE")))
    net.revoke("CM-0102")
    net.run()
    ch = net.device("CH-01")
    assert "CM-0102" in ch.grant  # stale: the CH still accepts the revoked member
    t0 = mark(net)
    net.rekey("CM-0102", "CH-01")
    net.run()
    assert any(e.type == "HANDSHAKE_OK" and e.device == "CH-01" for e in net.scheduler.events[t0:])
    last_grant = max(r.step for r in net.scheduler.log if r.frame is not None and r.frame.label == "CLUSTER_GRANT")
    net.step(last_grant + 50 - net.scheduler.step_no - 1)
    assert "CM-0102" in ch.grant  # the window is open until the refresh fires
    t1 = mark(net)
    net.step(10)  # refresh timer fires, CLUSTER_CLAIM -> CLUSTER_GRANT over the sealed CH-BS session
    assert "CM-0102" not in ch.grant
    assert not [e for e in net.scheduler.events[t1:] if e.type in ("HANDSHAKE_OK", "KEY_CONFIRMED")]  # no rekey
    assert [e.details["granted"] for e in events(net, "GRANT_ISSUED", t1)] == [2]
    t2 = mark(net)
    net.rekey("CM-0102", "CH-01")
    net.run()
    at_ch = [e.type for e in net.scheduler.events[t2:] if e.device == "CH-01"]
    assert set(at_ch) == {"UNAUTHORISED_PEER"} and len(at_ch) == 1 + 3  # first try + 3 retries


def test_d4_session_epoch_is_the_registry_epoch_on_both_sides() -> None:
    net = onboarded("small")
    bs = net.bs()
    net.revoke("CM-0103")  # registry epoch 0 -> 1; the notice tells CH-01
    net.run()
    assert bs.epoch == 1
    for peer, other in (("CH-01", "BS-01"), ("CM-0101", "BS-01"), ("CM-0101", "CH-01")):
        net.rekey(peer, other)
        net.run()
    pairs = [("CH-01", "BS-01", m.CH_BS), ("CM-0101", "BS-01", m.CM_BS), ("CM-0101", "CH-01", m.CM_CH)]
    for a, b, purpose in pairs:
        sa, sb = net.device(a).current_session(b, purpose), net.device(b).current_session(a, purpose)
        assert sa.sid == sb.sid and sa.epoch == sb.epoch == 1, (a, b, sa.epoch, sb.epoch)
    # sessions established before the revocation keep the epoch they were established in
    assert net.device("CM-0102").current_session("CH-01", m.CM_CH).epoch == 0
    assert {r["epoch"] for r in net.session_infos() if r["state"] == "ESTABLISHED"} == {0, 1}


def test_d5_send_seq_bound_refuses_and_rekeys_initiator() -> None:
    net = onboarded("paper")
    cm = net.device("CM-0101")
    old = cm.current_session("BS-01", m.CM_BS)
    old.send_seq = SEQ_LIMIT - 2
    net.send_reading("CM-0101", "last allowed")  # seq 2^32 - 1
    net.run()
    t0 = mark(net)
    r = net.send_reading("CM-0101", "refused")
    assert r.verdict == "REJECT" and r.reason == "SEQ_EXHAUSTED"
    assert old.send_seq == SEQ_LIMIT - 1  # nothing was sealed under seq 2^32
    net.run()
    new = cm.current_session("BS-01", m.CM_BS)
    assert new.sid != old.sid and events(net, "KEY_ROTATED", t0)
    net.send_reading("CM-0101", "after rekey")
    net.run()
    assert [(x["value"], x["seq"]) for x in net.readings()] == [("last allowed", SEQ_LIMIT - 1), ("after rekey", 1)]


def test_d5_send_seq_bound_at_a_responder_asks_the_initiator_to_rekey() -> None:
    net = onboarded("small")
    bs = net.bs()
    old = bs.current_session("CH-01", m.CH_BS)
    old.send_seq = SEQ_LIMIT - 1
    t0 = mark(net)
    r = net.revoke("CM-0102")  # the BS must seal REVOKE_NOTICE to CH-01, as the CH-BS responder
    assert r.reason == "SEQ_EXHAUSTED" and events(net, "SEQ_EXHAUSTED", t0)[0].device == "BS-01"
    net.run()
    assert bs.current_session("CH-01", m.CH_BS).sid != old.sid  # CH-01 rekeyed on SESSION_UNKNOWN
    assert "CM-0102" not in net.device("CH-01").grant  # and its post-rekey grant dropped the member


def test_v_life_04_rekey_supersedes_and_rejects_in_flight_data() -> None:
    net = onboarded("paper")
    old = net.device("CM-0101").current_session("BS-01", m.CM_BS)
    net.scheduler.bus.add_interceptor(adversary.Delay(adversary.label_is("DATA_CM"), n=60, limit=1))
    t0 = mark(net)
    net.send_reading("CM-0101", "sent under the old keys")
    net.rekey("CM-0101", "BS-01")
    net.run()
    assert net.device("CM-0101").keystore.has(old.key("send")) is False
    assert events(net, "KEY_ROTATED", t0)
    rejected = [e for e in events(net, "SESSION_SUPERSEDED", t0)
                if e.device == "BS-01" and e.peer == "CM-0101" and e.sid == old.sid_hex and "by" not in e.details]
    assert len(rejected) == 1  # the in-flight reading, sealed under the superseded session
    assert not events(net, "DATA_ACCEPTED", t0)


def test_v_cap_01_invariant_hook_detects_master_key_on_a_device() -> None:
    net = onboarded("paper")
    assert net.bs().keystore.has("k")
    assert all(not d.keystore.has("k") for d in net.scheduler.devices.values() if d.identity != "BS-01")
    net.device("CM-0101").keystore.put("k", b"\x01", SecretClass.SECRET)
    with pytest.raises(MasterKeyLeak):
        net.send_reading("CM-0101", "x")  # the hook runs after every command and step


def test_v_cap_02_capture_of_one_cm() -> None:
    net = onboarded("small")
    stolen = net.device("CM-0101").keystore.snapshot()
    assert "k" not in stolen and "pr" in stolen  # C1: capture yields only this device's keys
    cm, ch = net.device("CM-0101"), net.device("CH-01")
    r = adversary_rng()

    def handshake_as(id_i: str, psk: bytes) -> bool:
        forged = attacker.forge_hs1(cm.curve, cm.g, r, id_i, "CH-01", m.CM_CH)
        rec = adversary.Record(lambda f: f.label == "HS2" and f.dst == id_i)
        net.scheduler.bus.add_interceptor(rec)
        net.scheduler.bus.add_interceptor(adversary.Drop(lambda f: f.label == "HS2" and f.dst == id_i, limit=1))
        inject(net, id_i, "CH-01", forged.payload)
        net.step(1)
        net.scheduler.bus.clear_interceptors()
        hs3 = attacker.finish_as_initiator(cm.curve, forged.payload, forged.x, rec.frames[-1].payload, psk)
        if hs3 is None:
            return False
        t0 = mark(net)
        inject(net, id_i, "CH-01", hs3)
        net.step(1)
        return any(e.type == "HANDSHAKE_OK" and e.device == "CH-01" and e.peer == id_i
                   for e in net.scheduler.events[t0:])

    assert handshake_as("CM-0101", stolen["psk:CH-01"])  # expected: the captured identity
    assert not handshake_as("CM-0102", stolen["psk:CH-01"])  # cannot become another member
    # KCI (accepted residual, §2.3): with CM-0101's keys, pose as the CH *to CM-0101*
    rec = adversary.Record(lambda f: f.label == "HS1" and f.src == "CM-0101" and f.dst == "CH-01")
    net.scheduler.bus.add_interceptor(rec)
    net.scheduler.bus.add_interceptor(adversary.Drop(lambda f: f.label == "HS1" and f.src == "CM-0101"))
    net.rekey("CM-0101", "CH-01")
    net.step(1)
    t0 = mark(net)
    inject(net, "CH-01", "CM-0101", attacker.forge_hs2(cm.curve, cm.g, r, rec.frames[-1].payload, stolen["psk:CH-01"]))
    net.step(1)
    assert any(e.type == "KEY_CONFIRMED" and e.device == "CM-0101" for e in net.scheduler.events[t0:])
    # ... but not to CM-0102, whose PSK with the CH the attacker lacks (V-ADV-10): every PSK taken
    # from CM-0101 is tried as CH-01's answer to CM-0102's handshake
    net.scheduler.bus.clear_interceptors()
    victim = adversary.Record(lambda f: f.label == "HS1" and f.src == "CM-0102" and f.dst == "CH-01")
    net.scheduler.bus.add_interceptor(victim)
    net.scheduler.bus.add_interceptor(adversary.Drop(lambda f: f.label == "HS1" and f.src == "CM-0102"))
    psks = {n: v for n, v in stolen.items() if n.startswith("psk:")}
    assert set(psks) == {"psk:CH-01", "psk:BS-01"}
    for name, psk in psks.items():
        net.rekey("CM-0102", "CH-01")
        net.step(1)
        forged = attacker.forge_hs2(cm.curve, cm.g, r, victim.frames[-1].payload, psk)
        t1 = mark(net)
        inject(net, "CH-01", "CM-0102", forged)
        delivered = [res for res in net.step(3) if res.frame is not None and res.frame.payload == forged]
        assert len(delivered) == 1 and delivered[0].reason == "BAD_TAG", name
        assert not [e for e in net.scheduler.events[t1:] if e.type == "KEY_CONFIRMED" and e.device == "CM-0102"]
    assert ch.current_session("CM-0102", m.CM_CH) is not None  # its genuine session is untouched


def test_d2_ch_revoked_members_await_redesignation_then_drop_the_old_ch() -> None:
    net = onboarded("small")
    cms = ("CM-0101", "CM-0102", "CM-0103")
    net.revoke("CH-01")
    net.run()
    # state 1: the members are not told; they keep their designation, sessions and PSK with CH-01
    for ident in cms:
        cm = net.device(ident)
        assert net.designation_state(ident) == en.CH_REVOKED and cm.designated == "CH-01"
        assert cm.keystore.has("psk:CH-01") and cm.current_session("CH-01", m.CM_CH) is not None
    t0 = mark(net)
    net.send_reading("CM-0101", "lost")
    net.run()
    assert net.undelivered_readings("CM-0101") == 1 and not events(net, "DATA_ACCEPTED", t0)
    # state 2: the replacement CH relays a new DESIGNATION; each member then destroys its sessions
    # and PSK with the revoked CH
    net.reprovision("CH-01", "CH-01-r1")
    net.run()
    for ident in cms:
        cm = net.device(ident)
        assert net.designation_state(ident) == "ok" and cm.designated == "CH-01-r1"
        assert not cm.keystore.has("psk:CH-01")
        assert {s.state for s in cm.sessions.values() if s.peer == "CH-01"} == {"CLOSED"}
        assert not [n for n in cm.keystore.names() if any(n.startswith(f"sess:{s.sid_hex}")
                                                         for s in cm.sessions.values() if s.peer == "CH-01")]
    t1 = mark(net)
    net.send_reading("CM-0101", "delivered")
    net.run()
    assert [e.details["via"] for e in events(net, "DATA_ACCEPTED", t1)] == ["CH-01-r1"]
    assert net.undelivered_readings("CM-0101") == 1  # the loss stays on record


def test_d5_hop_seq_bound_refuses_and_rekeys_the_cm_ch_session() -> None:
    net = onboarded("paper")
    cm = net.device("CM-0101")
    hop = cm.current_session("CH-01", m.CM_CH)
    hop.hop_seq = SEQ_LIMIT - 1
    t0 = mark(net)
    r = net.send_reading("CM-0101", "refused")
    assert r.reason == "SEQ_EXHAUSTED" and hop.hop_seq == SEQ_LIMIT - 1
    assert cm.current_session("BS-01", m.CM_BS).send_seq == 0  # refused before sealing anything
    net.run()
    assert cm.current_session("CH-01", m.CM_CH).sid != hop.sid and events(net, "KEY_ROTATED", t0)
    net.send_reading("CM-0101", "after rekey")
    net.run()
    assert [x["value"] for x in net.readings()] == ["after rekey"]
