"""M4-T7: revocation, rekey, reprovisioning -- V-LIFE-01..04, V-CAP-01, V-CAP-02 (L5)."""

from __future__ import annotations

import pytest

from maka import codec
from maka.enhanced import messages as m
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


def test_v_life_03_missed_notice_window_closes_on_rekey() -> None:
    net = onboarded("small")
    net.scheduler.bus.add_interceptor(adversary.Drop(adversary.label_is("REVOKE_NOTICE")))
    net.revoke("CM-0102")
    net.run()
    ch = net.device("CH-01")
    assert "CM-0102" in ch.grant  # stale: the CH still accepts the revoked member
    t0 = mark(net)
    net.rekey("CM-0102", "CH-01")
    net.run()
    assert any(e.type == "HANDSHAKE_OK" and e.device == "CH-01" for e in net.scheduler.events[t0:])
    net.rekey("CH-01")  # CH-BS rekey refreshes the grant (§4.6.7)
    net.run()
    assert "CM-0102" not in ch.grant
    t1 = mark(net)
    net.rekey("CM-0102", "CH-01")
    net.run()
    at_ch = [e.type for e in net.scheduler.events[t1:] if e.device == "CH-01"]
    assert set(at_ch) == {"UNAUTHORISED_PEER"} and len(at_ch) == 1 + 3  # first try + 3 retries


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
    assert any(e.type == "HANDSHAKE_OK" and e.device == "CM-0101" for e in net.scheduler.events[t0:])
    # ... but not to CM-0102, whose PSK with the CH the attacker lacks (V-ADV-10)
    assert codec.enc_point(ch.g)  # keep the curve objects referenced for readers
