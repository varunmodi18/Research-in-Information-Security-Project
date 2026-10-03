"""M4-T3/T4: PSK and AKE -- V-UNIT-10, V-POS-01, V-POS-03, V-ADV-01..07, 11, 12, 14, V-DOS-01..02."""

from __future__ import annotations

import pytest

from maka import codec
from maka.enhanced import ake
from maka.enhanced import messages as m
from maka.enhanced import network as en
from maka.enhanced import states as st
from maka.lab import attacker
from maka.runtime import adversary
from maka.runtime.bus import Frame

from .util import SEED, adversary_rng, events, frames, inject, mark, onboarded, session_keys


def test_v_unit_10_psk_symmetry_and_distinctness() -> None:
    net = onboarded("small")
    cm, ch, bs = net.device("CM-0101"), net.device("CH-01"), net.bs()
    assert cm.psk("CH-01") == ch.psk("CM-0101")
    assert cm.psk("CH-01") != net.device("CM-0102").psk("CH-01")
    assert cm.psk("CH-01") != cm.psk("BS-01")
    k = codec.dec_scalar(bs.curve, bs.keystore.get("k"))
    assert ake.psk_with_master_key(bs.curve, k, "CM-0101", "CH-01") == cm.psk("CH-01")


def test_v_pos_01_cm_ch_ake_keys() -> None:
    net = onboarded("paper")
    cm_send, cm_recv = session_keys(net, "CM-0101", "CH-01", m.CM_CH)
    ch_send, ch_recv = session_keys(net, "CH-01", "CM-0101", m.CM_CH)
    assert cm_send == ch_recv and cm_recv == ch_send and cm_send != cm_recv
    for ident, peer in (("CM-0101", "CH-01"), ("CH-01", "CM-0101")):
        assert net.device(ident).current_session(peer, m.CM_CH).state == st.ESTABLISHED


def test_v_pos_03_consecutive_akes_give_different_keys() -> None:
    net = onboarded("paper")
    first = session_keys(net, "CM-0101", "CH-01", m.CM_CH)
    net.rekey("CM-0101", "CH-01")
    net.run()
    second = session_keys(net, "CM-0101", "CH-01", m.CM_CH)
    assert first[0] != second[0] and first[1] != second[1]
    assert session_keys(net, "CH-01", "CM-0101", m.CM_CH) == (second[1], second[0])


def test_ephemerals_destroyed_after_handshake() -> None:
    net = onboarded("small")
    for d in net.scheduler.devices.values():
        assert not [n for n in d.keystore.names() if n.startswith(("eph:", "hs:"))], d.identity


# -- adversarial -----------------------------------------------------------------------------------

def test_v_adv_01_replayed_hs1_is_rejected() -> None:
    net = en.build("toy", "paper", seed=SEED)
    rec = adversary.Record(adversary.label_is("HS1"))
    net.scheduler.bus.add_interceptor(rec)
    net.onboard()
    hs1 = next(f for f in rec.frames if f.src == "CM-0101" and f.dst == "CH-01")
    t0 = mark(net)
    inject(net, "CM-0101", "CH-01", hs1.payload)
    net.run()
    assert [e.type for e in net.scheduler.events[t0:]] == ["REPLAY_REJECTED"]
    # same HS1 under a fresh sid: a new pending handshake that only times out
    patched = m.encode_hs1(b"\x99" * 16, "CM-0101", "CH-01", m.CM_CH, b"\x00" * 32, m.decode_hs1(hs1.payload).x_raw)
    t1 = mark(net)
    inject(net, "CM-0101", "CH-01", patched)
    net.run()
    types = [e.type for e in net.scheduler.events[t1:]]
    assert "UNKNOWN_SESSION" in types and "TIMEOUT" in types and "HANDSHAKE_OK" not in types


@pytest.mark.parametrize("label", ["HS2", "HS3"])
def test_v_adv_02_replayed_hs2_hs3_unknown_session(label: str) -> None:
    net = onboarded("paper")
    captured = frames(net, label, src="CH-01" if label == "HS2" else "CM-0101")[0]
    t0 = mark(net)
    inject(net, captured.src, captured.dst, captured.payload)
    net.run()
    assert [e.type for e in net.scheduler.events[t0:]] == ["UNKNOWN_SESSION"]


def is_cm_ch(label: str, f: Frame) -> bool:
    """A CM-0101 <-> CH-01 handshake frame of purpose CM-CH (not a forwarded CM-BS one)."""
    if f.label != label:
        return False
    if label == "HS1":
        return m.decode_hs1(f.payload).purpose == m.CM_CH and f.dst == "CH-01"
    if label == "HS2":
        return m.decode_hs2(f.payload).id_r == "CH-01"
    return f.src == "CM-0101" and f.dst == "CH-01"


def _first_cm_ch(label: str):  # type: ignore[no-untyped-def]
    return lambda f: is_cm_ch(label, f)


def test_v_adv_03_tampered_x() -> None:
    net = en.build("toy", "paper", seed=SEED)
    net.scheduler.bus.add_interceptor(adversary.Modify(_first_cm_ch("HS1"), adversary.flip_byte(-1), limit=1))
    net.onboard()
    fails = [e for e in net.scheduler.events if e.type in ("BAD_POINT", "BAD_TAG")]
    assert fails and fails[0].device in ("CH-01", "CM-0101")
    assert net.device("CM-0101").status == "active"  # the retry succeeds


def test_v_adv_04_tampered_tag_r() -> None:
    net = en.build("toy", "paper", seed=SEED)
    net.scheduler.bus.add_interceptor(adversary.Modify(_first_cm_ch("HS2"), adversary.flip_byte(-1), limit=1))
    net.onboard()
    bad = events(net, "BAD_TAG")
    assert bad and bad[0].device == "CM-0101" and bad[0].details["purpose"] == m.CM_CH
    assert any(e.type == "HANDSHAKE_FAIL" and e.device == "CM-0101" for e in net.scheduler.events)


def test_v_adv_05_swapped_purpose() -> None:
    net = en.build("toy", "paper", seed=SEED)

    def swap(payload: bytes) -> bytes:
        return payload.replace(b"CM-CH", b"CM-BS", 1)

    net.scheduler.bus.add_interceptor(adversary.Modify(_first_cm_ch("HS1"), swap, limit=1))
    net.onboard()
    assert events(net, "BAD_PURPOSE")[0].device == "CH-01"


def test_v_adv_06_wrong_recipient() -> None:
    net = onboarded("net")
    hs1 = frames(net, "HS1", src="CM-0101", dst="CH-01")[0]
    t0 = mark(net)
    inject(net, "CM-0101", "CH-02", hs1.payload)
    net.run()
    assert [(e.type, e.device) for e in net.scheduler.events[t0:]] == [("WRONG_RECIPIENT", "CH-02")]


def test_v_adv_07_dropped_hs3_then_recovery() -> None:
    net = en.build("toy", "paper", seed=SEED)
    net.scheduler.bus.add_interceptor(adversary.Drop(_first_cm_ch("HS3"), limit=1))
    net.onboard()
    assert any(e.type == "TIMEOUT" and e.device == "CH-01" for e in net.scheduler.events)
    assert net.device("CH-01").current_session("CM-0101", m.CM_CH) is None
    t0 = mark(net)
    net.send_reading("CM-0101", "lost")
    net.run()
    assert [e.type for e in events(net, "UNKNOWN_SESSION", t0)] == ["UNKNOWN_SESSION"]
    assert events(net, "HANDSHAKE_OK", t0)  # SESSION_UNKNOWN made the CM re-handshake
    t1 = mark(net)
    net.send_reading("CM-0101", "after-retry")
    net.run()
    assert [e.details["seq"] for e in events(net, "DATA_ACCEPTED", t1)] == [2]


def test_v_adv_11_fake_bs_fails_at_ch() -> None:
    net = en.build("toy", "paper", seed=SEED)
    rec = adversary.Record(adversary.label_is("HS1"))
    net.scheduler.bus.add_interceptor(rec)  # records before the drop below
    net.scheduler.bus.add_interceptor(adversary.Drop(lambda f: f.label == "HS1" and f.dst == "BS-01", limit=1))
    net.start_onboarding()
    hs1 = rec.frames[0].payload
    ch = net.device("CH-01")
    forged = attacker.forge_hs2(ch.curve, ch.g, adversary_rng(), hs1, psk_guess=b"\x00" * 32)
    inject(net, "BS-01", "CH-01", forged)
    net.step(1)
    assert net.scheduler.log[-1].reason == "BAD_TAG" and net.scheduler.log[-1].to == "CH-01"


def test_v_adv_12_forward_secrecy() -> None:
    net = en.build("toy", "paper", seed=SEED)
    rec = adversary.Record(lambda f: is_cm_ch("HS1", f) or is_cm_ch("HS2", f))
    net.scheduler.bus.add_interceptor(rec)
    net.onboard()
    hs1, hs2 = rec.frames[0].payload, rec.frames[1].payload
    assert rec.frames[0].label == "HS1" and rec.frames[1].label == "HS2"
    net.rekey("CM-0101", "CH-01")  # the recorded session ends (superseded, keys destroyed)
    net.run()
    stolen = net.device("CM-0101").keystore.snapshot()  # Pr and every PSK, after the fact
    psk = stolen["psk:CH-01"]
    cm = net.device("CM-0101")
    x_pt = codec.dec_point(cm.curve, m.decode_hs1(hs1).x_raw)
    y_pt = codec.dec_point(cm.curve, m.decode_hs2(hs2).y_raw)
    pr = codec.load_point(cm.curve, stolen["pr"])
    candidates = [x_pt, y_pt, x_pt + y_pt, pr, pr + x_pt, codec.dec_scalar(cm.curve, psk[:3].rjust(3, b"\x00")) * y_pt]
    assert not attacker.try_derive_session(cm.curve, hs1, hs2, psk, candidates)
    assert not [n for n in stolen if n.startswith(("eph:", "hs:"))]


def test_v_adv_14_cross_mode_and_cross_purpose() -> None:
    net = onboarded("paper")
    t0 = mark(net)
    original_mode_bytes = codec.encode_auth(net.device("CH-01").g, net.device("CH-01").g, b"\x00" * 20)
    inject(net, "CM-0101", "CH-01", original_mode_bytes)
    net.run()
    assert [e.type for e in net.scheduler.events[t0:]] == ["DECODE_ERROR"]

    hs2_cm_bs = frames(net, "HS2", src="CH-01", dst="CM-0101")  # relayed BS->CM HS2 (purpose CM-BS)
    cm_bs_hs2 = next(f.payload for f in hs2_cm_bs if m.decode_hs2(f.payload).id_r == "BS-01")
    rec = adversary.Record(lambda f: is_cm_ch("HS1", f))
    net.scheduler.bus.add_interceptor(rec)
    net.scheduler.bus.add_interceptor(adversary.Drop(lambda f: is_cm_ch("HS2", f), limit=1))
    net.rekey("CM-0101", "CH-01")
    net.step(2)
    pending_sid = m.decode_hs1(rec.frames[-1].payload).sid
    old = m.decode_hs2(cm_bs_hs2)
    spliced = m.hs2_body(pending_sid, "CH-01", "CM-0101", old.n_r, old.y_raw) + old.tag
    t1 = mark(net)
    inject(net, "CH-01", "CM-0101", spliced)
    net.step(1)
    assert net.scheduler.log[-1].reason == "BAD_TAG"
    assert not events(net, "KEY_CONFIRMED", t1)


def test_v_dos_01_unprovisioned_flood_costs_no_public_key_ops() -> None:
    net = onboarded("paper")
    ch = net.device("CH-01")
    before = net.ledger.total("CH-01")
    t0 = mark(net)
    r = adversary_rng()
    for i in range(1000):
        hs1 = attacker.forge_hs1(ch.curve, ch.g, r, f"EVIL-{i}", "CH-01", m.CM_CH).payload
        inject(net, f"EVIL-{i}", "CH-01", hs1)
    net.run()
    after = net.ledger.total("CH-01")
    for op in ("T_P", "T_SM", "T_SM_val", "T_HKDF"):
        assert after.get(op, 0) == before.get(op, 0), op
    assert len(events(net, "UNAUTHORISED_PEER", t0)) == 1000


def test_v_dos_02_pending_limits() -> None:
    net = onboarded("small")
    ch = net.device("CH-01")
    t0 = mark(net)
    r = adversary_rng()
    peak = {"per_id": 0, "total": 0}

    def watch(_result):  # type: ignore[no-untyped-def]
        peak["per_id"] = max(peak["per_id"], ch._pending_responder("CM-0101"))
        peak["total"] = max(peak["total"], ch._pending_responder())

    net.scheduler.hooks.append(watch)
    for _ in range(50):
        inject(net, "CM-0101", "CH-01", attacker.forge_hs1(ch.curve, ch.g, r, "CM-0101", "CH-01", m.CM_CH).payload)
    net.run()
    assert peak["per_id"] <= 1 and peak["total"] <= ch.cfg.max_pending
    assert len(events(net, "RATE_LIMITED", t0)) == 49


def test_hs1_on_unknown_frame_type_is_decode_error() -> None:
    net = onboarded("paper")
    t0 = mark(net)
    net.scheduler.bus.inject(Frame("CM-0101", "CH-01", "X", b"\x02\x7f"), net.scheduler.step_no)
    net.run()
    assert [e.type for e in net.scheduler.events[t0:]] == ["DECODE_ERROR"]
