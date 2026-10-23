"""Feature extraction on a hand-built frame/event log (docs/BEHAVIOUR.md §Features)."""

from __future__ import annotations

from maka.behaviour import features as ft
from maka.enhanced import messages as em
from maka.runtime.bus import Frame
from maka.runtime.events import SecurityEvent
from maka.runtime.scheduler import StepResult

ROLES = {"BS-01": "BS", "CH-01": "CH", "CM-0101": "CM", "CM-0102": "CM"}


def _hs1(initiator: str, responder: str, purpose: str) -> bytes:
    return em.encode_hs1(b"\x01" * em.SID_BYTES, initiator, responder, purpose, b"\x02" * em.NONCE_BYTES, b"\x03" * 8)


def _frame(src: str, dst: str, label: str, payload: bytes, step: int) -> Frame:
    return Frame(src, dst, label, payload, step=step)


def _ev(etype: str, device: str, step: int, peer: str | None = None, sid: str | None = None,
        **details: object) -> SecurityEvent:
    return SecurityEvent(type=etype, device=device, step=step, peer=peer, sid=sid, details=dict(details))


def _log() -> tuple[list[StepResult], list[SecurityEvent]]:
    relayed = em.encode_relay("BS-01", _hs1("CM-0101", "BS-01", em.CM_BS))
    log = [
        # window 0 (steps 0-9): CM-0101 starts a CM-BS handshake through its CH and a direct CM-CH one
        StepResult(step=1, kind="command", emitted=[_frame("CM-0101", "CH-01", "RELAY:HS1", relayed, 1)]),
        StepResult(step=2, kind="deliver", to="CH-01", frame=_frame("CM-0101", "CH-01", "RELAY:HS1", relayed, 1),
                   # the CH forwards the HS1: a frame it sends, but not a handshake it initiated
                   emitted=[_frame("CH-01", "BS-01", "HS1", _hs1("CM-0101", "BS-01", em.CM_BS), 2)]),
        StepResult(step=3, kind="command", emitted=[_frame("CM-0101", "CH-01", "HS1", _hs1("CM-0101", "CH-01", em.CM_CH), 3)]),
        StepResult(step=4, kind="deliver", to="CH-01", frame=_frame("CM-0101", "CH-01", "HS1", b"", 3)),
        # window 1 (steps 10-19): a reading from CM-0102, a corrupt HS1 (not counted as initiated)
        StepResult(step=11, kind="command", emitted=[_frame("CM-0102", "CH-01", "DATA_CM", b"x", 11),
                                                     _frame("CM-0102", "CH-01", "HS1", b"\x00garbage", 11)]),
        StepResult(step=12, kind="deliver", to="CH-01", frame=_frame("CM-0102", "CH-01", "DATA_CM", b"x", 11)),
        StepResult(step=13, kind="idle"),
    ]
    events = [
        _ev("KEY_CONFIRMED", "CM-0101", 5, peer="CH-01", sid="s1", purpose="CM-CH"),
        _ev("HANDSHAKE_OK", "CH-01", 5, peer="CM-0101", sid="s1", purpose="CM-CH"),
        _ev("SESSION_SUPERSEDED", "CM-0101", 5, peer="CH-01", sid="s0", purpose="CM-CH", by="s1"),
        _ev("KEY_ROTATED", "CM-0101", 5, peer="CH-01", sid="s1", purpose="CM-CH"),
        _ev("SESSION_SUPERSEDED", "CH-01", 6, peer="CM-0101", sid="s0"),  # data on a superseded session
        _ev("BAD_TAG", "CH-01", 6, peer="CM-0102", reason="hop MAC"),
        _ev("DATA_ACCEPTED", "BS-01", 7, peer="CM-0101", sid="a", seq=1, via="CH-01"),
        _ev("DATA_ACCEPTED", "BS-01", 14, peer="CM-0101", sid="a", seq=4, via="CH-01"),  # 2 and 3 missing
        _ev("DATA_ACCEPTED", "BS-01", 15, peer="CM-0102", sid="b", seq=2, via="CH-01"),  # 1 missing
        _ev("DATA_ACCEPTED", "BS-01", 16, peer="CM-0101", sid="c", seq=1, via="CH-01"),  # new session: no gap
        _ev("BATCH_SENT", "CH-01", 13, peer="BS-01", items=3),
        _ev("DATA_ACCEPTED", "CH-01", 16, peer="CM-0101", seq=9),  # not at the BS: ignored
        _ev("BATCH_SENT", "CH-01", 25, peer="BS-01", items=5),  # outside the two windows
    ]
    return log, events


def _rows() -> dict[tuple[str, int], dict[str, object]]:
    log, events = _log()
    rows = ft.extract(log, events, ROLES, start=0, n_windows=2, window=10)
    return {(r["device"], r["window"]): r for r in rows}


def test_rows_cover_scored_devices_and_windows_only() -> None:
    rows = _rows()
    assert set(rows) == {(d, k) for d in ("CH-01", "CM-0101", "CM-0102") for k in (0, 1)}
    assert all(set(r) == {"device", "role", "window", *ft.FEATURES} for r in rows.values())


def test_frame_features() -> None:
    rows = _rows()
    assert rows[("CM-0101", 0)]["frames_sent"] == 2 and rows[("CM-0101", 0)]["handshakes_initiated"] == 2
    assert rows[("CH-01", 0)]["frames_sent"] == 1 and rows[("CH-01", 0)]["handshakes_initiated"] == 0
    assert rows[("CH-01", 0)]["frames_received"] == 2
    assert rows[("CM-0102", 1)]["frames_sent"] == 2 and rows[("CM-0102", 1)]["handshakes_initiated"] == 0
    assert rows[("CH-01", 1)]["frames_received"] == 1


def test_event_features() -> None:
    rows = _rows()
    cm1, ch0, ch1 = rows[("CM-0101", 0)], rows[("CH-01", 0)], rows[("CH-01", 1)]
    assert cm1["handshakes_completed"] == 1 and ch0["handshakes_completed"] == 1
    assert cm1["rekeys"] == 1 and cm1["rejections"] == 0  # rotation is not a rejection
    assert ch0["rejections"] == 2  # BAD_TAG and data on a superseded session
    assert cm1["readings_accepted_at_bs"] == 1 and rows[("CM-0101", 1)]["readings_accepted_at_bs"] == 2
    assert rows[("CM-0101", 1)]["seq_gaps_at_bs"] == 2 and rows[("CM-0102", 1)]["seq_gaps_at_bs"] == 1
    assert ch1["seq_gaps_at_bs"] == 3  # attributed to the forwarding CH as well
    assert ch1["batch_items_forwarded"] == 3 and ch0["batch_items_forwarded"] == 0


def test_extract_is_a_pure_function_of_the_log() -> None:
    log, events = _log()
    a = ft.extract(log, events, ROLES, start=0, n_windows=2, window=10)
    b = ft.extract(log, events, ROLES, start=0, n_windows=2, window=10)
    assert a == b
    shifted = ft.extract(log, events, ROLES, start=10, n_windows=1, window=10)
    assert next(r for r in shifted if r["device"] == "CH-01")["batch_items_forwarded"] == 3
