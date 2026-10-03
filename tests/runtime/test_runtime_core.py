"""M2-T1..T3: scheduler, timers, bus, interceptors, keystore (V-RT-01..05)."""

from __future__ import annotations

import pytest

from maka import rng
from maka.runtime import adversary
from maka.runtime import events as ev
from maka.runtime.bus import BROADCAST, LAB, PRODUCT, Bus, Frame
from maka.runtime.device import Device
from maka.runtime.errors import AdversaryNotAllowed, StepLimitExceeded
from maka.runtime.keystore import Keystore, SecretClass
from maka.runtime.scheduler import Scheduler


class Echo(Device):
    """Records what it receives; replies 'pong' to 'ping'; a 'tick' timer re-arms itself."""

    def __init__(self, identity: str) -> None:
        super().__init__(identity, None, Keystore(identity), rng.Rng(seed=1).spawn(identity))
        self.received: list[tuple[int, str, bytes]] = []
        self.ticks: list[int] = []

    def handle(self, frame: Frame) -> list[Frame]:
        self.received.append((self.now, frame.label, frame.payload))
        self.check("label known", frame.label in ("ping", "pong", "data"))
        if frame.payload == b"bad":
            return self.reject("DECODE_ERROR", peer=frame.src)
        if frame.label == "ping":
            return [self.frame(frame.src, "pong", frame.payload)]
        return []

    def on_timer(self, name: str) -> list[Frame]:
        self.ticks.append(self.now)
        return []

    def start(self, peer: str, n: int) -> list[Frame]:
        return [self.frame(peer, "ping", bytes([i])) for i in range(n)]

    def arm(self, delay: int) -> list[Frame]:
        self.set_timer("tick", delay)
        return []

    def disarm(self) -> list[Frame]:
        self.cancel_timer("tick")
        return []


def _net(kind: str = LAB) -> tuple[Scheduler, Echo, Echo]:
    a, b = Echo("A"), Echo("B")
    return Scheduler(Bus(kind=kind), [a, b]), a, b


def test_v_rt_01_fifo_delivery() -> None:
    s, a, b = _net()
    s.command("A", "start", "B", 5)
    s.run_until_quiescent()
    assert [p for _, label, p in b.received if label == "ping"] == [bytes([i]) for i in range(5)]
    assert [p for _, label, p in a.received] == [bytes([i]) for i in range(5)]
    steps = [r.step for r in s.log if r.kind == "deliver"]
    assert steps == sorted(steps) and len(steps) == 10


def test_v_rt_02_timers_fire_at_their_step_and_can_be_cancelled() -> None:
    s, a, _ = _net()
    s.command("A", "arm", 4)
    s.run_until_quiescent()
    assert a.ticks == [4]
    s.command("A", "arm", 3)
    s.command("A", "disarm")
    s.run_until_quiescent()
    assert a.ticks == [4]


def test_v_rt_03_step_limit() -> None:
    s, _, _ = _net()
    s.command("A", "start", "B", 50)
    with pytest.raises(StepLimitExceeded):
        s.run_until_quiescent(max_steps=10)


def test_v_rt_04_same_seed_same_frame_log() -> None:
    def run() -> list[tuple[int, str, str, str, bytes]]:
        s, _, _ = _net()
        s.command("A", "start", "B", 4)
        s.command("B", "start", "A", 2)
        s.run_until_quiescent()
        return [(r.step, r.frame.src, r.frame.dst, r.frame.label, r.frame.payload)
                for r in s.log if r.frame is not None]
    assert run() == run()


def test_verdicts_checks_and_events_recorded() -> None:
    s, _a, _b = _net()
    s.bus.send(Frame("A", "B", "data", b"bad"), 0)
    r = s.step()
    assert r.verdict == ev.REJECT and r.reason == "DECODE_ERROR"
    assert r.checks == [ev.Check("label known", True)]
    assert r.events[0].type == "DECODE_ERROR" and r.events[0].frame_id == r.frame.frame_id


def test_broadcast_reaches_every_other_device_once() -> None:
    c = Echo("C")
    s, a, b = _net()
    s.add_device(c)
    s.bus.send(Frame("A", BROADCAST, "data", b"hello"), 0)
    s.run_until_quiescent()
    assert [x[2] for x in b.received] == [b"hello"] and [x[2] for x in c.received] == [b"hello"]
    assert a.received == []


# -- V-RT-05: every interceptor kind ------------------------------------------------

def test_v_rt_05_drop() -> None:
    s, _a, b = _net()
    drop = adversary.Drop(adversary.label_is("ping"), limit=2)
    s.bus.add_interceptor(drop)
    s.command("A", "start", "B", 3)
    s.run_until_quiescent()
    assert [p for _, _, p in b.received] == [bytes([2])] and drop.hits == 2
    assert [e.fate for e in s.bus.transcript[:3]] == ["dropped", "dropped", "sent"]


def test_v_rt_05_modify() -> None:
    s, _, b = _net()
    s.bus.add_interceptor(adversary.Modify(adversary.label_is("ping"), adversary.flip_byte(0, 0xFF)))
    s.command("A", "start", "B", 1)
    s.run_until_quiescent()
    assert b.received[0][2] == b"\xff"
    assert s.bus.transcript[0].fate == "modified" and s.bus.transcript[0].frame.tampered


def test_v_rt_05_delay_reorders() -> None:
    s, _, b = _net()
    s.bus.add_interceptor(adversary.Delay(lambda f: f.payload == b"\x00", 5))
    s.command("A", "start", "B", 3)
    s.run_until_quiescent()
    assert [p for _, label, p in b.received if label == "ping"] == [b"\x01", b"\x02", b"\x00"]


def test_v_rt_05_duplicate() -> None:
    s, _, b = _net()
    s.bus.add_interceptor(adversary.Duplicate(adversary.label_is("ping")))
    s.command("A", "start", "B", 1)
    s.run_until_quiescent()
    assert [p for _, label, p in b.received if label == "ping"] == [b"\x00", b"\x00"]
    ids = [e.frame.frame_id for e in s.bus.transcript if e.frame.label == "ping"]
    assert len(set(ids)) == 2


def test_v_rt_05_inject_and_record() -> None:
    s, _a, b = _net()
    rec = adversary.Record(adversary.always)
    s.bus.add_interceptor(rec)
    s.bus.add_interceptor(adversary.Inject(Frame("A", "B", "ping", b"forged"), at_step=3))
    s.run_until_quiescent()
    assert (3, "ping", b"forged") in b.received
    assert [f.label for f in rec.frames] == ["pong"]  # the injection bypasses the chain; the reply does not
    assert any(e.fate == "injected" for e in s.bus.transcript)


def test_v_web_06_product_bus_refuses_adversary() -> None:
    s, _, _ = _net(kind=PRODUCT)
    with pytest.raises(AdversaryNotAllowed):
        s.bus.add_interceptor(adversary.Record())
    with pytest.raises(AdversaryNotAllowed):
        s.bus.inject(Frame("A", "B", "ping", b""), 0)


def test_frame_payload_must_be_bytes() -> None:
    with pytest.raises(TypeError):
        Frame("A", "B", "x", "not bytes")  # type: ignore[arg-type]


def test_capture_returns_a_copy_of_the_keystore() -> None:
    s, a, _ = _net()
    a.keystore.put("pr", b"\x01\x02", SecretClass.SECRET)
    stolen = adversary.capture(s, "A")
    assert stolen == {"pr": b"\x01\x02"}
    stolen["pr"] = b""
    assert a.keystore.get("pr") == b"\x01\x02"


# -- M2-T2 keystore ---------------------------------------------------------------------

def test_keystore_destroy_zeroes_the_original_buffer() -> None:
    ks = Keystore("D")
    ks.put("x", b"secret!", SecretClass.SECRET)
    buf = ks._entries["x"].value
    assert ks.destroy("x") is True
    assert buf == bytearray(len(b"secret!")) and not ks.has("x")
    assert ks.destroy("x") is False


def test_keystore_adapter_mirrors_changes() -> None:
    log: list[tuple[str, str]] = []

    class Adapter:
        def save(self, device_id, name, cls, value):  # type: ignore[no-untyped-def]
            log.append(("save", name))

        def delete(self, device_id, name):  # type: ignore[no-untyped-def]
            log.append(("delete", name))

    ks = Keystore("D", Adapter())
    ks.put("a", b"1", SecretClass.PUBLIC)
    ks.put("a", b"2", SecretClass.PUBLIC)
    ks.destroy("a")
    assert log == [("save", "a"), ("delete", "a"), ("save", "a"), ("delete", "a")]
