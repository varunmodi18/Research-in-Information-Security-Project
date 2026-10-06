"""Device base class (IMPLEMENTATION_PLAN.md §4.3).

A device's only inputs are `handle(frame)`, `on_timer(name)` and operator commands. It holds
its identity, role, cluster, keystore and protocol state -- and no reference to any other
device, the bus, the scheduler or the network (V-ARCH-01). Outputs are returned frames; events,
checks, timer requests and the verdict are buffered here and drained by the scheduler.
"""

from __future__ import annotations

from typing import Any

from maka import rng
from maka.runtime import events as ev
from maka.runtime.bus import Frame
from maka.runtime.keystore import Keystore

# Device status values (FR-11)
PROVISIONED = "provisioned"
REGISTERED = "registered"
AUTHENTICATED = "authenticated"
ACTIVE = "active"
FAILED = "failed"
REVOKED = "revoked"

# Timers whose name starts with this prefix are periodic background work (the CH's grant refresh,
# follow-up D3): they fire whenever steps are taken but do not keep the scheduler busy, so
# run_until_quiescent returns once all protocol traffic has settled.
BACKGROUND = "bg:"

BS = "BS"
CH = "CH"
CM = "CM"


class Device:
    role = ""

    def __init__(self, identity: str, cluster: str | None, keystore: Keystore,
                 randomness: rng.RandomSource) -> None:
        self.identity = identity
        self.cluster = cluster
        self.keystore = keystore
        self.rng = randomness
        self.status = PROVISIONED
        self.now = 0  # current scheduler step, set before every call
        self._events: list[ev.SecurityEvent] = []
        self._checks: list[ev.Check] = []
        self._timer_ops: list[tuple[str, str, int]] = []  # ("set"|"cancel", name, delay)
        self._verdict: tuple[str, str | None] = (ev.ACCEPT, None)

    # -- inputs (overridden by protocol devices) -------------------------------

    def handle(self, frame: Frame) -> list[Frame]:
        raise NotImplementedError

    def on_timer(self, name: str) -> list[Frame]:
        return []

    # -- helpers for subclasses ------------------------------------------------------

    def frame(self, dst: str, label: str, payload: bytes, paper_bits: int = 0) -> Frame:
        return Frame(src=self.identity, dst=dst, label=label, payload=payload, paper_bits=paper_bits)

    def emit(self, event_type: str, peer: str | None = None, sid: str | None = None,
             **details: Any) -> None:
        self._events.append(ev.make_event(event_type, self.identity, peer=peer, sid=sid, **details))

    def check(self, name: str, ok: bool, reason: str = "") -> bool:
        self._checks.append(ev.Check(name, ok, reason))
        return ok

    def reject(self, code: str, peer: str | None = None, sid: str | None = None,
               **details: Any) -> list[Frame]:
        """Records a FAIL verdict whose reason is `code` (an event type), emits that event,
        and sends nothing."""
        self._verdict = (ev.REJECT, code)
        self.emit(code, peer=peer, sid=sid, **details)
        return []

    def set_timer(self, name: str, delay: int) -> None:
        self._timer_ops.append(("set", name, delay))

    def cancel_timer(self, name: str) -> None:
        self._timer_ops.append(("cancel", name, 0))

    def set_status(self, status: str) -> None:
        self.status = status

    # -- scheduler interface --------------------------------------------------------

    def _begin(self, now: int) -> None:
        self.now = now
        self._events, self._checks, self._timer_ops = [], [], []
        self._verdict = (ev.ACCEPT, None)

    def _drain(self) -> tuple[list[ev.SecurityEvent], list[ev.Check], list[tuple[str, str, int]],
                              tuple[str, str | None]]:
        out = (self._events, self._checks, self._timer_ops, self._verdict)
        self._events, self._checks, self._timer_ops = [], [], []
        return out
