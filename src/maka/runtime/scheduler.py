"""Discrete-event scheduler (IMPLEMENTATION_PLAN.md §4.3, M2-T1).

Each `step()` advances the clock by one, fires the timers due at that step, then delivers at
most one ready frame to its destination's `handle`. Frames a device returns are sent on the
bus with the device's identity as source. Operator commands run between steps. Every step
produces a StepResult, which hooks (invariant checks, persistence, live events) observe.
"""

from __future__ import annotations

import heapq
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from maka.runtime import events as ev
from maka.runtime.bus import Bus, Frame
from maka.runtime.device import Device
from maka.runtime.errors import StepLimitExceeded, UnknownDevice


@dataclass
class StepResult:
    step: int
    kind: str  # "deliver" | "command" | "idle"
    frame: Frame | None = None
    to: str | None = None
    verdict: str = ev.IDLE
    reason: str | None = None
    checks: list[ev.Check] = field(default_factory=list)
    events: list[ev.SecurityEvent] = field(default_factory=list)
    emitted: list[Frame] = field(default_factory=list)
    timers_fired: list[tuple[str, str]] = field(default_factory=list)
    status_changes: dict[str, str] = field(default_factory=dict)


Hook = Callable[[StepResult], None]


def _timer_call(device: Device, name: str) -> Callable[[], list[Frame]]:
    return lambda: device.on_timer(name)


class Scheduler:
    def __init__(self, bus: Bus, devices: list[Device] | None = None) -> None:
        self.bus = bus
        self.devices: dict[str, Device] = {}
        self.step_no = 0
        self.log: list[StepResult] = []
        self.events: list[ev.SecurityEvent] = []
        self.hooks: list[Hook] = []
        self._timers: list[tuple[int, int, str, str]] = []  # (at_step, seq, device, name)
        self._cancelled: set[tuple[str, str, int]] = set()
        self._timer_seq = 0
        self.bus.recipients = lambda: list(self.devices)
        for d in devices or []:
            self.add_device(d)

    def add_device(self, device: Device) -> None:
        if device.identity in self.devices:
            raise ValueError(f"duplicate device {device.identity}")
        self.devices[device.identity] = device

    def remove_device(self, identity: str) -> None:
        self.devices.pop(identity, None)

    # -- timers -------------------------------------------------------------------

    def set_timer(self, device_id: str, name: str, at_step: int) -> None:
        self._timer_seq += 1
        heapq.heappush(self._timers, (at_step, self._timer_seq, device_id, name))

    def cancel_timer(self, device_id: str, name: str) -> None:
        for _at, seq, dev, nm in self._timers:
            if dev == device_id and nm == name:
                self._cancelled.add((dev, nm, seq))

    def _live_timers(self) -> list[tuple[int, int, str, str]]:
        return [t for t in self._timers if (t[2], t[3], t[1]) not in self._cancelled]

    def pending_timers(self) -> int:
        return len(self._live_timers())

    # -- invoking devices ------------------------------------------------------------

    def _invoke(self, device: Device, fn: Callable[[], list[Frame]], result: StepResult) -> None:
        device._begin(self.step_no)
        before = device.status
        frames = fn() or []
        events, checks, timer_ops, verdict = device._drain()
        for op, name, delay in timer_ops:
            if op == "set":
                self.cancel_timer(device.identity, name)
                self.set_timer(device.identity, name, self.step_no + max(1, delay))
            else:
                self.cancel_timer(device.identity, name)
        stamped = [replace(e, step=self.step_no,
                           frame_id=result.frame.frame_id if result.frame and e.frame_id is None else e.frame_id)
                   for e in events]
        result.events.extend(stamped)
        result.checks.extend(checks)
        if result.kind in ("deliver", "command") and verdict[0] != ev.ACCEPT:
            result.verdict, result.reason = verdict
        for f in frames:
            result.emitted.extend(self.bus.send(replace(f, src=device.identity), self.step_no))
        if device.status != before:
            result.status_changes[device.identity] = device.status

    def command(self, device_id: str, method: str, *args: Any, **kwargs: Any) -> StepResult:
        """Runs an operator command (e.g. start_onboarding, send_reading) at the current step."""
        device = self.devices.get(device_id)
        if device is None:
            raise UnknownDevice(device_id)
        result = StepResult(step=self.step_no, kind="command", verdict=ev.COMMAND, to=device_id,
                            reason=method)
        self._invoke(device, lambda: getattr(device, method)(*args, **kwargs), result)
        self._finish(result)
        return result

    def step(self) -> StepResult:
        self.step_no += 1
        self.bus.tick(self.step_no)
        result = StepResult(step=self.step_no, kind="idle")

        while self._timers and self._timers[0][0] <= self.step_no:
            _at, seq, dev_id, name = heapq.heappop(self._timers)
            if (dev_id, name, seq) in self._cancelled:
                self._cancelled.discard((dev_id, name, seq))
                continue
            device = self.devices.get(dev_id)
            if device is None:
                continue
            result.timers_fired.append((dev_id, name))
            self._invoke(device, _timer_call(device, name), result)

        delivery = self.bus.pop_ready(self.step_no)
        if delivery is not None:
            result.kind = "deliver"
            result.frame = delivery.frame
            result.to = delivery.to
            result.verdict = ev.ACCEPT
            device = self.devices.get(delivery.to)
            if device is None:
                result.verdict, result.reason = ev.DROPPED, "NO_SUCH_DEVICE"
            else:
                self._invoke(device, lambda: device.handle(delivery.frame), result)
        self._finish(result)
        return result

    def _finish(self, result: StepResult) -> None:
        self.log.append(result)
        self.events.extend(result.events)
        for hook in list(self.hooks):
            hook(result)

    # -- running ------------------------------------------------------------------------

    def busy(self) -> bool:
        return self.bus.pending() > 0 or self.pending_timers() > 0 or any(
            hasattr(i, "pending_injections") and i.pending_injections(self.step_no)
            for i in self.bus.interceptors)

    def run_until_quiescent(self, max_steps: int = 10_000,
                            should_stop: Callable[[], bool] | None = None) -> list[StepResult]:
        """Steps until nothing is in flight and no timer is pending. Raises StepLimitExceeded."""
        results = []
        taken = 0
        while self.busy():
            if should_stop is not None and should_stop():
                break
            if taken >= max_steps:
                raise StepLimitExceeded(f"still busy after {max_steps} steps")
            results.append(self.step())
            taken += 1
        return results

    def run_steps(self, n: int) -> list[StepResult]:
        return [self.step() for _ in range(n)]
