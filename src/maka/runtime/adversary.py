"""Adversary capabilities on a lab network's channel (IMPLEMENTATION_PLAN.md §2.1 AT1-AT4, M2-T3).

Each capability is an interceptor added to the bus; `Bus(kind="product")` refuses them.
`capture` models device capture (AT4): it copies one device's keystore for Lab scenario code.
Its output must never reach the API; the Lab reports secret *names* and verdicts only.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace

from maka.runtime.bus import Frame
from maka.runtime.scheduler import Scheduler

Pred = Callable[[Frame], bool]


def label_is(*labels: str) -> Pred:
    return lambda f: f.label in labels


def always(_frame: Frame) -> bool:
    return True


@dataclass
class _Base:
    hits: int = field(default=0, init=False)
    hit_frame_ids: list[int] = field(default_factory=list, init=False)

    def _hit(self, frame: Frame) -> None:
        self.hits += 1
        self.hit_frame_ids.append(frame.frame_id)

    def tick(self, step: int) -> list[Frame]:
        return []


@dataclass
class Drop(_Base):
    pred: Pred = always
    limit: int | None = None  # drop at most this many matching frames

    def intercept(self, frame: Frame, step: int) -> list[tuple[Frame, int]]:
        if self.pred(frame) and (self.limit is None or self.hits < self.limit):
            self._hit(frame)
            return []
        return [(frame, 0)]


@dataclass
class Modify(_Base):
    pred: Pred = always
    fn: Callable[[bytes], bytes] = lambda b: b
    limit: int | None = None

    def intercept(self, frame: Frame, step: int) -> list[tuple[Frame, int]]:
        if self.pred(frame) and (self.limit is None or self.hits < self.limit):
            self._hit(frame)
            return [(replace(frame, payload=self.fn(frame.payload)), 0)]
        return [(frame, 0)]


def flip_byte(index: int = -1, mask: int = 0x01) -> Callable[[bytes], bytes]:
    def fn(payload: bytes) -> bytes:
        raw = bytearray(payload)
        raw[index] ^= mask
        return bytes(raw)
    return fn


@dataclass
class Delay(_Base):
    pred: Pred = always
    n: int = 1
    limit: int | None = None

    def intercept(self, frame: Frame, step: int) -> list[tuple[Frame, int]]:
        if self.pred(frame) and (self.limit is None or self.hits < self.limit):
            self._hit(frame)
            return [(frame, self.n)]
        return [(frame, 0)]


@dataclass
class Duplicate(_Base):
    pred: Pred = always
    limit: int | None = None

    def intercept(self, frame: Frame, step: int) -> list[tuple[Frame, int]]:
        if self.pred(frame) and (self.limit is None or self.hits < self.limit):
            self._hit(frame)
            return [(frame, 0), (frame, 0)]
        return [(frame, 0)]


@dataclass
class Inject(_Base):
    """Puts `frame` on the channel at `at_step` (delivered from that step on)."""

    frame: Frame | None = None
    at_step: int = 1
    done: bool = field(default=False, init=False)

    def intercept(self, frame: Frame, step: int) -> list[tuple[Frame, int]]:
        return [(frame, 0)]

    def tick(self, step: int) -> list[Frame]:
        if not self.done and self.frame is not None and step >= self.at_step:
            self.done = True
            self.hits += 1
            return [self.frame]
        return []

    def pending_injections(self, step: int) -> bool:
        return not self.done


@dataclass
class Record(_Base):
    """Passive eavesdropper: keeps a copy of every matching frame (AT1 'read')."""

    pred: Pred = always
    frames: list[Frame] = field(default_factory=list, init=False)

    def intercept(self, frame: Frame, step: int) -> list[tuple[Frame, int]]:
        if self.pred(frame):
            self._hit(frame)
            self.frames.append(frame)
        return [(frame, 0)]


def capture(scheduler: Scheduler, device_id: str) -> dict[str, bytes]:
    """AT4 device capture: a copy of every keystore entry of one device, at this moment."""
    return scheduler.devices[device_id].keystore.snapshot()
