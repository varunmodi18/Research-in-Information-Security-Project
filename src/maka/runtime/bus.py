"""The simulated radio channel: immutable byte frames and an in-flight queue (§4.3, TB1).

`Bus.send` runs the interceptor chain (lab networks only) and enqueues the result. Delivery
order is FIFO by (deliver-at step, enqueue order). A frame addressed to BROADCAST is delivered
separately to every other device, as one radio transmission (it is counted once).
"""

from __future__ import annotations

import heapq
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from typing import Protocol

from maka.runtime.errors import AdversaryNotAllowed

BROADCAST = "*"
PRODUCT = "product"
LAB = "lab"


@dataclass(frozen=True)
class Frame:
    """One transmission. Holds bytes and public metadata only -- never Python objects."""

    src: str
    dst: str
    label: str
    payload: bytes
    paper_bits: int = 0  # RP9 §7.2 paper-model size (original mode); 0 when not applicable
    frame_id: int = -1  # assigned by the bus
    step: int = -1  # step at which it was sent, assigned by the bus
    injected: bool = False  # put on the channel by the adversary
    tampered: bool = False  # modified by the adversary in transit

    def __post_init__(self) -> None:
        if not isinstance(self.payload, bytes):
            raise TypeError("Frame.payload must be bytes")


class Interceptor(Protocol):
    """An adversary capability on the channel (maka.runtime.adversary)."""

    def intercept(self, frame: Frame, step: int) -> list[tuple[Frame, int]]:
        """Returns the frames to enqueue instead of `frame`, each with an extra delay in steps.
        [] drops it; [(frame, 0)] passes it unchanged."""
        ...

    def tick(self, step: int) -> list[Frame]:
        """Frames to inject at `step`."""
        ...


@dataclass(frozen=True)
class Delivery:
    at_step: int
    seq: int
    to: str
    frame: Frame

    def key(self) -> tuple[int, int]:
        return (self.at_step, self.seq)


@dataclass
class TranscriptEntry:
    """What happened to a frame on the channel (frame log, FR-13)."""

    frame: Frame
    fate: str  # sent | dropped | modified | delayed | duplicated | injected


@dataclass
class Bus:
    kind: str = LAB
    recipients: Callable[[], Iterable[str]] = field(default=lambda: ())
    transcript: list[TranscriptEntry] = field(default_factory=list)
    _interceptors: list[Interceptor] = field(default_factory=list)
    _queue: list[tuple[tuple[int, int], Delivery]] = field(default_factory=list)
    _next_id: int = 1
    _seq: int = 0

    def __post_init__(self) -> None:
        if self.kind not in (PRODUCT, LAB):
            raise ValueError(f"unknown bus kind {self.kind!r}")

    # -- adversary -------------------------------------------------------------

    def add_interceptor(self, interceptor: Interceptor) -> None:
        if self.kind == PRODUCT:
            raise AdversaryNotAllowed("product networks have no adversary interceptors (NFR-SEC-03)")
        self._interceptors.append(interceptor)

    def clear_interceptors(self) -> None:
        self._interceptors.clear()

    @property
    def interceptors(self) -> tuple[Interceptor, ...]:
        return tuple(self._interceptors)

    def inject(self, frame: Frame, step: int) -> Frame:
        """Adversary transmission: bypasses the interceptor chain, delivered from step+1."""
        if self.kind == PRODUCT:
            raise AdversaryNotAllowed("product networks have no adversary (NFR-SEC-03)")
        frame = replace(frame, frame_id=self._new_id(), step=step, injected=True)
        self.transcript.append(TranscriptEntry(frame, "injected"))
        self._enqueue(frame, step + 1)
        return frame

    def tick(self, step: int) -> None:
        for interceptor in list(self._interceptors):
            for frame in interceptor.tick(step):
                self.inject(frame, step - 1)  # deliverable at this very step

    # -- honest traffic ------------------------------------------------------------

    def send(self, frame: Frame, step: int) -> list[Frame]:
        """Transmits `frame` (sent during `step`); returns the frames actually enqueued."""
        frame = replace(frame, frame_id=self._new_id(), step=step)
        outputs: list[tuple[Frame, int]] = [(frame, 0)]
        for interceptor in self._interceptors:
            outputs = [(f2, d1 + d2) for f1, d1 in outputs for f2, d2 in interceptor.intercept(f1, step)]
        if not outputs:
            self.transcript.append(TranscriptEntry(frame, "dropped"))
            return []
        enqueued = []
        for i, (out, delay) in enumerate(outputs):
            if i > 0:
                out = replace(out, frame_id=self._new_id())
                fate = "duplicated"
            elif out.payload != frame.payload or out.dst != frame.dst or out.label != frame.label:
                out = replace(out, tampered=True)
                fate = "modified"
            else:
                fate = "delayed" if delay else "sent"
            self.transcript.append(TranscriptEntry(out, fate))
            self._enqueue(out, step + 1 + delay)
            enqueued.append(out)
        return enqueued

    # -- queue -------------------------------------------------------------------------

    def _new_id(self) -> int:
        fid = self._next_id
        self._next_id += 1
        return fid

    def _enqueue(self, frame: Frame, at_step: int) -> None:
        targets = [d for d in self.recipients() if d != frame.src] if frame.dst == BROADCAST else [frame.dst]
        for to in targets:
            self._seq += 1
            delivery = Delivery(at_step, self._seq, to, frame)
            heapq.heappush(self._queue, (delivery.key(), delivery))

    def pop_ready(self, step: int) -> Delivery | None:
        if self._queue and self._queue[0][0][0] <= step:
            return heapq.heappop(self._queue)[1]
        return None

    def next_ready_step(self) -> int | None:
        return self._queue[0][0][0] if self._queue else None

    def pending(self) -> int:
        return len(self._queue)

    def in_flight(self) -> list[Delivery]:
        return [d for _, d in sorted(self._queue, key=lambda kv: kv[0])]

    def flush(self) -> int:
        """Discards every in-flight frame (used by recovery, §4.8). Returns how many."""
        n = len(self._queue)
        self._queue.clear()
        return n
