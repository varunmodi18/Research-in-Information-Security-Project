"""Public broadcast channel with a Dolev-Yao tap (IA-08).

Every frame sent is appended to a global transcript an adversary may read. An optional
interceptor (IMPLEMENTATION_PLAN.md M1-T3, I-11) sees each frame before delivery and may pass
it, return a modified copy, or drop it by returning None. Receivers must read what `send`
returns -- the delivered frame -- never the sender's in-memory values (I-01).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace

from maka import trace
from maka.wire import size


@dataclass(frozen=True)
class Frame:
    label: str
    src: str
    dst: str
    payload: object  # bytes for MAKA frames (maka.codec); ICMDS scenarios still pass objects
    nbits: int  # RP9 §7.2 paper-model size, from the sender's itemised body
    injected: bool = False  # put on the channel by the adversary; excluded from cost totals


Interceptor = Callable[[Frame], "Frame | None"]


@dataclass
class Channel:
    """A single shared broadcast medium. `frames` is the adversary-visible transcript."""

    frames: list[Frame] = field(default_factory=list)
    interceptor: Interceptor | None = None

    def send(self, label: str, src: str, dst: str, payload: object,
             body: dict[str, object]) -> Frame | None:
        """Transmits a frame and returns the frame as delivered (None if dropped)."""
        nbits, _itemisation = size([(k, v) for k, v in body.items()])
        frame: Frame | None = Frame(label=label, src=src, dst=dst, payload=payload, nbits=nbits)
        t = trace.active()
        if self.interceptor is not None:
            original = frame
            frame = self.interceptor(original)
            if frame is None:
                t.step("adversary", f"dropped {label} ({src} -> {dst})")
                return None
            if frame != original:
                t.step("adversary", f"modified {label} ({src} -> {dst}) in transit")
        assert frame is not None  # type narrowing only
        self.frames.append(frame)
        t.frame(frame.src, frame.dst, frame.label, frame.nbits, body)
        return frame

    def eavesdrop(self, label: str | None = None) -> list[Frame]:
        """Adversary read access: every frame, or every frame with a given label."""
        return [f for f in self.frames if label is None or f.label == label]

    def inbox(self, dst: str, label: str) -> list[Frame]:
        """Frames with a given label delivered to `dst`, in delivery order."""
        return [f for f in self.frames if f.dst == dst and f.label == label]

    def replay(self, frame: Frame) -> Frame:
        """Adversary re-injects a previously observed frame verbatim; the caller delivers the
        returned frame to its destination's receive handler."""
        frame = replace(frame, injected=True)
        self.frames.append(frame)
        t = trace.active()
        t.step("adversary", f"replaying frame {frame.label} ({frame.src} -> {frame.dst})")
        return frame

    def reset(self) -> None:
        self.frames.clear()

    def total_bits(self, labels: list[str] | None = None) -> int:
        return sum(f.nbits for f in self.frames
                   if not f.injected and (labels is None or f.label in labels))

    def bits_since(self, start: int) -> int:
        """Paper-model bits of every frame sent after transcript index `start` (Table 3 row 4)."""
        return sum(f.nbits for f in self.frames[start:] if not f.injected)
