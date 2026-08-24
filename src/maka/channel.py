"""Public broadcast channel with a Dolev-Yao tap (IA-08).

Every frame sent is appended to a global transcript an adversary may read, replay, drop,
reorder or inject into -- the channel model RP9 implicitly assumes for a WSN.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from maka import trace
from maka.wire import size


@dataclass
class Frame:
    label: str
    src: str
    dst: str
    payload: object  # a messages.* dataclass
    nbits: int


@dataclass
class Channel:
    """A single shared broadcast medium. `frames` is the adversary-visible transcript."""

    frames: list[Frame] = field(default_factory=list)

    def send(self, label: str, src: str, dst: str, payload: object, body: dict[str, object]) -> Frame:
        nbits, itemisation = size([(k, v) for k, v in body.items()], sizing="paper")
        frame = Frame(label=label, src=src, dst=dst, payload=payload, nbits=nbits)
        self.frames.append(frame)
        t = trace.active()
        t.frame(src, dst, label, nbits, body)
        return frame

    def eavesdrop(self, label: str | None = None) -> list[Frame]:
        """Adversary read access: every frame, or every frame with a given label."""
        return [f for f in self.frames if label is None or f.label == label]

    def replay(self, frame: Frame) -> Frame:
        """Adversary re-injects a previously observed frame verbatim."""
        self.frames.append(frame)
        t = trace.active()
        t.step("adversary", f"replaying frame {frame.label} ({frame.src} -> {frame.dst})")
        return frame

    def reset(self) -> None:
        self.frames.clear()

    def count(self, label: str | None = None) -> int:
        return len(self.eavesdrop(label))

    def total_bits(self, labels: list[str] | None = None) -> int:
        return sum(f.nbits for f in self.frames if labels is None or f.label in labels)
