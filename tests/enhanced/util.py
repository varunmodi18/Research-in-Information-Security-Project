"""Helpers for the MAKA-E tests. Every network built here runs the V-CAP-01 invariant hook
(no keystore but the BS's ever holds k) after every scheduler step."""

from __future__ import annotations

from typing import Any

from maka import rng
from maka.enhanced import messages as m
from maka.enhanced import network as en
from maka.runtime.bus import Frame
from maka.runtime.events import SecurityEvent

SEED = 424242


def onboarded(topology: str = "small", seed: int = SEED, **kw: Any) -> en.EnhancedNetwork:
    net = en.build("toy", topology, seed=seed, **kw)
    net.onboard()
    return net


def events(net: en.EnhancedNetwork, etype: str, since: int = 0) -> list[SecurityEvent]:
    return [e for e in net.scheduler.events[since:] if e.type == etype]


def mark(net: en.EnhancedNetwork) -> int:
    return len(net.scheduler.events)


def adversary_rng(label: str = "adversary") -> rng.Rng:
    return rng.Rng(seed=9_000_001).spawn(label)


def inject(net: en.EnhancedNetwork, src: str, dst: str, payload: bytes) -> None:
    net.scheduler.bus.inject(Frame(src, dst, m.label(payload), payload), net.scheduler.step_no)


def frames(net: en.EnhancedNetwork, label: str, src: str | None = None, dst: str | None = None) -> list[Frame]:
    return [e.frame for e in net.scheduler.bus.transcript if e.frame.label == label
            and (src is None or e.frame.src == src) and (dst is None or e.frame.dst == dst)]


def session_keys(net: en.EnhancedNetwork, ident: str, peer: str, purpose: str) -> tuple[bytes, bytes]:
    d = net.device(ident)
    s = d.current_session(peer, purpose)
    assert s is not None, (ident, peer, purpose)
    return d.keystore.get(s.key("send")), d.keystore.get(s.key("recv"))
