"""V-ARCH-01 (follow-up E1): a device holds no reference to another device, the scheduler, the bus
or the network driver, in either mode. Devices interact only through frames on the bus.

The scan walks every attribute, container element and dict key reachable from a device (cycles cut
by identity), so a reference hidden in a session, a keystore or a callback's closure is found. A
positive control plants such a reference and checks that the scan reports it.
"""

from __future__ import annotations

import pytest

from maka.enhanced import network as en
from maka.original_rt import network as onet
from maka.runtime.bus import Bus
from maka.runtime.device import Device
from maka.runtime.scheduler import Scheduler

SEED = 20260927
FORBIDDEN = (Device, Scheduler, Bus, onet.OriginalNetwork, en.EnhancedNetwork)
ATOMS = (str, bytes, bytearray, int, float, complex, bool, type(None))


def references(obj: object, owner: Device, seen: set[int], path: str) -> list[str]:
    """Paths from `owner` to any FORBIDDEN object other than `owner` itself."""
    if id(obj) in seen or isinstance(obj, ATOMS):
        return []
    seen.add(id(obj))
    if obj is not owner and isinstance(obj, FORBIDDEN):
        return [path]
    children: list[tuple[str, object]] = []
    if isinstance(obj, dict):
        children = [(f"{path}[{k!r}]", v) for k, v in obj.items()] + [(f"{path}.key", k) for k in obj]
    elif isinstance(obj, (list, tuple, set, frozenset)):
        children = [(f"{path}[{i}]", v) for i, v in enumerate(obj)]
    else:
        if hasattr(obj, "__dict__"):
            children += [(f"{path}.{k}", v) for k, v in vars(obj).items()]
        for slot in getattr(type(obj), "__slots__", ()):
            if hasattr(obj, slot):
                children.append((f"{path}.{slot}", getattr(obj, slot)))
        closure = getattr(obj, "__closure__", None) or ()
        children += [(f"{path}.<closure>", c.cell_contents) for c in closure if c.cell_contents is not None]
        bound = getattr(obj, "__self__", None)
        if bound is not None and not isinstance(obj, type):
            children.append((f"{path}.__self__", bound))
    out: list[str] = []
    for p, child in children:
        out += references(child, owner, seen, p)
    return out


def _networks() -> list[tuple[str, object]]:
    orig = onet.build("toy", "net", seed=SEED)
    orig.onboard()
    enh = en.build("toy", "net", seed=SEED)
    enh.onboard()
    enh.send_reading("CM-0101", "21.4")
    enh.run()
    return [("original", orig), ("enhanced", enh)]


@pytest.mark.parametrize("mode", ["original", "enhanced"])
def test_v_arch_01_devices_hold_no_cross_references(mode: str) -> None:
    net = dict(_networks())[mode]
    devices = net.scheduler.devices.values()  # type: ignore[attr-defined]
    assert len(devices) == 13
    for dev in devices:
        assert references(dev, dev, set(), dev.identity) == [], dev.identity


@pytest.mark.parametrize("plant", ["network", "scheduler", "other device", "closure"])
def test_v_arch_01_positive_control(plant: str) -> None:
    """The scan is not vacuous: a planted reference is found, wherever it hides."""
    net = en.build("toy", "paper", seed=SEED)
    net.onboard()
    cm, ch = net.device("CM-0101"), net.device("CH-01")
    s = cm.current_session("CH-01", "CM-CH")
    if plant == "network":
        s.via = net  # type: ignore[assignment]
    elif plant == "scheduler":
        cm.keystore.__dict__["_leak"] = [{"deep": (net.scheduler,)}]
    elif plant == "other device":
        cm.retry_via[("x", "y")] = ch  # type: ignore[assignment]
    else:
        cm.__dict__["_hook"] = lambda: ch.identity
    assert references(cm, cm, set(), cm.identity)
