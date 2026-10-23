"""Traffic driver with benign variation and per-device fault injection (docs/BEHAVIOUR.md).

One run: build a MAKA-E network on a lab bus (toy parameters by default, for speed), onboard it
with the cluster heads started in random order at random offsets and each CH's members in random
order, then drive `observe_steps` steps of normal traffic: every CM sends readings at jittered
intervals and occasionally rekeys at a low rate. A `Fault` makes one device behave abnormally for
a time span; it is the ground truth for the labels. Nothing here is an adversary on the channel:
the network runs unmodified apart from the one faulty device, and every frame is protocol-valid.

Faults:
- `excessive_rekey`: one CM rekeys every `rekey_interval` steps during the span (far below the
  normal interval; the `near_normal` variant only slightly below it).
- `lossy_forwarding`: one CH forwards only `forward_fraction` of its members' readings in its
  batches during the span; the rest are silently left out.
"""

from __future__ import annotations

from collections.abc import MutableSequence, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, TypeVar, cast

from maka.enhanced import network as en
from maka.enhanced.lifecycle import EnhancedCH
from maka.rng import Rng
from maka.runtime import device as dv
from maka.runtime.bus import Frame
from maka.runtime.events import SecurityEvent
from maka.runtime.scheduler import StepResult

T = TypeVar("T")


# Seeded helpers on maka.rng (all randomness flows through it; tests/test_hygiene.py).
def uniform(r: Rng) -> float:
    """Uniform float in [0, 1)."""
    return r.below(1 << 53) / (1 << 53)


def choice(r: Rng, seq: Sequence[T]) -> T:
    return seq[r.below(len(seq))]


def shuffle(r: Rng, seq: MutableSequence[T]) -> None:
    """Fisher-Yates, in place."""
    for i in range(len(seq) - 1, 0, -1):
        j = r.below(i + 1)
        seq[i], seq[j] = seq[j], seq[i]


EXCESSIVE_REKEY = "excessive_rekey"
LOSSY_FORWARDING = "lossy_forwarding"
FAULT_KINDS = (EXCESSIVE_REKEY, LOSSY_FORWARDING)


@dataclass(frozen=True)
class TrafficConfig:
    """Every knob of a run in one object (recorded in the dataset manifest)."""

    params: str = "toy"
    window: int = 20  # scheduler steps per feature window
    observe_steps: int = 600  # traffic steps after onboarding (30 windows)
    reading_interval: int = 30  # mean steps between a CM's readings
    reading_jitter: int = 10  # each interval is uniform in [interval - jitter, interval + jitter]
    rekey_rate: float = 1 / 300  # probability per CM per step of a legitimate rekey
    onboarding_stagger: int = 10  # each CH starts onboarding at a random offset in [0, stagger]
    fault_start: int = 200  # steps after the start of observation
    fault_duration: int = 300


@dataclass(frozen=True)
class Fault:
    """One device behaving abnormally during [start, start + duration) steps of observation."""

    kind: str
    variant: str = "default"
    rekey_interval: int = 5  # excessive_rekey: steps between the faulty CM's rekeys
    forward_fraction: float = 0.7  # lossy_forwarding: share of member readings the CH forwards


# The variants the dataset covers. Normal rekeys come every 300 steps on average (rekey_rate).
FAULT_VARIANTS: dict[str, Fault] = {
    "excessive_rekey/default": Fault(EXCESSIVE_REKEY, "default", rekey_interval=5),
    "excessive_rekey/near_normal": Fault(EXCESSIVE_REKEY, "near_normal", rekey_interval=150),
    "lossy_forwarding/default": Fault(LOSSY_FORWARDING, "default", forward_fraction=0.7),
}


class LossyForwardingCH(EnhancedCH):
    """A cluster head with a forwarding fault: while `forward_fraction` < 1 it leaves a random
    share of its members' readings out of each batch. Used only by this driver."""

    def __init__(self, *args: Any, fault_seed: int = 0, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.forward_fraction = 1.0
        self.left_out = 0
        self._fault_rng = Rng(seed=fault_seed)

    def _flush_batch(self) -> list[Frame]:
        if self.forward_fraction < 1.0 and self.batch:
            kept = [item for item in self.batch if uniform(self._fault_rng) < self.forward_fraction]
            self.left_out += len(self.batch) - len(kept)
            self.batch = kept
        return super()._flush_batch()


@dataclass
class RunRecord:
    """What a run leaves behind: the frame/step log, the security events, the device roles and
    the ground truth. Feature extraction reads only `log`, `events` and `roles`."""

    topology: str
    seed: int
    config: TrafficConfig
    log: list[StepResult]
    events: list[SecurityEvent]
    roles: dict[str, str]
    observe_start: int  # scheduler step at which observation (window 0) starts
    fault: Fault | None = None
    fault_device: str | None = None
    fault_steps: tuple[int, int] | None = None  # absolute [start, end) scheduler steps
    notes: dict[str, Any] = field(default_factory=dict)

    @property
    def n_windows(self) -> int:
        return self.config.observe_steps // self.config.window

    def fault_windows(self) -> set[int]:
        """Windows that overlap the fault span: the ground-truth abnormal windows of fault_device."""
        if self.fault_steps is None:
            return set()
        w, (a, b) = self.config.window, self.fault_steps
        return {k for k in range(self.n_windows)
                if self.observe_start + k * w < b and self.observe_start + (k + 1) * w > a}

    def manifest(self) -> dict[str, Any]:
        return {"topology": self.topology, "seed": self.seed,
                "fault": asdict(self.fault) if self.fault else None, "fault_device": self.fault_device,
                "fault_steps": list(self.fault_steps) if self.fault_steps else None,
                "observe_start": self.observe_start, **self.notes}


def _swap_in_lossy_ch(net: en.EnhancedNetwork, ch_id: str, fault_seed: int) -> LossyForwardingCH:
    """Before onboarding: replace one CH with an identical, freshly constructed LossyForwardingCH
    (same identity, keystore, randomness and member list)."""
    old = cast(EnhancedCH, net.device(ch_id))
    new = LossyForwardingCH(old.identity, old.cluster, old.keystore, old.rng, old.cfg,
                            member_config=list(old.member_config), fault_seed=fault_seed)
    net.scheduler.remove_device(ch_id)
    net.scheduler.add_device(new)
    return new


def run(topology: str, seed: int, config: TrafficConfig | None = None, fault: Fault | None = None) -> RunRecord:
    cfg = config or TrafficConfig()
    rnd = Rng(seed=seed).spawn(f"behaviour-traffic/{topology}")
    net = en.build(cfg.params, topology, seed=seed)
    chs = sorted(ch.identity for ch in net.chs())
    cms = sorted(cm.identity for cm in net.cms())
    fault_device = None
    lossy: LossyForwardingCH | None = None
    if fault is not None:
        if fault.kind == EXCESSIVE_REKEY:
            fault_device = choice(rnd, cms)
        elif fault.kind == LOSSY_FORWARDING:
            fault_device = choice(rnd, chs)
            lossy = _swap_in_lossy_ch(net, fault_device, rnd.below(2**32))
        else:
            raise ValueError(f"unknown fault {fault.kind!r}; choose one of {FAULT_KINDS}")

    # Benign variation 1: random onboarding order (CHs at random offsets, members shuffled).
    for ch_id in chs:
        members = cast(EnhancedCH, net.device(ch_id)).member_config
        shuffle(rnd, members)
    starts = sorted((rnd.randint(0, cfg.onboarding_stagger + 1), ch_id) for ch_id in chs)
    for offset, ch_id in starts:
        while net.scheduler.step_no < offset:
            net.step(1)
        with net.context():
            net.scheduler.command(ch_id, "start_onboarding")
    net.run()

    t0 = net.scheduler.step_no
    fault_steps = (t0 + cfg.fault_start, t0 + cfg.fault_start + cfg.fault_duration) if fault else None
    # Benign variation 2: jittered reading intervals, starting at a random phase.
    next_reading = {cm: t0 + rnd.randint(1, cfg.reading_interval + 1) for cm in cms}
    for _ in range(cfg.observe_steps):
        now = net.scheduler.step_no
        in_fault = fault_steps is not None and fault_steps[0] <= now < fault_steps[1]
        if lossy is not None:
            lossy.forward_fraction = cast(Fault, fault).forward_fraction if in_fault else 1.0
        for cm in cms:
            if net.device(cm).status == dv.REVOKED:
                continue
            if now >= next_reading[cm]:
                net.send_reading(cm, f"{20 + uniform(rnd) * 5:.2f}")
                next_reading[cm] = now + max(1, cfg.reading_interval + rnd.randint(-cfg.reading_jitter,
                                                                                  cfg.reading_jitter + 1))
            # Benign variation 3: occasional legitimate rekeys at a low rate.
            if uniform(rnd) < cfg.rekey_rate:
                net.rekey(cm)
        if (in_fault and fault is not None and fault.kind == EXCESSIVE_REKEY and fault_steps is not None
                and (now - fault_steps[0]) % fault.rekey_interval == 0):
            net.rekey(cast(str, fault_device))
        net.step(1)

    roles = {ident: d.role for ident, d in net.scheduler.devices.items()}
    notes: dict[str, Any] = {}
    if lossy is not None:
        notes["readings_left_out"] = lossy.left_out
    return RunRecord(topology=topology, seed=seed, config=cfg, log=list(net.scheduler.log),
                     events=list(net.scheduler.events), roles=roles, observe_start=t0, fault=fault,
                     fault_device=fault_device, fault_steps=fault_steps, notes=notes)
