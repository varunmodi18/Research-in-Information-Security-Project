"""Builds and drives a MAKA-E network on the runtime (IMPLEMENTATION_PLAN.md §4.6, M4).

The driver is the operator's console-side harness: it issues commands to devices and acts as
the trusted factory channel when provisioning (loading Pr_i). It never relays protocol data.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from typing import Any, cast

from maka import fixtures, ledger, params, rng, trace
from maka.enhanced import messages as m
from maka.enhanced import states as st
from maka.enhanced.device import EnhancedConfig, EnhancedDevice
from maka.enhanced.lifecycle import EnhancedBS, EnhancedCH, EnhancedCM
from maka.enhanced.membership import REVOKED
from maka.enhanced.provisioning import check_master_key_invariant, new_bs_keystore
from maka.runtime import device as dv
from maka.runtime.bus import LAB, Bus
from maka.runtime.errors import UnknownDevice
from maka.runtime.keystore import Keystore, SecretClass
from maka.runtime.scheduler import Scheduler, StepResult


@dataclass(frozen=True)
class Tunables:
    max_pending: int = 16
    t_hs: int = 20
    t_retry: int = 5
    batch_steps: int = 5
    batch_max: int = 8
    grant_refresh_steps: int = 50


def effective_t_hs(t_hs: int, n_devices: int) -> int:
    """One frame is delivered per step network-wide, so a handshake's latency grows with the
    number of frames in flight. T_HS is scaled by device count (docs/PLAN_ERRATA.md E-05)."""
    return t_hs + 6 * n_devices


@dataclass
class EnhancedNetwork:
    scheduler: Scheduler
    cfg: EnhancedConfig
    params_name: str
    source: rng.RandomSource
    ledger: ledger.Ledger = field(default_factory=ledger.Ledger)
    mode: str = "enhanced"
    aborted_sessions: list[dict[str, Any]] = field(default_factory=list)
    # readings a CM sent while its designated CH was revoked: the CH cannot reach the BS any more,
    # so they are lost (follow-up D2). Driver-side bookkeeping, like revoke()'s status update.
    undelivered: dict[str, int] = field(default_factory=dict)

    # -- plumbing --------------------------------------------------------------------------

    @contextmanager
    def context(self) -> Iterator[None]:
        with ExitStack() as stack:
            stack.enter_context(rng.using(self.source))
            stack.enter_context(ledger.using(self.ledger))
            stack.enter_context(trace.using(trace.NullTracer()))
            yield

    @property
    def bs_id(self) -> str:
        return self.cfg.id_bs

    def bs(self) -> EnhancedBS:
        return cast(EnhancedBS, self.scheduler.devices[self.bs_id])

    def device(self, ident: str) -> EnhancedDevice:
        d = self.scheduler.devices.get(ident)
        if d is None:
            raise UnknownDevice(ident)
        return cast(EnhancedDevice, d)

    def chs(self) -> list[EnhancedCH]:
        return [cast(EnhancedCH, d) for d in self.scheduler.devices.values() if d.role == dv.CH]

    def cms(self) -> list[EnhancedCM]:
        return [cast(EnhancedCM, d) for d in self.scheduler.devices.values() if d.role == dv.CM]

    def members_of(self, ch_id: str) -> list[EnhancedCM]:
        cluster = self.bs().registry[ch_id].cluster
        return [cm for cm in self.cms() if self.bs().registry.get(cm.identity) is not None
                and self.bs().registry[cm.identity].cluster == cluster]

    def _command(self, ident: str, method: str, *args: Any) -> StepResult:
        with self.context():
            return self.scheduler.command(ident, method, *args)

    def run(self, max_steps: int = 20_000, should_stop: Callable[[], bool] | None = None) -> list[StepResult]:
        with self.context():
            return self.scheduler.run_until_quiescent(max_steps, should_stop)

    def step(self, n: int = 1) -> list[StepResult]:
        with self.context():
            return self.scheduler.run_steps(n)

    # -- operator workflows -------------------------------------------------------------------

    def start_onboarding(self) -> list[StepResult]:
        """§4.6.5: each active CH starts its CH-BS AKE; the rest of the sequence is event-driven."""
        return [self._command(ch.identity, "start_onboarding") for ch in self.chs() if ch.status != dv.REVOKED]

    def onboard(self, max_steps: int = 20_000) -> list[StepResult]:
        return self.start_onboarding() + self.run(max_steps)

    def send_reading(self, cm_id: str, value: str) -> StepResult:
        result = self._command(cm_id, "send_reading", value)
        if result.verdict != "REJECT" and self.designation_state(cm_id) == CH_REVOKED:
            self.undelivered[cm_id] = self.undelivered.get(cm_id, 0) + 1
        return result

    def rekey(self, ident: str, peer: str | None = None) -> list[StepResult]:
        """FR-08: a CH rekeys its CH-BS session and every member's sessions (cluster rekey);
        a CM rekeys its own sessions; a pair (CM, CH|BS) rekeys just that session."""
        dev = self.device(ident)
        if peer is not None:
            if dev.role != dv.CM and self.device(peer).role == dv.CM:
                ident, peer, dev = peer, ident, self.device(peer)
            purpose = {dv.BS: m.CM_BS, dv.CH: m.CM_CH}[self.device(peer).role] if dev.role == dv.CM else m.CH_BS
            via = cast(EnhancedCM, dev).relay_ch if purpose == m.CM_BS else None
            return [self._command(ident, "start_ake", peer, purpose, via)]
        out = [self._command(ident, "rekey")]
        if dev.role == dv.CH:
            out += [self._command(cm.identity, "rekey") for cm in self.members_of(ident)
                    if cm.status != dv.REVOKED]
        return out

    def revoke(self, ident: str) -> StepResult:
        result = self._command(self.bs_id, "revoke", ident)
        if result.verdict != "REJECT":
            self.device(ident).set_status(dv.REVOKED)  # bookkeeping: the device itself is not told
        return result

    def provision_device(self, ident: str, role: str, cluster: str, member_config: list[str] | None = None) -> None:
        """FR-02/FR-10: the BS computes Pr for a new identity; the factory loads it (C1)."""
        bs = self.bs()
        if ident in bs.registry or ident in self.scheduler.devices:
            raise ValueError(f"identity {ident} already exists (a revoked identity is never reused)")
        with self.context():
            bs.register(ident, role, cluster)
        self.load_device(ident, role, cluster, member_config or [])

    def load_device(self, ident: str, role: str, cluster: str, member_config: list[str]) -> None:
        """Factory provisioning of a registered identity: only Pr_i reaches the device (C1)."""
        with self.context():
            ks = Keystore(ident)
            ks.put("pr", self.bs().provision_key(ident), SecretClass.SECRET)
            self.scheduler.add_device(_make_device(ident, role, cluster, ks, self.source.spawn(ident), self.cfg,
                                                   member_config))

    def reprovision(self, old: str, new: str) -> list[StepResult]:
        """FR-10: a revoked device comes back under a new identity; the old one stays revoked."""
        bs = self.bs()
        reg = bs.registry.get(old)
        if reg is None or reg.status != REVOKED:
            raise ValueError(f"{old} is not revoked")
        if reg.role == dv.CM:
            self.provision_device(new, dv.CM, cast(str, reg.cluster))
            ch_id = bs.cluster_ch.get(cast(str, reg.cluster))
            cast(EnhancedCM, self.device(new)).relay_ch = ch_id
            if ch_id is None:
                return []
            ch = cast(EnhancedCH, self.device(ch_id))
            ch.member_config = [x for x in ch.member_config if x != old] + [new]
            return [self._command(ch_id, "refresh_grant")]
        members = [cm.identity for cm in self.cms() if bs.registry[cm.identity].cluster == reg.cluster
                   and bs.registry[cm.identity].status != REVOKED]
        self.provision_device(new, dv.CH, cast(str, reg.cluster), members)
        return self.designate(cast(str, reg.cluster), new)

    def designate(self, cluster: str, ch_id: str) -> list[StepResult]:
        """FR-03: designate an existing CH (provision it first with provision_device)."""
        out = [self._command(self.bs_id, "designate", cluster, ch_id)]
        out.append(self._command(ch_id, "start_onboarding"))
        return out

    # -- recovery (§4.8) ---------------------------------------------------------------------

    def recover(self) -> None:
        """No session survives an interruption: in-flight frames dropped, every session ABORTED,
        session keys destroyed, active devices revert to registered."""
        self.scheduler.bus.flush()
        self.scheduler._timers.clear()
        for d in self.scheduler.devices.values():
            dev = cast(EnhancedDevice, d)
            dev.abort_all_sessions()
            if dev.status in (dv.ACTIVE, dv.AUTHENTICATED) and dev.role != dv.BS:
                dev.set_status(dv.REGISTERED)
            if isinstance(dev, EnhancedCH):
                dev.grant.clear()
            if isinstance(dev, EnhancedCM):
                dev.designated = None
            if isinstance(dev, EnhancedBS):
                dev.grants.clear()

    # -- read-only views for the console (public metadata only) -------------------------------

    def device_epoch(self, ident: str) -> int:
        reg = self.bs().registry.get(ident)
        return reg.epoch if reg is not None else 0

    def designation(self, ident: str) -> str | None:
        """The CH a CM currently treats as designated (None for other roles or before designation)."""
        dev = self.scheduler.devices.get(ident)
        return dev.designated if isinstance(dev, EnhancedCM) else None

    def designation_state(self, ident: str) -> str | None:
        """D2: a CM whose designated CH has been revoked keeps its sessions and PSK with that CH --
        it is not told -- until the replacement CH relays a new DESIGNATION. Until then its
        readings cannot reach the BS."""
        ch = self.designation(ident)
        if ch is None:
            return None
        reg = self.bs().registry.get(ch)
        return CH_REVOKED if reg is not None and reg.status == REVOKED else "ok"

    def undelivered_readings(self, ident: str) -> int:
        return self.undelivered.get(ident, 0)

    def readings(self) -> list[dict[str, Any]]:
        return list(self.bs().readings)

    def session_infos(self) -> list[dict[str, Any]]:
        """One row per handshake, from the initiator's view, with the responder's state when the
        two differ (e.g. HS3 lost: ESTABLISHED/FAILED). The epoch is the larger of the two sides':
        each side stamps the registry epoch it knows at establishment (D4), and a CM may not yet
        have heard of a newer one when its CM-CH session completes (follow-up F1)."""
        rows: dict[str, dict[str, Any]] = {}
        resp: dict[str, str] = {}
        resp_epoch: dict[str, int] = {}
        for d in self.scheduler.devices.values():
            for s in cast(EnhancedDevice, d).sessions.values():
                if s.role == st.RESPONDER:
                    resp[s.sid_hex] = s.state
                    resp_epoch[s.sid_hex] = s.epoch
                    rows.setdefault(s.sid_hex, _row(s.peer, d.identity, s))
        for d in self.scheduler.devices.values():
            for s in cast(EnhancedDevice, d).sessions.values():
                if s.role == st.INITIATOR:
                    rows[s.sid_hex] = _row(d.identity, s.peer, s)
        for sid, row in rows.items():
            r = resp.get(sid)
            if r is not None and r != row["state"]:
                row["state"] = f"{row['state']}/{r}"
            row["epoch"] = max(row["epoch"], resp_epoch.get(sid, 0))
        return list(rows.values()) + list(self.aborted_sessions)


CH_REVOKED = "ch_revoked_awaiting_redesignation"


def _row(a: str, b: str, s: st.Session) -> dict[str, Any]:
    return {"a": a, "b": b, "purpose": s.purpose, "state": s.state, "sid_hex": s.sid_hex,
            "established_step": s.established_step, "epoch": s.epoch, "sent": s.sent, "recv": s.recv,
            "superseded_by": s.superseded_by}


def _make_device(ident: str, role: str, cluster: str | None, ks: Keystore, source: rng.RandomSource,
                 cfg: EnhancedConfig, member_config: list[str]) -> EnhancedDevice:
    if role == dv.CH:
        return EnhancedCH(ident, cluster, ks, source, cfg, member_config=member_config)
    if role == dv.CM:
        return EnhancedCM(ident, cluster, ks, source, cfg, deployed_ch=cast(str, cluster))
    raise ValueError(f"cannot provision a device with role {role}")


def build(params_name: str, topology: str | dict[str, object], *, kind: str = LAB, seed: int | None = None,
          tunables: Tunables | None = None, check_invariant: bool = True) -> EnhancedNetwork:
    """Creates and provisions a MAKA-E network. Product networks pass kind=PRODUCT (their bus
    refuses adversaries) and no seed (system randomness)."""
    pset = params.get(params_name)
    topo = fixtures.topology(topology) if isinstance(topology, str) else topology
    chs = cast(dict[str, list[str]], topo["chs"])
    tun = tunables or Tunables()
    n_devices = 1 + sum(1 + len(c) for c in chs.values())
    cfg = EnhancedConfig(curve=pset.curve, g=pset.g, id_bs=str(topo["bs"]), max_pending=tun.max_pending,
                         t_hs=effective_t_hs(tun.t_hs, n_devices), t_retry=tun.t_retry,
                         batch_steps=tun.batch_steps, batch_max=tun.batch_max,
                         grant_refresh_steps=tun.grant_refresh_steps)
    source: rng.RandomSource = rng.Rng(seed=seed) if seed is not None else rng.SystemSource()
    net = EnhancedNetwork(scheduler=Scheduler(Bus(kind=kind)), cfg=cfg, params_name=params_name, source=source)
    with net.context():
        bs = EnhancedBS(cfg.id_bs, None, new_bs_keystore(cfg.id_bs, pset.curve, source), source.spawn(cfg.id_bs), cfg)
        net.scheduler.add_device(bs)
        for ch_id, cms in chs.items():
            bs.register(ch_id, dv.CH, ch_id)
            for cm_id in cms:
                bs.register(cm_id, dv.CM, ch_id)
    for ch_id, cms in chs.items():
        net.load_device(ch_id, dv.CH, ch_id, list(cms))
        for cm_id in cms:
            net.load_device(cm_id, dv.CM, ch_id, [])
    if check_invariant:
        net.scheduler.hooks.append(lambda _r: check_master_key_invariant(net.scheduler.devices.values(), net.bs_id))
    return net


@dataclass(frozen=True)
class DeviceSpec:
    """A device as persisted by the console (role, cluster, registry status and epoch)."""

    ident: str
    role: str
    cluster: str | None
    status: str
    epoch: int


def restore(params_name: str, bs_id: str, specs: list[DeviceSpec],
            keystores: dict[str, dict[str, tuple[SecretClass, bytes]]], *, kind: str = LAB,
            source: rng.RandomSource | None = None, tunables: Tunables | None = None,
            aborted_sessions: list[dict[str, Any]] | None = None) -> EnhancedNetwork:
    """Rebuilds a network after a restart or a failed job (§4.8): long-term keys from the
    encrypted keystore, registry from the device rows, no sessions (all ABORTED), devices that
    were active revert to registered. Grants and designations are re-established by onboarding."""
    pset = params.get(params_name)
    tun = tunables or Tunables()
    cfg = EnhancedConfig(curve=pset.curve, g=pset.g, id_bs=bs_id, max_pending=tun.max_pending,
                         t_hs=effective_t_hs(tun.t_hs, len(specs)), t_retry=tun.t_retry,
                         batch_steps=tun.batch_steps, batch_max=tun.batch_max,
                         grant_refresh_steps=tun.grant_refresh_steps)
    src = source or rng.SystemSource()
    net = EnhancedNetwork(scheduler=Scheduler(Bus(kind=kind)), cfg=cfg, params_name=params_name, source=src,
                          aborted_sessions=list(aborted_sessions or []))

    def keystore(ident: str) -> Keystore:
        ks = Keystore(ident)
        ks.load_raw(keystores.get(ident, {}))
        return ks

    bs = EnhancedBS(bs_id, None, keystore(bs_id), src.spawn(bs_id), cfg)
    net.scheduler.add_device(bs)
    for spec in specs:
        if spec.role == dv.BS:
            continue
        bs.register(spec.ident, spec.role, spec.cluster)
        reg = bs.registry[spec.ident]
        reg.epoch = spec.epoch
        if spec.status == dv.REVOKED:
            reg.status = REVOKED
        bs.epoch = max(bs.epoch, spec.epoch)
    for c in {s.cluster for s in specs if s.role == dv.CH and s.cluster}:
        live = [s.ident for s in specs if s.role == dv.CH and s.cluster == c and s.status != dv.REVOKED]
        bs.cluster_ch[c] = live[-1] if live else None
    for spec in specs:
        if spec.role == dv.BS:
            continue
        members = [s.ident for s in specs if s.role == dv.CM and s.cluster == spec.cluster and s.status != dv.REVOKED]
        dev = _make_device(spec.ident, spec.role, spec.cluster, keystore(spec.ident), src.spawn(spec.ident), cfg,
                           members if spec.role == dv.CH else [])
        if spec.role == dv.CM and spec.cluster is not None:
            cast(EnhancedCM, dev).relay_ch = bs.cluster_ch.get(spec.cluster)
        if spec.status == dv.REVOKED:
            dev.set_status(dv.REVOKED)
        elif spec.status != dv.PROVISIONED:
            dev.set_status(dv.REGISTERED)
        net.scheduler.add_device(dev)
    net.scheduler.hooks.append(lambda _r: check_master_key_invariant(net.scheduler.devices.values(), net.bs_id))
    return net
