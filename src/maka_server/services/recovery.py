"""Operator-approved cluster-head replacement (docs/RECOVERY.md, IA-20, IA-21).

- `status`: per live cluster head, the behaviour monitor's last flags, the "CH suspected" alert and
  the ranked replacement candidates. Read-only; viewers may see it.
- `recover_cluster` job (operator): promote the member the operator confirmed (`EnhancedNetwork.promote`).
- `inject_fault` job (lab networks only): make a CH forward only part of its members' readings, so the
  alert can be demonstrated. The fault lives in memory only; a restart removes it.
"""

from __future__ import annotations

from typing import Any, cast

from maka.behaviour.traffic import LossyForwardingCH
from maka.enhanced.lifecycle import EnhancedCH
from maka.enhanced.network import EnhancedNetwork
from maka.recovery import controller, monitor
from maka.runtime import device as dv
from maka_server.errors import ApiError
from maka_server.jobs import JobContext, handler
from maka_server.services.enhanced_jobs import _device, _enhanced, _ident
from maka_server.services.networks import run_to_quiescence, runtime_for
from maka_server.services.runtime import NetworkRuntime

LOCK_TIMEOUT_S = 5.0


def status(rt: NetworkRuntime) -> dict[str, Any]:
    if rt.net.mode != "enhanced":
        return {"available": False, "reason": "cluster-head replacement is a MAKA-E operation; RP9 has no revocation (OB-05)"}
    if not rt.lock.acquire(timeout=LOCK_TIMEOUT_S):
        raise ApiError(409, "NETWORK_BUSY", "Network busy", "a job is running; try again when it has finished")
    try:
        net = cast(EnhancedNetwork, rt.net)
        cfg = controller.RecoveryConfig()
        clusters = controller.assess(net, rt.monitor_start, cfg)
        step = int(net.scheduler.step_no)
    finally:
        rt.lock.release()
    return {"available": True, "step": step, "monitor_start": rt.monitor_start,
            "windows_scored": max(0, (step - rt.monitor_start) // cfg.window), "window": cfg.window,
            "trigger": f"flagged in {cfg.flag_windows} of the last {cfg.of_last} windows",
            "trigger_detector": monitor.Z_BASELINE, "trust_detector": monitor.trust_scorer().name,
            "clusters": [c.as_dict() for c in clusters]}


PRECHECKED = {"recover_cluster", "inject_fault"}


def _check_promotion(net: EnhancedNetwork, cluster: str, member: str) -> None:
    if cluster not in net.bs().cluster_ch:
        raise ApiError(404, "NOT_FOUND", "Not found", f"cluster {cluster} does not exist")
    _device(net, member)
    dev, reg = net.device(member), net.bs().registry.get(member)
    if dev.role != dv.CM or dev.status != dv.ACTIVE or reg is None or reg.cluster != cluster or reg.status == "revoked":
        raise ApiError(422, "VALIDATION_FAILED", "Cannot promote",
                       f"{member} is not an active, non-revoked member of cluster {cluster}")


def _check_fault(rt: NetworkRuntime, net: EnhancedNetwork, ident: str, fraction: float) -> None:
    if rt.kind != "lab":
        raise ApiError(422, "MODE_NOT_ALLOWED", "Lab only", "faults are injected only on lab networks")
    if not 0.0 <= fraction < 1.0:
        raise ApiError(422, "VALIDATION_FAILED", "Bad fraction", "forward_fraction must be in [0, 1)")
    _device(net, ident)
    dev = net.device(ident)
    if dev.role != dv.CH or dev.status != dv.ACTIVE:
        raise ApiError(422, "VALIDATION_FAILED", "Not an active cluster head", f"{ident} is not an active CH")


def precheck(rt: NetworkRuntime, job_type: str, args: dict[str, Any]) -> None:
    """Validates at submission, so an operator's mistake is a 422 and not a failed job (a failed job
    applies the §4.8 recovery rule to the whole network). The job validates again when it runs."""
    net = _enhanced(rt, "cluster-head replacement" if job_type == "recover_cluster" else "fault injection")
    if not rt.lock.acquire(timeout=LOCK_TIMEOUT_S):
        raise ApiError(409, "NETWORK_BUSY", "Network busy", "a job is running; try again when it has finished")
    try:
        if job_type == "recover_cluster":
            _check_promotion(net, _ident(args.get("cluster"), "cluster"), _ident(args.get("member"), "member"))
        else:
            _check_fault(rt, net, _ident(args.get("device"), "device"), float(args.get("forward_fraction", 0.7)))
    finally:
        rt.lock.release()


@handler("recover_cluster")
def job_recover_cluster(ctx: JobContext) -> dict[str, Any]:
    """Promote the confirmed member of `cluster` to cluster head (the BS revokes the current one)."""
    rt = runtime_for(ctx)
    net = _enhanced(rt, "cluster-head replacement")
    cluster = _ident(ctx.args.get("cluster"), "cluster")
    member = _ident(ctx.args.get("member"), "member")
    with rt.lock:
        _check_promotion(net, cluster, member)
        replaced = net.bs().cluster_ch.get(cluster)
        try:
            net.promote(cluster, member)
        except ValueError as exc:
            raise ApiError(422, "VALIDATION_FAILED", "Cannot promote", str(exc)) from exc
        steps = run_to_quiescence(ctx, rt, "cluster-head replacement")
        rt.monitor_start = rt.scheduler.step_no
        members = controller.candidates_of(net, cluster)
    return {"cluster": cluster, "promoted": member, "replaced": replaced, "steps": steps,
            "members_active": members, "statuses": rt.device_statuses()}


@handler("inject_fault")
def job_inject_fault(ctx: JobContext) -> dict[str, Any]:
    """Lab only: the CH forwards only `forward_fraction` of its members' readings (lossy forwarding)."""
    rt = runtime_for(ctx)
    net = _enhanced(rt, "fault injection")
    ident = _ident(ctx.args.get("device"), "device")
    fraction = float(ctx.args.get("forward_fraction", 0.7))
    with rt.lock:
        _check_fault(rt, net, ident, fraction)
        LossyForwardingCH.convert(cast(EnhancedCH, net.device(ident)), fraction, fault_seed=rt.network_id)
    return {"device": ident, "fault": "lossy_forwarding", "forward_fraction": fraction}
