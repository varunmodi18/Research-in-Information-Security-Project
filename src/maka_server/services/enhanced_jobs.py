"""Job handlers for the key lifecycle and periodic readings (FR-06, FR-08..FR-10, FR-03).

Revocation, reprovisioning and designation are MAKA-E operations: RP9 has no revocation
(OB-05), so on original-mode networks they are refused with MODE_NOT_ALLOWED.
"""

from __future__ import annotations

from typing import Any, cast

from sqlalchemy import delete

from maka import codec, fixtures
from maka.enhanced.network import EnhancedNetwork
from maka.runtime.errors import UnknownDevice
from maka_server import models
from maka_server.errors import ApiError
from maka_server.jobs import JobContext, handler
from maka_server.services.networks import (
    TEMPLATES,
    _add_devices,
    cms_of,
    run_to_quiescence,
    runtime_for,
)
from maka_server.services.runtime import NetworkRuntime


def _enhanced(rt: NetworkRuntime, what: str) -> EnhancedNetwork:
    if rt.net.mode != "enhanced":
        raise ApiError(422, "MODE_NOT_ALLOWED", "Not available in RP9 mode",
                       f"{what} is not part of RP9's protocol (OB-05); use a MAKA-E network")
    return cast(EnhancedNetwork, rt.net)


def _ident(value: Any, what: str) -> str:
    try:
        return codec.dec_id(codec.enc_id(str(value)))
    except ValueError as exc:
        raise ApiError(422, "VALIDATION_FAILED", f"Bad {what}", str(exc)) from exc


def _device(net: EnhancedNetwork, ident: str) -> None:
    try:
        net.device(ident)
    except UnknownDevice as exc:
        raise ApiError(404, "NOT_FOUND", "Not found", f"device {ident} does not exist") from exc


@handler("rekey")
def job_rekey(ctx: JobContext) -> dict[str, Any]:
    """FR-08: rekey a device (a CH rekeys its whole cluster) or one pair."""
    rt = runtime_for(ctx)
    net = _enhanced(rt, "rekey")
    ident = _ident(ctx.args.get("device"), "device")
    peer = _ident(ctx.args["peer"], "peer") if ctx.args.get("peer") else None
    with rt.lock:
        _device(net, ident)
        if net.device(ident).status == "revoked":
            raise ApiError(422, "REVOKED_IDENTITY", "Device revoked", f"{ident} is revoked")
        net.rekey(ident, peer)
        steps = run_to_quiescence(ctx, rt, "rekey")
    return {"steps": steps}


@handler("revoke")
def job_revoke(ctx: JobContext) -> dict[str, Any]:
    """FR-09: revoke a device; the BS notifies its CH (all CHs for a CH) and sessions end."""
    rt = runtime_for(ctx)
    net = _enhanced(rt, "revocation")
    ident = _ident(ctx.args.get("device"), "device")
    with rt.lock:
        _device(net, ident)
        if ident == net.bs_id:
            raise ApiError(422, "VALIDATION_FAILED", "Refused", "the base station cannot be revoked")
        result = net.revoke(ident)
        if result.verdict == "REJECT":
            raise ApiError(422, "REVOKED_IDENTITY", "Already revoked", f"{ident} is already revoked")
        steps = run_to_quiescence(ctx, rt, "revocation")
    return {"revoked": ident, "steps": steps}


@handler("reprovision")
def job_reprovision(ctx: JobContext) -> dict[str, Any]:
    """FR-10: a revoked device rejoins under a new identity; the old one stays revoked."""
    rt = runtime_for(ctx)
    net = _enhanced(rt, "reprovisioning")
    old = _ident(ctx.args.get("device"), "device")
    new = _ident(ctx.args.get("new_ident"), "new identity")
    with rt.lock:
        _device(net, old)
        if new in net.scheduler.devices or new in net.bs().registry:
            raise ApiError(422, "REVOKED_IDENTITY", "Identity in use",
                           f"{new} already exists; a revoked identity is never reactivated")
        try:
            net.reprovision(old, new)
        except ValueError as exc:
            raise ApiError(422, "VALIDATION_FAILED", "Cannot reprovision", str(exc)) from exc
        steps = run_to_quiescence(ctx, rt, "reprovisioning")
    return {"old": old, "new": new, "steps": steps}


@handler("designate")
def job_designate(ctx: JobContext) -> dict[str, Any]:
    """FR-03: designate a cluster head (a new identity is provisioned as a CH first)."""
    rt = runtime_for(ctx)
    net = _enhanced(rt, "designation")
    cluster = _ident(ctx.args.get("cluster"), "cluster")
    ch = _ident(ctx.args.get("ch"), "cluster head")
    with rt.lock:
        bs = net.bs()
        if cluster not in bs.cluster_ch:
            raise ApiError(404, "NOT_FOUND", "Not found", f"cluster {cluster} does not exist")
        if ch not in net.scheduler.devices:
            members = [cm.identity for cm in net.cms() if bs.registry[cm.identity].cluster == cluster
                       and bs.registry[cm.identity].status != "revoked"]
            net.provision_device(ch, "CH", cluster, members)
        net.designate(cluster, ch)
        steps = run_to_quiescence(ctx, rt, "designation")
    return {"cluster": cluster, "ch": ch, "steps": steps}


@handler("reset_network")
def job_reset(ctx: JobContext) -> dict[str, Any]:
    """Re-provisions the network from its template (new master key); history is kept."""
    nid = ctx.network_id
    if nid is None:
        raise ApiError(422, "VALIDATION_FAILED", "Network required", "reset_network needs a network")
    ctx.app.jobs.periodic.pop(nid, None)
    ctx.app.registry.drop(nid)
    with ctx.app.db.session() as db:
        net = db.get(models.Network, nid)
        if net is None:
            raise ApiError(404, "NOT_FOUND", "Not found", f"network {nid}")
        db.execute(delete(models.ProtocolSession).where(models.ProtocolSession.network_id == nid))
        db.execute(delete(models.Device).where(models.Device.network_id == nid))
        chs, cms = (TEMPLATES[net.template] if net.template in TEMPLATES
                    else map(int, net.template.removeprefix("custom-").split("x")))
        _add_devices(db, net, fixtures.custom(chs, cms))
        net.options_json = {k: v for k, v in net.options_json.items() if k != "restores"}
    rt = ctx.app.registry.get(nid)
    return {"devices": len(rt.scheduler.devices)}


@handler("start_periodic")
def job_start_periodic(ctx: JobContext) -> dict[str, Any]:
    """FR-06: one simulated reading per selected CM every `every_steps` scheduler steps, until
    stop_periodic. Ticks run in the network's worker between jobs, so jobs still interleave."""
    rt = runtime_for(ctx)
    every = int(ctx.args.get("every_steps", 20))
    if not 5 <= every <= 1000:
        raise ApiError(422, "VALIDATION_FAILED", "Bad interval", "every_steps must be 5-1000")
    cms = cms_of(rt, ctx.args.get("devices"))
    assert ctx.network_id is not None  # type narrowing only
    ctx.app.jobs.periodic[ctx.network_id] = {"devices": cms, "every_steps": every, "tick": 0}
    return {"periodic": True, "devices": cms, "every_steps": every}


@handler("stop_periodic")
def job_stop_periodic(ctx: JobContext) -> dict[str, Any]:
    assert ctx.network_id is not None  # type narrowing only
    return {"periodic": ctx.app.jobs.periodic.pop(ctx.network_id, None) is not None}

