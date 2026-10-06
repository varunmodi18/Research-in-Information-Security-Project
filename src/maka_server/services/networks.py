"""Networks: creation, runtime builders, and the protocol job handlers (FR-01..FR-07).

Product networks run MAKA-E only; original (RP9) mode and adversaries exist only on lab
networks (NFR-SEC-03). Readings are simulated demo data, labelled as such (§3.2).
"""

from __future__ import annotations

import json
from typing import Any, cast

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from maka import fixtures
from maka.enhanced import network as en
from maka.original_rt import network as onet
from maka.rng import Rng, SystemSource
from maka.runtime.keystore import Keystore
from maka.runtime.scheduler import StepResult
from maka_server import models
from maka_server.context import AppContext
from maka_server.errors import ApiError
from maka_server.jobs import JobContext, handler
from maka_server.keystore_store import EncryptedKeystoreAdapter
from maka_server.schemas import NetworkCreate
from maka_server.services.runtime import NetworkRuntime, RuntimeNet, pu_fingerprint

TEMPLATES = {"paper": (1, 1), "small": (1, 3), "net": (3, 3)}
MAX_STEPS = 50_000


def mode_not_allowed(detail: str) -> ApiError:
    return ApiError(422, "MODE_NOT_ALLOWED", "Mode not allowed", detail)


# -- creation --------------------------------------------------------------------------

def create_network(ctx: AppContext, req: NetworkCreate) -> int:
    if req.kind == "product" and req.mode != "enhanced":
        raise mode_not_allowed("product networks run MAKA-E (enhanced) only; use a lab network for RP9")
    if req.kind == "product" and req.seed is not None and not ctx.settings.allow_seeded_product:
        raise mode_not_allowed("seeded product networks are not allowed when MAKA_ENV=demo")
    if req.mode not in ctx.registry.builders:
        raise mode_not_allowed(f"{req.mode} mode is not available in this build")
    if req.custom is not None:
        chs, cms = req.custom.chs, req.custom.cms_per_ch
        template = f"custom-{chs}x{cms}"
    else:
        chs, cms = TEMPLATES[req.template or "paper"]
        template = req.template or "paper"
    topo = fixtures.custom(chs, cms)
    options = {"secure_pseudo_ids": req.secure_pseudo_ids, "forward_ciphertexts": req.forward_ciphertexts}

    with ctx.db.session() as db:
        if db.scalar(select(models.Network).where(models.Network.name == req.name)) is not None:
            raise ApiError(409, "NAME_TAKEN", "Name taken", f"a network named {req.name!r} exists")
        net = models.Network(name=req.name, kind=req.kind, mode=req.mode, params=req.params,
                             template=template, seed=req.seed, status="idle", bs_device_id=str(topo["bs"]),
                             options_json=options)
        db.add(net)
        db.flush()
        _add_devices(db, net, topo)
        network_id = net.id
    ctx.registry.get(network_id)  # builds and provisions the runtime, persists the keystore
    return network_id


def _add_devices(db: Session, net: models.Network, topo: dict[str, object]) -> None:
    chs = cast(dict[str, list[str]], topo["chs"])
    rows: list[tuple[str, str, str | None]] = [(str(topo["bs"]), "BS", None)]
    for ch_id, cms in chs.items():
        rows.append((ch_id, "CH", ch_id))
        rows.extend((cm_id, "CM", ch_id) for cm_id in cms)
    for ident, role, cluster in rows:
        db.add(models.Device(network_id=net.id, ident=ident, role=role, cluster=cluster,
                             status="provisioned", pu_fingerprint=pu_fingerprint(net.params, ident),
                             status_history=[{"step": 0, "status": "provisioned"}]))


def topology_from_rows(row: models.Network, devices: list[models.Device]) -> dict[str, object]:
    chs: dict[str, list[str]] = {}
    for d in devices:
        if d.role == "CH":
            chs.setdefault(d.ident, [])
    for d in devices:
        if d.role == "CM" and d.cluster is not None and d.status != "revoked":
            chs.setdefault(d.cluster, []).append(d.ident)
    return {"bs": row.bs_device_id, "chs": chs}


def mirror_keystores(keystores: list[Keystore], adapter: EncryptedKeystoreAdapter) -> None:
    """Attaches the encrypted adapter and records the entries provisioning already wrote."""
    for ks in keystores:
        ks.attach(adapter)
        for name in ks.names():
            adapter.save(ks.device_id, name, ks.cls_of(name), ks.get(name))


def build_original(row: models.Network, devices: list[models.Device], adapter: EncryptedKeystoreAdapter,
                   db: Session) -> RuntimeNet:
    """RP9 has no recovery path, so a (re)build always re-provisions the lab network from
    scratch: fresh k (or the network's seed), every device back to `provisioned`."""
    db.execute(delete(models.KeystoreEntry).where(
        models.KeystoreEntry.device_id.in_([d.id for d in devices])))
    net = onet.build(row.params, topology_from_rows(row, devices), kind=row.kind, seed=row.seed,
                     secure_pseudo_ids=bool(row.options_json.get("secure_pseudo_ids", True)),
                     forward_ciphertexts=bool(row.options_json.get("forward_ciphertexts", False)))
    mirror_keystores([d.keystore for d in net.scheduler.devices.values()], adapter)
    return cast(RuntimeNet, net)


def make_enhanced_builder(ctx: AppContext):  # type: ignore[no-untyped-def]
    s = ctx.settings
    tunables = en.Tunables(max_pending=s.max_pending, t_hs=s.t_hs, t_retry=s.t_retry,
                           batch_steps=s.batch_steps, batch_max=s.batch_max,
                           grant_refresh_steps=s.grant_refresh_steps)

    def build_enhanced(row: models.Network, devices: list[models.Device], adapter: EncryptedKeystoreAdapter,
                       db: Session) -> RuntimeNet:
        """Fresh MAKA-E provisioning, or the §4.8 restore from the encrypted keystore."""
        dev_ids = [d.id for d in devices]
        has_keys = db.scalar(select(models.KeystoreEntry.id).where(
            models.KeystoreEntry.device_id.in_(dev_ids)).limit(1)) is not None
        if not has_keys:
            net = en.build(row.params, topology_from_rows(row, devices), kind=row.kind, seed=row.seed,
                           tunables=tunables)
            mirror_keystores([d.keystore for d in net.scheduler.devices.values()], adapter)
            return cast(RuntimeNet, net)
        restores = int(row.options_json.get("restores", 0)) + 1
        row.options_json = {**row.options_json, "restores": restores}
        source: SystemSource | Rng = (Rng(seed=row.seed).spawn(f"restore-{restores}") if row.seed is not None
                                      else SystemSource())
        aborted = [{"a": r.a, "b": r.b, "purpose": r.purpose, "state": "ABORTED", "sid_hex": r.sid_hex,
                    "established_step": r.established_step, "epoch": r.epoch, "sent": r.sent, "recv": r.recv,
                    "superseded_by": None}
                   for r in db.scalars(select(models.ProtocolSession).where(
                       models.ProtocolSession.network_id == row.id))
                   if r.state in ("ESTABLISHED", "SENT_HS1", "WAIT_HS3") or r.state.startswith("ESTABLISHED/")]
        net = en.restore(row.params, row.bs_device_id,
                         [en.DeviceSpec(d.ident, d.role, d.cluster, d.status, d.epoch) for d in devices],
                         {d.ident: adapter.load(db, d.id, d.ident) for d in devices}, kind=row.kind,
                         source=source, tunables=tunables, aborted_sessions=aborted)
        for d in net.scheduler.devices.values():
            d.keystore.attach(adapter)
        return cast(RuntimeNet, net)

    return build_enhanced


def register_builders(ctx: AppContext) -> None:
    ctx.registry.builders["original"] = build_original
    ctx.registry.builders["enhanced"] = make_enhanced_builder(ctx)


# -- job handlers ------------------------------------------------------------------------

def runtime_for(ctx: JobContext) -> NetworkRuntime:
    if ctx.network_id is None:
        raise ApiError(422, "VALIDATION_FAILED", "Network required", f"{ctx.type} needs a network")
    return ctx.app.registry.get(ctx.network_id)


def _fault_injection(ctx: JobContext, rt: NetworkRuntime) -> None:
    """MAKA_ENV=test only: raise inside the worker at a given step (V-REC-01)."""
    fail_at = ctx.args.get("_fail_at_step")
    if fail_at is None:
        return
    if ctx.app.settings.env != "test":
        raise ApiError(422, "VALIDATION_FAILED", "Not allowed", "_fail_at_step is a test-only argument")

    def boom(result: StepResult) -> None:
        if result.step >= int(fail_at):
            rt.scheduler.hooks.remove(boom)
            raise RuntimeError(f"injected worker failure at step {result.step}")
    rt.scheduler.hooks.append(boom)


def run_to_quiescence(ctx: JobContext, rt: NetworkRuntime, phase: str) -> int:
    devices = rt.scheduler.devices
    start = rt.scheduler.step_no

    def should_stop() -> bool:
        done = sum(1 for d in devices.values() if d.status in ("active", "revoked", "failed"))
        ctx.progress(done / max(1, len(devices)), f"{phase}: step {rt.scheduler.step_no}")
        return ctx.cancelled()

    rt.net.run(max_steps=MAX_STEPS, should_stop=should_stop)
    return int(rt.scheduler.step_no) - int(start)


@handler("onboard")
def job_onboard(ctx: JobContext) -> dict[str, Any]:
    """FR-04 (run) and FR-05 (step mode: issue the start commands only)."""
    rt = runtime_for(ctx)
    with rt.lock:
        _fault_injection(ctx, rt)
        rt.net.start_onboarding()
        if ctx.args.get("step_mode"):
            return {"mode": "step", "pending_frames": rt.scheduler.bus.pending()}
        steps = run_to_quiescence(ctx, rt, "onboarding")
        return {"steps": steps, "statuses": rt.device_statuses()}


@handler("step")
def job_step(ctx: JobContext) -> dict[str, Any]:
    """FR-05: advance `count` scheduler steps, or {"until": "quiescent"}."""
    rt = runtime_for(ctx)
    with rt.lock:
        if ctx.args.get("until") == "quiescent":
            steps = run_to_quiescence(ctx, rt, "run to end")
        else:
            count = int(ctx.args.get("count", 1))
            if not 1 <= count <= 1000:
                raise ApiError(422, "VALIDATION_FAILED", "Bad count", "count must be 1-1000")
            results = rt.net.step(count)  # type: ignore[attr-defined]
            steps = len(results)
        return {"steps": steps, "pending_frames": rt.scheduler.bus.pending(), "step": rt.scheduler.step_no}


def simulated_reading() -> str:
    """Demo data (§3.2): a generated temperature, labelled as simulated."""
    centi = 1500 + SystemSource().below(1500)
    return json.dumps({"kind": "simulated reading", "temperature_c": centi / 100})


def cms_of(rt: NetworkRuntime, wanted: Any) -> list[str]:
    cms = [i for i, d in rt.scheduler.devices.items() if d.role == "CM"]
    if wanted in (None, "all"):
        return cms
    unknown = [w for w in wanted if w not in cms]
    if unknown:
        raise ApiError(422, "VALIDATION_FAILED", "Unknown device", f"not cluster members: {unknown}")
    return list(wanted)


@handler("send_readings")
def job_send_readings(ctx: JobContext) -> dict[str, Any]:
    """FR-06: send `count` readings from each selected CM, then deliver them."""
    rt = runtime_for(ctx)
    count = int(ctx.args.get("count", 1))
    if not 1 <= count <= 50:
        raise ApiError(422, "VALIDATION_FAILED", "Bad count", "count must be 1-50")
    with rt.lock:
        sent = 0
        for _ in range(count):
            for cm in cms_of(rt, ctx.args.get("devices")):
                result = rt.net.send_reading(cm, simulated_reading())
                sent += 1 if result.emitted else 0
            run_to_quiescence(ctx, rt, "readings")
        return {"sent": sent, "step": rt.scheduler.step_no}
