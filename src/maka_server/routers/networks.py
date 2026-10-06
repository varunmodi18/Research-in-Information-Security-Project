"""Networks, devices, frames, readings, jobs and the live stream (IMPLEMENTATION_PLAN.md §4.5)."""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from maka_server import models
from maka_server.context import AppContext
from maka_server.deps import Principal, admin, get_ctx, get_db, operator, viewer
from maka_server.errors import ApiError, not_found
from maka_server.schemas import (
    SECURITY_LEVELS,
    CheckOut,
    DeviceDetail,
    FrameOut,
    JobAccepted,
    JobCreate,
    NetworkCreate,
    NetworkDelete,
    NetworkDetail,
    NetworkOut,
    Page,
    ReadingOut,
    SessionOut,
    devices_out,
)
from maka_server.services import networks as svc
from maka_server.services.jobrules import check_job_allowed

router = APIRouter(prefix="/networks", tags=["networks"])


def _network_out(db: Session, net: models.Network) -> NetworkOut:
    devices = list(db.scalars(select(models.Device).where(models.Device.network_id == net.id)))
    return NetworkOut(id=net.id, name=net.name, kind=net.kind, mode=net.mode, params=net.params,
                      security_level=SECURITY_LEVELS[net.params], template=net.template, seed=net.seed,
                      status=net.status, step=net.step, created_at=net.created_at,
                      status_counts=dict(Counter(d.status for d in devices)), device_count=len(devices),
                      options=dict(net.options_json))


def _get_network(db: Session, network_id: int) -> models.Network:
    net = db.get(models.Network, network_id)
    if net is None:
        raise not_found(f"network {network_id}")
    return net


@router.get("", response_model=list[NetworkOut])
def list_networks(_: Principal = Depends(viewer), db: Session = Depends(get_db)) -> list[NetworkOut]:
    return [_network_out(db, n) for n in db.scalars(select(models.Network).order_by(models.Network.id))]


@router.post("", response_model=NetworkDetail, status_code=201)
def create_network(body: NetworkCreate, _: Principal = Depends(operator),
                   ctx: AppContext = Depends(get_ctx)) -> NetworkDetail:
    network_id = svc.create_network(ctx, body)
    with ctx.db.session() as db:
        return _detail(ctx, db, _get_network(db, network_id))


def _detail(ctx: AppContext, db: Session, net: models.Network) -> NetworkDetail:
    devices = list(db.scalars(select(models.Device).where(models.Device.network_id == net.id)
                              .order_by(models.Device.id)))
    s = ctx.settings
    return NetworkDetail(**_network_out(db, net).model_dump(),
                         devices=devices_out(devices),
                         tunables={"MAX_PENDING": s.max_pending, "T_HS": s.t_hs, "T_RETRY": s.t_retry,
                                   "BATCH_STEPS": s.batch_steps, "BATCH_MAX": s.batch_max})


@router.get("/{network_id}", response_model=NetworkDetail)
def get_network(network_id: int, _: Principal = Depends(viewer), ctx: AppContext = Depends(get_ctx),
                db: Session = Depends(get_db)) -> NetworkDetail:
    return _detail(ctx, db, _get_network(db, network_id))


@router.delete("/{network_id}", status_code=204)
def delete_network(network_id: int, body: NetworkDelete, _: Principal = Depends(admin),
                   ctx: AppContext = Depends(get_ctx)) -> None:
    with ctx.db.session() as db:
        net = _get_network(db, network_id)
        if body.confirm_name != net.name:
            raise ApiError(422, "CONFIRMATION_MISMATCH", "Confirmation does not match",
                           "type the network's exact name to delete it")
        if net.status == "busy":
            raise ApiError(409, "NETWORK_BUSY", "Network busy", "wait for the running job to finish")
        db.execute(delete(models.Job).where(models.Job.network_id == network_id))
        db.delete(net)
    ctx.jobs.periodic.pop(network_id, None)
    ctx.registry.drop(network_id)
    ctx.broker.forget(network_id)


@router.post("/{network_id}/jobs", response_model=JobAccepted, status_code=202)
def submit_job(network_id: int, body: JobCreate, principal: Principal = Depends(operator),
               ctx: AppContext = Depends(get_ctx)) -> JobAccepted:
    with ctx.db.session() as db:
        net = _get_network(db, network_id)
        check_job_allowed(net, body.type, principal.role)
    job, created = ctx.jobs.submit(network_id, body.type, body.args, body.idempotency_key, principal.user_id)
    return JobAccepted(job_id=job.id, created=created)


@router.get("/{network_id}/devices/{ident}", response_model=DeviceDetail)
def get_device(network_id: int, ident: str, _: Principal = Depends(viewer),
               db: Session = Depends(get_db)) -> DeviceDetail:
    _get_network(db, network_id)
    dev = db.scalar(select(models.Device).where(models.Device.network_id == network_id,
                                                models.Device.ident == ident))
    if dev is None:
        raise not_found(f"device {ident}")
    sessions = db.scalars(select(models.ProtocolSession).where(
        models.ProtocolSession.network_id == network_id,
        (models.ProtocolSession.a == ident) | (models.ProtocolSession.b == ident)))
    designated = [dev] + list(db.scalars(select(models.Device).where(
        models.Device.network_id == network_id, models.Device.ident == dev.designated))) if dev.designated else [dev]
    return DeviceDetail(device=devices_out(designated)[0],
                        sessions=[SessionOut.model_validate(s) for s in sessions],
                        status_history=list(dev.status_history))


@router.get("/{network_id}/frames", response_model=Page[FrameOut])
def list_frames(network_id: int, label: str | None = None, src: str | None = None, dst: str | None = None,
                verdict: str | None = None, after_step: int | None = None, job: int | None = None,
                run_tag: str | None = None, cursor: int | None = None, limit: int = Query(default=200, ge=1, le=1000),
                _: Principal = Depends(viewer), db: Session = Depends(get_db)) -> Page[FrameOut]:
    _get_network(db, network_id)
    q = select(models.FrameRow).where(models.FrameRow.network_id == network_id)
    if label:
        q = q.where(models.FrameRow.label == label)
    if src:
        q = q.where(models.FrameRow.src == src)
    if dst:
        q = q.where((models.FrameRow.dst == dst) | (models.FrameRow.to == dst))
    if verdict:
        q = q.where(models.FrameRow.verdict == verdict)
    if after_step is not None:
        q = q.where(models.FrameRow.step > after_step)
    if job is not None:
        q = q.where(models.FrameRow.job_id == job)
    q = q.where(models.FrameRow.run_tag == run_tag) if run_tag else q.where(models.FrameRow.run_tag.is_(None))
    if cursor is not None:
        q = q.where(models.FrameRow.id > cursor)
    rows = list(db.scalars(q.order_by(models.FrameRow.id).limit(limit + 1)))
    items = [FrameOut(id=r.id, frame_id=r.frame_id, job_id=r.job_id, step=r.step, sent_step=r.sent_step,
                      src=r.src, dst=r.dst, to=r.to, label=r.label, bytes_len=r.bytes_len,
                      paper_bits=r.paper_bits, payload_hex=r.payload.hex() if r.payload is not None else None,
                      verdict=r.verdict, reason=r.reason, fate=r.fate, run_tag=r.run_tag,
                      checks=[CheckOut(**c) for c in r.checks_json]) for r in rows[:limit]]
    return Page[FrameOut](items=items, next_cursor=rows[limit - 1].id if len(rows) > limit else None)


@router.get("/{network_id}/readings", response_model=Page[ReadingOut])
def list_readings(network_id: int, device: str | None = None, cursor: int | None = None,
                  limit: int = Query(default=200, ge=1, le=1000), _: Principal = Depends(operator),
                  db: Session = Depends(get_db)) -> Page[ReadingOut]:
    """FR-07: decrypted readings at the BS -- Operator and Admin only (V-WEB-08)."""
    _get_network(db, network_id)
    q = select(models.Reading).where(models.Reading.network_id == network_id)
    if device:
        q = q.where(models.Reading.device == device)
    if cursor is not None:
        q = q.where(models.Reading.id > cursor)
    rows = list(db.scalars(q.order_by(models.Reading.id).limit(limit + 1)))
    items = [ReadingOut(id=r.id, device=r.device, seq=r.seq, value=r.value_json.get("value"),
                        received_step=r.received_step) for r in rows[:limit]]
    return Page[ReadingOut](items=items, next_cursor=rows[limit - 1].id if len(rows) > limit else None)


@router.get("/{network_id}/stream")
async def stream(network_id: int, request: Request, last_event_id: int | None = None, once: bool = False,
                 _: Principal = Depends(viewer), ctx: AppContext = Depends(get_ctx)) -> StreamingResponse:
    """SSE: frame, security_event, device_status, job_progress. Resumes after Last-Event-ID.
    `once=true` returns the buffered events and closes (used by tests and polling clients)."""
    with ctx.db.session() as db:
        _get_network(db, network_id)
    header = request.headers.get("last-event-id")
    start = int(header) if header and header.isdigit() else (last_event_id or 0)

    async def events() -> AsyncIterator[str]:
        last = start
        idle = 0.0
        yield "retry: 2000\n\n"
        while True:
            batch = ctx.broker.since(network_id, last)
            for e in batch:
                last = e.id
                yield e.encode()
            if once:
                return
            if await request.is_disconnected():
                return
            await asyncio.sleep(0.25)
            idle = 0.0 if batch else idle + 0.25
            if idle >= 15:
                idle = 0.0
                yield ": keep-alive\n\n"

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
