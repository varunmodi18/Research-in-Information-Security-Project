"""Security event log: GET /events, GET /events/export (FR-14)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from maka_server import models
from maka_server.deps import Principal, get_db, viewer
from maka_server.schemas import EventOut, Page

router = APIRouter(prefix="/events", tags=["events"])


def _query(network: int | None, severity: str | None, type: str | None, device: str | None,
           since: datetime | None, run_tag: str | None = None) -> Select[models.SecurityEventRow]:
    q = select(models.SecurityEventRow)
    if run_tag:
        q = q.where(models.SecurityEventRow.run_tag == run_tag)
    if network is not None:
        q = q.where(models.SecurityEventRow.network_id == network)
    if severity:
        q = q.where(models.SecurityEventRow.severity.in_(severity.split(",")))
    if type:
        q = q.where(models.SecurityEventRow.type.in_(type.split(",")))
    if device:
        q = q.where((models.SecurityEventRow.device == device) | (models.SecurityEventRow.peer == device))
    if since is not None:
        q = q.where(models.SecurityEventRow.ts >= since)
    return q


def _out(r: models.SecurityEventRow) -> EventOut:
    return EventOut(id=r.id, network_id=r.network_id, step=r.step, ts=r.ts, severity=r.severity, type=r.type,
                    device=r.device, peer=r.peer, session_sid=r.session_sid, frame_id=r.frame_id,
                    details=dict(r.details_json), run_tag=r.run_tag)


@router.get("", response_model=Page[EventOut])
def list_events(network: int | None = None, severity: str | None = None, type: str | None = None,
                device: str | None = None, since: datetime | None = None, run_tag: str | None = None,
                cursor: int | None = None, limit: int = Query(default=200, ge=1, le=1000),
                order: Literal["asc", "desc"] = "desc",
                _: Principal = Depends(viewer), db: Session = Depends(get_db)) -> Page[EventOut]:
    q = _query(network, severity, type, device, since, run_tag)
    if cursor is not None:
        q = q.where(models.SecurityEventRow.id < cursor if order == "desc" else models.SecurityEventRow.id > cursor)
    col = models.SecurityEventRow.id
    rows = list(db.scalars(q.order_by(col.desc() if order == "desc" else col).limit(limit + 1)))
    return Page[EventOut](items=[_out(r) for r in rows[:limit]],
                          next_cursor=rows[limit - 1].id if len(rows) > limit else None)


@router.get("/export")
def export_events(format: Literal["csv", "json"] = "csv", network: int | None = None,
                  severity: str | None = None, type: str | None = None, device: str | None = None,
                  since: datetime | None = None, _: Principal = Depends(viewer),
                  db: Session = Depends(get_db)) -> Response:
    rows = [_out(r) for r in db.scalars(_query(network, severity, type, device, since)
                                        .order_by(models.SecurityEventRow.id).limit(100_000))]
    if format == "json":
        body = json.dumps([r.model_dump(mode="json") for r in rows], indent=1)
        return Response(body, media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="security_events.json"'})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "network_id", "step", "ts", "severity", "type", "device", "peer", "session_sid",
                "frame_id", "details"])
    for r in rows:
        w.writerow([r.id, r.network_id, r.step, r.ts.isoformat(), r.severity, r.type, r.device, r.peer or "",
                    r.session_sid or "", r.frame_id or "", json.dumps(r.details, sort_keys=True)])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="security_events.csv"'})
