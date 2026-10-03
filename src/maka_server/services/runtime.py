"""Live runtime networks and their persistence (IMPLEMENTATION_PLAN.md §4.3, §4.8).

The runtime keeps live state in memory and is touched only by its network's worker thread.
`flush` writes device status, session metadata, frames, events and readings -- and the
buffered encrypted keystore changes -- in one transaction, after each job and every
`persist_every_steps` steps. API reads go to the DB, never the live runtime.

Recovery rule (§4.8, NFR-REL-01): live protocol state does not survive a restart or a failed
job. Such a network is rebuilt with every session ABORTED and no session key retained;
devices that were `active` revert to `registered` (enhanced) or, for RP9's original mode,
which has no recovery path, the lab network is re-provisioned from scratch.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from maka import codec, hashing, params
from maka.runtime.scheduler import StepResult
from maka_server import models
from maka_server.db import Database
from maka_server.keystore_store import EncryptedKeystoreAdapter
from maka_server.sse import Broker

FRAME_CAP = 50_000
PRODUCT_PAYLOAD_CAP = 4096


class RuntimeNet(Protocol):
    """What the server needs from an original-mode or enhanced-mode runtime network."""

    mode: str
    params_name: str

    @property
    def scheduler(self) -> Any: ...
    def context(self) -> Any: ...
    def start_onboarding(self) -> list[StepResult]: ...
    def run(self, max_steps: int = ..., should_stop: Callable[[], bool] | None = ...) -> list[StepResult]: ...
    def send_reading(self, cm_id: str, value: str) -> StepResult: ...
    def session_infos(self) -> list[dict[str, Any]]: ...
    def readings(self) -> list[dict[str, Any]]: ...
    def device_epoch(self, ident: str) -> int: ...


def pu_fingerprint(params_name: str, ident: str) -> str:
    """First 8 hex of SHA-256(enc_point(Pu)), Pu = H(ID) -- a public value (§4.8)."""
    curve = params.get(params_name).curve
    return hashlib.sha256(codec.enc_point(hashing.hash_to_point(curve, ident.encode()))).hexdigest()[:8]


@dataclass
class NetworkRuntime:
    network_id: int
    net: RuntimeNet
    adapter: EncryptedKeystoreAdapter
    kind: str
    lock: threading.RLock = field(default_factory=threading.RLock)
    job_id: int | None = None
    _log_cursor: int = 0
    _transcript_cursor: int = 0
    _event_cursor: int = 0
    _reading_cursor: int = 0
    _since_flush: int = 0

    @property
    def scheduler(self) -> Any:
        return self.net.scheduler

    def device_statuses(self) -> dict[str, str]:
        return {ident: d.status for ident, d in self.scheduler.devices.items()}

    # -- persistence ---------------------------------------------------------------

    def flush(self, db: Session) -> None:
        sched = self.scheduler
        net_row = db.get(models.Network, self.network_id)
        if net_row is None:
            return
        dev_rows = {d.ident: d for d in db.scalars(select(models.Device).where(
            models.Device.network_id == self.network_id))}
        for ident, dev in sched.devices.items():  # devices added by reprovision / designate
            if ident not in dev_rows:
                row = models.Device(network_id=self.network_id, ident=ident, role=dev.role, cluster=dev.cluster,
                                    status=dev.status, pu_fingerprint=pu_fingerprint(self.net.params_name, ident),
                                    status_history=[{"step": sched.step_no, "status": dev.status}])
                db.add(row)
                dev_rows[ident] = row
        db.flush()

        keep_payload = self.kind == "lab"
        for result in sched.log[self._log_cursor:]:
            if result.kind == "deliver" and result.frame is not None:
                f = result.frame
                payload = f.payload if keep_payload or len(f.payload) <= PRODUCT_PAYLOAD_CAP else None
                db.add(models.FrameRow(
                    network_id=self.network_id, job_id=self.job_id, frame_id=f.frame_id, step=result.step,
                    sent_step=f.step, src=f.src, dst=f.dst, to=result.to, label=f.label,
                    bytes_len=len(f.payload), paper_bits=f.paper_bits, payload=payload,
                    verdict=result.verdict, reason=result.reason,
                    fate="injected" if f.injected else "modified" if f.tampered else "delivered",
                    checks_json=[{"name": c.name, "ok": c.ok, "reason": c.reason} for c in result.checks]))
        self._log_cursor = len(sched.log)

        for entry in sched.bus.transcript[self._transcript_cursor:]:
            if entry.fate == "dropped":
                f = entry.frame
                db.add(models.FrameRow(
                    network_id=self.network_id, job_id=self.job_id, frame_id=f.frame_id, step=f.step,
                    sent_step=f.step, src=f.src, dst=f.dst, to=None, label=f.label,
                    bytes_len=len(f.payload), paper_bits=f.paper_bits,
                    payload=f.payload if keep_payload else None, verdict="DROPPED",
                    reason="ADVERSARY_DROP", fate="dropped", checks_json=[]))
        self._transcript_cursor = len(sched.bus.transcript)

        for e in sched.events[self._event_cursor:]:
            db.add(models.SecurityEventRow(
                network_id=self.network_id, step=e.step, severity=e.severity, type=e.type, device=e.device,
                peer=e.peer, session_sid=e.sid, frame_id=e.frame_id, details_json=dict(e.details)))
        self._event_cursor = len(sched.events)

        readings = self.net.readings()
        for r in readings[self._reading_cursor:]:
            db.add(models.Reading(network_id=self.network_id, device=str(r["device"]), seq=int(r["seq"]),
                                  value_json={"value": r["value"]}, received_step=int(r["step"])))
        self._reading_cursor = len(readings)

        for ident, dev in sched.devices.items():
            dev_row = dev_rows.get(ident)
            if dev_row is None:
                continue
            if dev_row.status != dev.status:
                dev_row.status_history = [*dev_row.status_history, {"step": sched.step_no, "status": dev.status}]
                dev_row.status = dev.status
            dev_row.epoch = self.net.device_epoch(ident)

        db.execute(delete(models.ProtocolSession).where(models.ProtocolSession.network_id == self.network_id))
        for s in self.net.session_infos():
            db.add(models.ProtocolSession(network_id=self.network_id, **s))

        self.adapter.flush(db, {ident: row.id for ident, row in dev_rows.items()})
        net_row.step = sched.step_no
        self._trim_frames(db)
        self._since_flush = 0

    def _trim_frames(self, db: Session) -> None:
        count = db.scalar(select(func.count()).select_from(models.FrameRow).where(
            models.FrameRow.network_id == self.network_id)) or 0
        if count > FRAME_CAP:
            cutoff = db.scalar(select(models.FrameRow.id).where(models.FrameRow.network_id == self.network_id)
                               .order_by(models.FrameRow.id).offset(count - FRAME_CAP).limit(1))
            db.execute(delete(models.FrameRow).where(models.FrameRow.network_id == self.network_id,
                                                     models.FrameRow.id < cutoff))


def publish_step(broker: Broker, network_id: int, result: StepResult) -> None:
    """SSE events for one scheduler step: public metadata only (§4.4)."""
    if result.frame is not None:
        f = result.frame
        broker.publish(network_id, "frame", {
            "step": result.step, "frame_id": f.frame_id, "src": f.src, "dst": f.dst, "to": result.to,
            "label": f.label, "bytes": len(f.payload), "verdict": result.verdict, "reason": result.reason})
    for e in result.events:
        broker.publish(network_id, "security_event", e.as_dict())
    for ident, status in result.status_changes.items():
        broker.publish(network_id, "device_status", {"device": ident, "status": status, "step": result.step})


class RuntimeRegistry:
    """Builds, caches and rebuilds live networks. Build functions per mode are registered by
    services.networks (original mode now; enhanced mode from M4)."""

    def __init__(self, db: Database, broker: Broker, kek: bytes, persist_every: int) -> None:
        self.db = db
        self.broker = broker
        self.kek = kek
        self.persist_every = persist_every
        self._live: dict[int, NetworkRuntime] = {}
        self._lock = threading.Lock()
        self.builders: dict[str, Callable[[models.Network, list[models.Device], EncryptedKeystoreAdapter,
                                          Session], RuntimeNet]] = {}

    def get(self, network_id: int) -> NetworkRuntime:
        with self._lock:
            rt = self._live.get(network_id)
            if rt is not None:
                return rt
        with self.db.session() as db:
            rt = self._build(db, network_id)
            rt.flush(db)
        with self._lock:
            return self._live.setdefault(network_id, rt)

    def peek(self, network_id: int) -> NetworkRuntime | None:
        with self._lock:
            return self._live.get(network_id)

    def drop(self, network_id: int) -> None:
        with self._lock:
            self._live.pop(network_id, None)

    def rebuild(self, network_id: int) -> NetworkRuntime:
        """The §4.8 recovery rule: forget live state and rebuild from DB + keystore."""
        self.drop(network_id)
        return self.get(network_id)

    def _build(self, db: Session, network_id: int) -> NetworkRuntime:
        row = db.get(models.Network, network_id)
        if row is None:
            raise KeyError(network_id)
        devices = list(db.scalars(select(models.Device).where(models.Device.network_id == network_id)
                                  .order_by(models.Device.id)))
        adapter = EncryptedKeystoreAdapter(self.kek, network_id)
        net = self.builders[row.mode](row, devices, adapter, db)
        rt = NetworkRuntime(network_id=network_id, net=net, adapter=adapter, kind=row.kind)

        def hook(result: StepResult, rt: NetworkRuntime = rt) -> None:
            publish_step(self.broker, network_id, result)
            rt._since_flush += 1
            if rt._since_flush >= self.persist_every:
                with self.db.session() as s:
                    rt.flush(s)

        net.scheduler.hooks.append(hook)
        return rt
