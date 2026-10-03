"""Background jobs (IMPLEMENTATION_PLAN.md §4.1, §4.5, M3-T4).

One worker thread per network runs that network's jobs one at a time, so no two jobs touch
a network's runtime concurrently; API handlers never run cryptography. Job states:
queued -> running -> succeeded | failed | cancelled, plus `aborted` for jobs found running at
startup. Cancellation is checked between scheduler steps. A failed or aborted job triggers the
§4.8 recovery rule for its network.
"""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from maka_server import models
from maka_server.errors import ApiError

if TYPE_CHECKING:
    from maka_server.context import AppContext

QUEUED, RUNNING, SUCCEEDED, FAILED, CANCELLED, ABORTED = (
    "queued", "running", "succeeded", "failed", "cancelled", "aborted")
TERMINAL = {SUCCEEDED, FAILED, CANCELLED, ABORTED}


class JobCancelled(Exception):
    pass


@dataclass
class JobContext:
    app: AppContext
    job_id: int
    network_id: int | None
    type: str
    args: dict[str, Any]
    cancel: threading.Event
    user_id: int | None
    _last_progress: float = 0.0
    _state: dict[str, Any] = field(default_factory=dict)

    def cancelled(self) -> bool:
        return self.cancel.is_set()

    def progress(self, fraction: float, phase: str, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_progress < 0.3:
            return
        self._last_progress = now
        fraction = max(0.0, min(1.0, fraction))
        with self.app.db.session() as db:
            job = db.get(models.Job, self.job_id)
            if job is not None:
                job.progress, job.phase = fraction, phase
        data = {"job_id": self.job_id, "type": self.type, "state": RUNNING, "progress": fraction, "phase": phase}
        self.app.broker.publish(self.network_id, "job_progress", data)


Handler = Callable[[JobContext], dict[str, Any]]
HANDLERS: dict[str, Handler] = {}


def handler(job_type: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        HANDLERS[job_type] = fn
        return fn
    return deco


class JobManager:
    def __init__(self, app: AppContext) -> None:
        self.app = app
        self._queues: dict[int | None, queue.Queue[int | None]] = {}
        self._threads: dict[int | None, threading.Thread] = {}
        self._cancel: dict[int, threading.Event] = {}
        self._done: dict[int, threading.Event] = {}
        self._lock = threading.Lock()

    # -- submission ------------------------------------------------------------------

    def submit(self, network_id: int | None, job_type: str, args: dict[str, Any],
               idempotency_key: str, user_id: int | None) -> tuple[models.Job, bool]:
        """Returns (job, created). Same key + same body returns the existing job; same key with
        a different body is a 409."""
        if job_type not in HANDLERS:
            raise ApiError(422, "VALIDATION_FAILED", "Unknown job type", f"no handler for {job_type!r}")
        with self.app.db.session() as db:
            existing = db.scalar(select(models.Job).where(models.Job.network_id == network_id,
                                                          models.Job.idempotency_key == idempotency_key))
            if existing is not None:
                if existing.type != job_type or existing.args_json != args:
                    raise ApiError(409, "IDEMPOTENCY_CONFLICT", "Idempotency key reused",
                                   "this idempotency key was already used with a different request")
                return existing, False
            job = models.Job(network_id=network_id, type=job_type, args_json=args,
                             idempotency_key=idempotency_key, state=QUEUED, user_id=user_id)
            db.add(job)
            db.flush()
            job_id = job.id
        self._enqueue(network_id, job_id)
        with self.app.db.session() as db:
            created = db.get(models.Job, job_id)
            assert created is not None  # type narrowing only
            return created, True

    def _enqueue(self, network_id: int | None, job_id: int) -> None:
        with self._lock:
            self._cancel[job_id] = threading.Event()
            self._done[job_id] = threading.Event()
            q = self._queues.get(network_id)
            if q is None:
                q = self._queues[network_id] = queue.Queue()
                t = threading.Thread(target=self._worker, args=(network_id, q), daemon=True,
                                     name=f"maka-net-{network_id}")
                self._threads[network_id] = t
                t.start()
        q.put(job_id)

    def cancel(self, job_id: int) -> models.Job:
        with self.app.db.session() as db:
            job = db.get(models.Job, job_id)
            if job is None:
                raise ApiError(404, "NOT_FOUND", "Not found", f"job {job_id} does not exist")
            if job.state == QUEUED:
                job.state = CANCELLED
                job.finished_at = models.utcnow()
            ev = self._cancel.get(job_id)
            if ev is not None:
                ev.set()
            return job

    def wait(self, job_id: int, timeout: float = 120.0) -> bool:
        ev = self._done.get(job_id)
        return ev.wait(timeout) if ev is not None else True

    def shutdown(self, timeout: float = 10.0) -> None:
        with self._lock:
            for ev in self._cancel.values():
                ev.set()
            for q in self._queues.values():
                q.put(None)
            threads = list(self._threads.values())
        for t in threads:
            t.join(timeout)

    # -- startup recovery (V-REC-02) ------------------------------------------------------

    def recover_on_startup(self) -> list[int]:
        """Jobs left `running` by a previous process become `aborted`; their networks are
        rebuilt under the recovery rule. Jobs still `queued` are re-enqueued."""
        with self.app.db.session() as db:
            running = list(db.scalars(select(models.Job).where(models.Job.state == RUNNING)))
            for job in running:
                job.state, job.error = ABORTED, "interrupted by a restart (sessions aborted, §4.8)"
                job.finished_at = models.utcnow()
            networks = {j.network_id for j in running if j.network_id is not None}
            for nid in networks:
                net = db.get(models.Network, nid)
                if net is not None:
                    net.status = "idle"
            queued = [(j.network_id, j.id) for j in db.scalars(
                select(models.Job).where(models.Job.state == QUEUED).order_by(models.Job.id))]
        for nid in networks:
            self.app.registry.rebuild(nid)
        for queued_nid, jid in queued:
            self._enqueue(queued_nid, jid)
        return [j.id for j in running]

    # -- execution ----------------------------------------------------------------------

    def _worker(self, network_id: int | None, q: queue.Queue[int | None]) -> None:
        self.app.thread_setup()
        while True:
            job_id = q.get()
            if job_id is None:
                return
            try:
                self._run(job_id)
            finally:
                done = self._done.get(job_id)
                if done is not None:
                    done.set()

    def _run(self, job_id: int) -> None:
        with self.app.db.session() as db:
            row = db.get(models.Job, job_id)
            if row is None or row.state != QUEUED:
                return
            job = row
            job.state = RUNNING
            ctx = JobContext(self.app, job.id, job.network_id, job.type, dict(job.args_json),
                             self._cancel.get(job.id, threading.Event()), job.user_id)
            if job.network_id is not None:
                net = db.get(models.Network, job.network_id)
                if net is not None:
                    net.status = "busy"
        self._publish(ctx, RUNNING, 0.0)
        try:
            result = HANDLERS[ctx.type](ctx)
            final = CANCELLED if ctx.cancelled() else SUCCEEDED
            error = None
        except JobCancelled:
            final, result, error = CANCELLED, {}, None
        except ApiError as exc:
            final, result, error = FAILED, {}, f"{exc.code}: {exc.detail or exc.title}"
        except Exception as exc:  # noqa: BLE001 -- any failure must leave a consistent state
            final, result, error = FAILED, {}, f"{type(exc).__name__}: {exc}"
        self._finish(ctx, final, result, error)

    def _finish(self, ctx: JobContext, final: str, result: dict[str, Any], error: str | None) -> None:
        nid = ctx.network_id
        rt = self.app.registry.peek(nid) if nid is not None else None
        if rt is not None:
            with self.app.db.session() as db, rt.lock:
                rt.flush(db)  # keep the evidence of what happened before any failure
            rt.job_id = None
        if final == FAILED and nid is not None and self.app.registry.peek(nid) is not None:
            self.app.registry.rebuild(nid)  # §4.8 recovery rule (V-REC-01)
        with self.app.db.session() as db:
            job = db.get(models.Job, ctx.job_id)
            if job is not None:
                job.state, job.result_json, job.error = final, result, error
                job.progress = 1.0 if final == SUCCEEDED else job.progress
                job.finished_at = models.utcnow()
            if nid is not None:
                net = db.get(models.Network, nid)
                if net is not None:
                    net.status = "failed" if final == FAILED else "idle"
        self._publish(ctx, final, 1.0 if final == SUCCEEDED else None, error)

    def _publish(self, ctx: JobContext, state: str, progress: float | None, error: str | None = None) -> None:
        data = {"job_id": ctx.job_id, "type": ctx.type, "state": state, "progress": progress, "error": error}
        self.app.broker.publish(ctx.network_id, "job_progress", data)
        if ctx.network_id is not None:
            self.app.broker.publish(None, "job_progress", {**data, "network_id": ctx.network_id})
