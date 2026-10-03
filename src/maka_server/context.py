"""Application-wide services, created once per app (IMPLEMENTATION_PLAN.md §4.1)."""

from __future__ import annotations

from dataclasses import dataclass, field

from maka import rng, trace
from maka_server.db import Database
from maka_server.jobs import JobManager
from maka_server.security import LoginLimiter
from maka_server.services.runtime import RuntimeRegistry
from maka_server.settings import Settings
from maka_server.sse import Broker


@dataclass
class AppContext:
    settings: Settings
    db: Database
    broker: Broker
    registry: RuntimeRegistry
    limiter: LoginLimiter
    jobs: JobManager = field(init=False)

    def __post_init__(self) -> None:
        self.jobs = JobManager(self)

    @staticmethod
    def thread_setup() -> None:
        """Every server thread: no transcript files, no fixed-seed randomness (§4.4)."""
        trace.use(trace.NullTracer())
        rng.use(rng.SystemSource())


def build_context(settings: Settings) -> AppContext:
    kek = settings.kek_bytes()  # fails fast without MAKA_KEK unless MAKA_ENV=test (§4.4 rule 2)
    trace.set_fallback(trace.NullTracer())
    rng.set_fallback(rng.SystemSource())
    db = Database(settings.db_url)
    broker = Broker()
    registry = RuntimeRegistry(db, broker, kek, settings.persist_every_steps)
    limiter = LoginLimiter(settings.login_max_failures, settings.login_window_s, settings.login_lock_s)
    return AppContext(settings=settings, db=db, broker=broker, registry=registry, limiter=limiter)
