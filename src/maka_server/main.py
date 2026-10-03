"""FastAPI application (IMPLEMENTATION_PLAN.md §4.1, M3-T1).

    uvicorn maka_server.main:app            # module attribute, created on first access
    uvicorn --factory maka_server.main:create_app

Startup: refuse to run without MAKA_KEK (unless MAKA_ENV=test), migrate the DB to head,
mark interrupted jobs aborted and apply the recovery rule (§4.8).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse

from maka_server import errors
from maka_server.context import AppContext, build_context
from maka_server.migrate import upgrade
from maka_server.routers import admin, auth, evaluation, events, jobs, lab, networks
from maka_server.services import audit
from maka_server.services import networks as network_service
from maka_server.settings import Settings, get_settings

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    ctx = build_context(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        AppContext.thread_setup()
        ctx.jobs.recover_on_startup()
        yield
        ctx.jobs.shutdown()

    upgrade(settings.db_url)
    network_service.register_builders(ctx)
    from maka_server.services import demo as demo_jobs  # noqa: F401
    from maka_server.services import enhanced_jobs, lab_jobs  # noqa: F401 -- registers job handlers
    from maka_server.services import evaluation as evaluation_jobs  # noqa: F401

    app = FastAPI(title="MAKA Secure IoT Console", version="1.0.0", lifespan=lifespan,
                  docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
    app.state.ctx = ctx
    errors.install(app)

    @app.middleware("http")
    async def headers_and_audit(request: Request,
                                call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        path = request.url.path
        if (request.method not in ("GET", "HEAD", "OPTIONS") and path.startswith("/api/")
                and path != "/api/auth/login"):
            principal = getattr(request.state, "principal", None)
            audit.record(ctx, principal.user_id if principal else None,
                         principal.username if principal else "", f"{request.method} {path}"[:64],
                         path[:128], "success" if response.status_code < 400 else f"http {response.status_code}")
        return response

    @app.get("/api/health", tags=["meta"])
    def health() -> dict[str, Any]:
        return {"status": "ok", "env": settings.env}

    for r in (auth.router, networks.router, jobs.router, events.router, lab.router, evaluation.router,
              admin.router):
        app.include_router(r, prefix="/api")

    _mount_spa(app, settings.static_dir)
    return app


def _mount_spa(app: FastAPI, static_dir: Path) -> None:
    """Serves the built React app; unknown non-API paths return index.html (client routing)."""
    root = static_dir.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> Response:
        if path.startswith("api/"):
            return JSONResponse({"code": "NOT_FOUND", "status": 404, "title": "Not found"}, status_code=404,
                                media_type=errors.PROBLEM)
        candidate = (root / path).resolve()
        if path and candidate.is_file() and root in candidate.parents:
            return FileResponse(candidate)
        index = root / "index.html"
        if index.is_file():
            return FileResponse(index)
        return JSONResponse({"detail": "web UI not built: run `npm run build` in web/"}, status_code=404)


_app: FastAPI | None = None


def __getattr__(name: str) -> FastAPI:  # PEP 562: `maka_server.main:app` without import-time side effects
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
