"""RFC 9457 problem details with a stable `code` enum (IMPLEMENTATION_PLAN.md §4.5)."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM = "application/problem+json"

_DEFAULT_CODES = {400: "BAD_REQUEST", 401: "UNAUTHENTICATED", 403: "FORBIDDEN", 404: "NOT_FOUND",
                  405: "METHOD_NOT_ALLOWED", 409: "CONFLICT", 422: "VALIDATION_FAILED",
                  429: "RATE_LIMITED", 500: "INTERNAL_ERROR"}


class ApiError(Exception):
    def __init__(self, status: int, code: str, title: str, detail: str = "") -> None:
        super().__init__(detail or title)
        self.status, self.code, self.title, self.detail = status, code, title, detail


def not_found(what: str) -> ApiError:
    return ApiError(404, "NOT_FOUND", "Not found", f"{what} does not exist")


def problem(request: Request, status: int, code: str, title: str, detail: str = "",
            extra: dict[str, Any] | None = None) -> JSONResponse:
    body = {"type": f"https://maka.local/problems/{code.lower().replace('_', '-')}", "title": title,
            "status": status, "detail": detail, "instance": request.url.path, "code": code}
    if extra:
        body.update(extra)
    return JSONResponse(body, status_code=status, media_type=PROBLEM)


def install(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return problem(request, exc.status, exc.code, exc.title, exc.detail)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _DEFAULT_CODES.get(exc.status_code, "ERROR")
        return problem(request, exc.status_code, code, str(exc.detail), str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = [{"loc": [str(x) for x in e.get("loc", [])], "msg": e.get("msg", "")} for e in exc.errors()]
        return problem(request, 422, "VALIDATION_FAILED", "Request validation failed",
                       "; ".join(f"{'.'.join(f['loc'])}: {f['msg']}" for f in fields), {"errors": fields})
