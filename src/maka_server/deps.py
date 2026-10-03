"""Request dependencies: authentication, CSRF, role checks (IMPLEMENTATION_PLAN.md §4.5, M3-T2).

Every endpoint except login requires a valid session cookie (401 otherwise). Every non-GET
request must also carry X-CSRF-Token equal to the session's token (403 otherwise).
Authorisation is enforced here, on the server; the UI only hides controls.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from maka_server import models
from maka_server.context import AppContext
from maka_server.errors import ApiError
from maka_server.security import token_hash, tokens_equal

COOKIE = "maka_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx  # type: ignore[no-any-return]


def get_db(ctx: AppContext = Depends(get_ctx)) -> Iterator[Session]:
    with ctx.db.session() as s:
        yield s


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    role: str
    csrf_token: str
    session_id: int


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def current_user(request: Request, ctx: AppContext = Depends(get_ctx)) -> Principal:
    token = request.cookies.get(COOKIE)
    if not token:
        raise ApiError(401, "UNAUTHENTICATED", "Authentication required", "sign in first")
    error: ApiError | None = None
    principal: Principal | None = None
    with ctx.db.session() as db:  # commits deletions of dead sessions before any error is raised
        sess = db.scalar(select(models.AuthSession).where(models.AuthSession.token_hash == token_hash(token)))
        now = datetime.now(UTC)
        user = db.get(models.User, sess.user_id) if sess is not None else None
        if sess is None or _aware(sess.expires_at) <= now:
            error = ApiError(401, "UNAUTHENTICATED", "Session expired", "sign in again")
        elif user is None or user.disabled:
            error = ApiError(401, "UNAUTHENTICATED", "Account unavailable", "sign in again")
        elif request.method not in SAFE_METHODS and not tokens_equal(
                request.headers.get(CSRF_HEADER, ""), sess.csrf_token):
            error = ApiError(403, "CSRF_FAILED", "CSRF check failed", f"missing or wrong {CSRF_HEADER} header")
        if error is not None and error.status == 401 and sess is not None:
            db.delete(sess)
        elif error is None and sess is not None and user is not None:
            sess.expires_at = now + timedelta(hours=ctx.settings.session_idle_hours)  # sliding idle expiry
            principal = Principal(user.id, user.username, user.role, sess.csrf_token, sess.id)
    if error is not None:
        raise error
    assert principal is not None  # type narrowing only
    request.state.principal = principal
    return principal


def require_role(minimum: str) -> Callable[..., Principal]:
    def dep(principal: Principal = Depends(current_user)) -> Principal:
        if ROLE_RANK[principal.role] < ROLE_RANK[minimum]:
            raise ApiError(403, "FORBIDDEN", "Insufficient role", f"requires {minimum} or higher")
        return principal
    return dep


viewer = require_role("viewer")
operator = require_role("operator")
admin = require_role("admin")
