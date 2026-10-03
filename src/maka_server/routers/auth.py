"""POST /auth/login, POST /auth/logout, GET /auth/me (IMPLEMENTATION_PLAN.md §4.5, M3-T2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select

from maka_server import models
from maka_server.context import AppContext
from maka_server.deps import COOKIE, Principal, current_user, get_ctx
from maka_server.errors import ApiError
from maka_server.schemas import LoginRequest, SessionInfoOut, UserOut
from maka_server.security import new_token, token_hash, verify_password
from maka_server.services.audit import record

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=SessionInfoOut)
def login(body: LoginRequest, response: Response, ctx: AppContext = Depends(get_ctx)) -> SessionInfoOut:
    if ctx.limiter.locked(body.username):
        record(ctx, None, body.username, "login", body.username, "locked")
        raise ApiError(429, "LOGIN_LOCKED", "Too many failed sign-ins",
                       "this account is locked for 15 minutes after repeated failures")
    with ctx.db.session() as db:
        user = db.scalar(select(models.User).where(models.User.username == body.username))
        ok = verify_password(user.password_hash if user else None, body.password) and user is not None
        if not ok or user is None or user.disabled:
            failed = True
        else:
            failed = False
            token, csrf = new_token(), new_token()
            db.add(models.AuthSession(token_hash=token_hash(token), user_id=user.id, csrf_token=csrf,
                                      expires_at=datetime.now(UTC) + timedelta(hours=ctx.settings.session_idle_hours)))
            out = SessionInfoOut(user=UserOut.model_validate(user), role=user.role, csrf_token=csrf)
            user_id = user.id
    if failed:
        ctx.limiter.record_failure(body.username)
        record(ctx, None, body.username, "login", body.username, "failure")
        raise ApiError(401, "BAD_CREDENTIALS", "Sign-in failed", "unknown user or wrong password")
    ctx.limiter.record_success(body.username)
    record(ctx, user_id, body.username, "login", body.username, "success")
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=ctx.settings.secure_cookies,
                        path="/", max_age=int(ctx.settings.session_idle_hours * 3600))
    return out


@router.post("/logout", status_code=204)
def logout(response: Response, principal: Principal = Depends(current_user),
           ctx: AppContext = Depends(get_ctx)) -> Response:
    with ctx.db.session() as db:
        sess = db.get(models.AuthSession, principal.session_id)
        if sess is not None:
            db.delete(sess)
    response.status_code = 204
    response.delete_cookie(COOKIE, path="/")
    return response


@router.get("/me", response_model=SessionInfoOut)
def me(request: Request, principal: Principal = Depends(current_user),
       ctx: AppContext = Depends(get_ctx)) -> SessionInfoOut:
    with ctx.db.session() as db:
        user = db.get(models.User, principal.user_id)
        if user is None:
            raise ApiError(401, "UNAUTHENTICATED", "Account unavailable", "sign in again")
        return SessionInfoOut(user=UserOut.model_validate(user), role=user.role, csrf_token=principal.csrf_token)
