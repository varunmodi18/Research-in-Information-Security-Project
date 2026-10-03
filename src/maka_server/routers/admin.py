"""Admin: users, demo reset, audit log (FR-18..FR-20)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from maka_server import models
from maka_server.context import AppContext
from maka_server.deps import Principal, admin, get_ctx
from maka_server.errors import ApiError, not_found
from maka_server.schemas import (
    AuditOut,
    JobAccepted,
    Page,
    ResetDemo,
    UserCreate,
    UserOut,
    UserPatch,
)
from maka_server.security import hash_password
from maka_server.services.users import create_user

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_model=list[UserOut])
def list_users(_: Principal = Depends(admin), ctx: AppContext = Depends(get_ctx)) -> list[UserOut]:
    with ctx.db.session() as db:
        return [UserOut.model_validate(u) for u in db.scalars(select(models.User).order_by(models.User.id))]


@router.post("/users", response_model=UserOut, status_code=201)
def add_user(body: UserCreate, _: Principal = Depends(admin), ctx: AppContext = Depends(get_ctx)) -> UserOut:
    return UserOut.model_validate(create_user(ctx, body.username, body.password, body.role))


@router.patch("/users/{user_id}", response_model=UserOut)
def patch_user(user_id: int, body: UserPatch, principal: Principal = Depends(admin),
               ctx: AppContext = Depends(get_ctx)) -> UserOut:
    with ctx.db.session() as db:
        user = db.get(models.User, user_id)
        if user is None:
            raise not_found(f"user {user_id}")
        if user.id == principal.user_id and (body.disabled or (body.role and body.role != "admin")):
            raise ApiError(422, "VALIDATION_FAILED", "Refused", "admins cannot disable or demote themselves")
        if body.role is not None:
            user.role = body.role
        if body.disabled is not None:
            user.disabled = body.disabled
            if body.disabled:
                for s in db.scalars(select(models.AuthSession).where(models.AuthSession.user_id == user.id)):
                    db.delete(s)
        if body.password is not None:
            user.password_hash = hash_password(body.password)
        return UserOut.model_validate(user)


@router.post("/reset-demo", response_model=JobAccepted, status_code=202)
def reset_demo(body: ResetDemo, principal: Principal = Depends(admin),
               ctx: AppContext = Depends(get_ctx)) -> JobAccepted:
    job, created = ctx.jobs.submit(None, "reset_demo", {}, f"reset-demo-{models.utcnow().timestamp():.0f}",
                                   principal.user_id)
    return JobAccepted(job_id=job.id, created=created)


@router.get("/audit", response_model=Page[AuditOut])
def audit(cursor: int | None = None, limit: int = Query(default=200, ge=1, le=1000),
          _: Principal = Depends(admin), ctx: AppContext = Depends(get_ctx)) -> Page[AuditOut]:
    with ctx.db.session() as db:
        q = select(models.AuditLog)
        if cursor is not None:
            q = q.where(models.AuditLog.id < cursor)
        rows = list(db.scalars(q.order_by(models.AuditLog.id.desc()).limit(limit + 1)))
        return Page[AuditOut](items=[AuditOut.model_validate(r) for r in rows[:limit]],
                              next_cursor=rows[limit - 1].id if len(rows) > limit else None)
