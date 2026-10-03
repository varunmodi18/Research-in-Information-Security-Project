"""Console users (FR-18) and the create-admin bootstrap (§4.9)."""

from __future__ import annotations

from sqlalchemy import select

from maka_server import models
from maka_server.context import AppContext
from maka_server.errors import ApiError
from maka_server.security import hash_password


def create_user(ctx: AppContext, username: str, password: str, role: str) -> models.User:
    try:
        pw_hash = hash_password(password)
    except ValueError as exc:
        raise ApiError(422, "VALIDATION_FAILED", "Weak password", str(exc)) from exc
    with ctx.db.session() as db:
        if db.scalar(select(models.User).where(models.User.username == username)) is not None:
            raise ApiError(409, "NAME_TAKEN", "Username taken", f"user {username!r} exists")
        user = models.User(username=username, password_hash=pw_hash, role=role, disabled=False)
        db.add(user)
        db.flush()
        return user
