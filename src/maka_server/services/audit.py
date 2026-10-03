"""Console audit log (FR-20, §4.10): who did what, when, with what outcome."""

from __future__ import annotations

from maka_server import models
from maka_server.context import AppContext


def record(ctx: AppContext, user_id: int | None, username: str, action: str, target: str, outcome: str) -> None:
    with ctx.db.session() as db:
        db.add(models.AuditLog(user_id=user_id, username=username[:64], action=action[:64],
                               target=target[:128], outcome=outcome[:32]))
