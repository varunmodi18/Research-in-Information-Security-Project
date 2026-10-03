"""Lab scenarios (FR-16). Scenario definitions arrive in M6; the listing endpoint is here."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from maka_server.deps import Principal, operator

router = APIRouter(prefix="/lab", tags=["lab"])


@router.get("/scenarios")
def list_scenarios(_: Principal = Depends(operator)) -> list[dict[str, Any]]:
    from maka.lab import scenarios

    return [s.describe() for s in scenarios.ALL]
