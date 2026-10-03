"""Evaluation runs (FR-17). The evaluation job handler arrives in M7."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from maka_server import models
from maka_server.context import AppContext
from maka_server.deps import Principal, get_ctx, viewer
from maka_server.errors import not_found

router = APIRouter(prefix="/evaluation", tags=["evaluation"])


@router.get("/runs/{run_id}")
def get_run(run_id: int, _: Principal = Depends(viewer), ctx: AppContext = Depends(get_ctx)) -> dict[str, Any]:
    with ctx.db.session() as db:
        run = db.get(models.EvaluationRun, run_id)
        if run is None:
            raise not_found(f"evaluation run {run_id}")
        return {"id": run.id, "job_id": run.job_id, "state": run.state, "config": run.config_json,
                "result": run.result_json, "created_at": run.created_at}
