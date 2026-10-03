"""Evaluation runs and reference material (FR-17, M7-T6)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select

from maka_server import models
from maka_server.context import AppContext
from maka_server.deps import Principal, get_ctx, viewer
from maka_server.errors import not_found

router = APIRouter(prefix="/evaluation", tags=["evaluation"])


@router.get("/reference")
def get_reference(_: Principal = Depends(viewer)) -> dict[str, Any]:
    """RP9 table reproductions, formal results, parameter levels, latest comparison, limitations."""
    from maka_server.services.evaluation import reference

    return reference()


@router.get("/runs")
def list_runs(_: Principal = Depends(viewer), ctx: AppContext = Depends(get_ctx)) -> list[dict[str, Any]]:
    with ctx.db.session() as db:
        rows = db.scalars(select(models.EvaluationRun).order_by(models.EvaluationRun.id.desc()).limit(20))
        return [{"id": r.id, "job_id": r.job_id, "state": r.state, "config": r.config_json,
                 "created_at": r.created_at} for r in rows]


@router.get("/runs/{run_id}")
def get_run(run_id: int, _: Principal = Depends(viewer), ctx: AppContext = Depends(get_ctx)) -> dict[str, Any]:
    with ctx.db.session() as db:
        run = db.get(models.EvaluationRun, run_id)
        if run is None:
            raise not_found(f"evaluation run {run_id}")
        return {"id": run.id, "job_id": run.job_id, "state": run.state, "config": run.config_json,
                "result": run.result_json, "created_at": run.created_at}
