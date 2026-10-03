"""GET /jobs/{id}, POST /jobs/{id}/cancel (IMPLEMENTATION_PLAN.md §4.5)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from maka_server import models
from maka_server.context import AppContext
from maka_server.deps import Principal, get_ctx, operator, viewer
from maka_server.errors import not_found
from maka_server.schemas import JobOut

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("/{job_id}", response_model=JobOut)
def get_job(job_id: int, _: Principal = Depends(viewer), ctx: AppContext = Depends(get_ctx)) -> JobOut:
    with ctx.db.session() as db:
        job = db.get(models.Job, job_id)
        if job is None:
            raise not_found(f"job {job_id}")
        return JobOut.model_validate(job)


@router.post("/{job_id}/cancel", response_model=JobOut, status_code=202)
def cancel_job(job_id: int, _: Principal = Depends(operator), ctx: AppContext = Depends(get_ctx)) -> JobOut:
    return JobOut.model_validate(ctx.jobs.cancel(job_id))
