"""Demo seed and reset (IMPLEMENTATION_PLAN.md M8-T1, §7.1).

The demo state is exactly:

* users `admin`, `operator`, `viewer` (passwords supplied by the person seeding, never stored here);
* product network "Vineyard": `net`, MAKA-E, `demo` parameters, OS randomness;
* lab network "Lab-Paper": `paper`, `toy` parameters, seed 20260927. A lab network runs Lab
  scenarios in both modes; its own mode is RP9 original so the network itself also shows RP9.

`reset_demo` restores the networks and clears everything that hangs off them (devices, keystores,
sessions, frames, events, readings, jobs) and the evaluation runs. Users and the audit log are kept:
the reset cannot know passwords, and the audit trail must survive resets.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select

from maka_server import models
from maka_server.context import AppContext
from maka_server.errors import ApiError
from maka_server.jobs import JobContext, handler
from maka_server.schemas import NetworkCreate
from maka_server.services.networks import create_network
from maka_server.services.users import create_user

DEMO_USERS = ("admin", "operator", "viewer")
DEMO_NETWORKS = (
    NetworkCreate(name="Vineyard", kind="product", mode="enhanced", params="demo", template="net"),
    NetworkCreate(name="Lab-Paper", kind="lab", mode="original", params="toy", template="paper", seed=20260927),
)
ACTIVE = ("queued", "running")


def reset_networks(ctx: AppContext, own_job_id: int | None = None) -> list[int]:
    """Deletes every network and evaluation run, then creates the demo networks. Refuses while any
    other job is queued or running, so no worker is mid-way through a network being deleted."""
    with ctx.db.session() as db:
        busy = db.scalar(select(models.Job.id).where(models.Job.state.in_(ACTIVE), models.Job.id != (own_job_id or -1)))
        if busy is not None:
            raise ApiError(409, "NETWORK_BUSY", "Jobs running", f"job {busy} is still active; wait or cancel it")
        ids = list(db.scalars(select(models.Network.id)))
        for nid in ids:
            ctx.jobs.periodic.pop(nid, None)
        db.execute(delete(models.Job).where(models.Job.network_id.is_not(None)))
        db.execute(delete(models.SecurityEventRow))
        db.execute(delete(models.EvaluationRun))
        db.execute(delete(models.Network))  # devices, keystores, sessions, frames, readings cascade
    for nid in ids:
        ctx.registry.drop(nid)
        ctx.broker.forget(nid)
    return [create_network(ctx, req) for req in DEMO_NETWORKS]


def seed(ctx: AppContext, passwords: dict[str, str]) -> dict[str, Any]:
    """Creates any missing demo user, then resets the demo networks. Existing users are left as they
    are (their passwords are not changed)."""
    created, kept = [], []
    with ctx.db.session() as db:
        existing = set(db.scalars(select(models.User.username).where(models.User.username.in_(DEMO_USERS))))
    for name in DEMO_USERS:
        if name in existing:
            kept.append(name)
            continue
        create_user(ctx, name, passwords[name], name)
        created.append(name)
    return {"users_created": created, "users_kept": kept, "networks": reset_networks(ctx)}


@handler("reset_demo")
def job_reset_demo(ctx: JobContext) -> dict[str, Any]:
    ctx.progress(0.1, "resetting demo networks", force=True)
    ids = reset_networks(ctx.app, own_job_id=ctx.job_id)
    return {"networks": ids, "names": [n.name for n in DEMO_NETWORKS]}
