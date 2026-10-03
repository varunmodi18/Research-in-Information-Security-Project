"""Lab scenario jobs (IMPLEMENTATION_PLAN.md M6-T1..T3) and evaluation jobs (M7).

A lab_scenario job runs the scenario on a fresh lab runtime per requested mode (the lab
network's parameter set and seed), stores that run's frames and events in the lab network
tagged `<scenario>/<mode>/<job>`, and returns the verdicts with links to their evidence.
Results show what actually happened; the §3.6 expectation is shown next to it.
"""

from __future__ import annotations

from typing import Any

from maka.lab import scenarios as sc
from maka_server import models
from maka_server.errors import ApiError
from maka_server.jobs import JobContext, handler
from maka_server.services.runtime import persist_events, persist_frames

LAB_TEMPLATES = ("small", "net")


@handler("lab_scenario")
def job_lab_scenario(ctx: JobContext) -> dict[str, Any]:
    scenario = sc.BY_ID.get(str(ctx.args.get("scenario", "")))
    if scenario is None:
        raise ApiError(422, "VALIDATION_FAILED", "Unknown scenario", f"choose one of {sorted(sc.BY_ID)}")
    modes = ctx.args.get("modes") or list(sc.MODES)
    if not isinstance(modes, list) or not modes or any(m not in sc.MODES for m in modes):
        raise ApiError(422, "VALIDATION_FAILED", "Bad modes", "modes must be a subset of [original, enhanced]")
    template = str(ctx.args.get("template", "small"))
    if template not in LAB_TEMPLATES:
        raise ApiError(422, "VALIDATION_FAILED", "Bad template", f"scenarios run on {LAB_TEMPLATES}")
    nid = ctx.network_id
    with ctx.app.db.session() as db:
        net = db.get(models.Network, nid)
        if net is None or net.kind != "lab":
            raise ApiError(422, "MODE_NOT_ALLOWED", "Lab only", "scenarios run only on lab networks")
        params, seed = net.params, net.seed if net.seed is not None else sc.DEFAULT_SEED

    runs: dict[str, Any] = {}
    for i, mode in enumerate(modes):
        ctx.progress(i / len(modes), f"{scenario.id} in {mode} mode", force=True)
        run = scenario.execute(mode, params=params, topology=template, seed=seed)
        verdict = run.verdict
        assert verdict is not None  # type narrowing only
        tag = f"{scenario.id}/{mode}/{ctx.job_id}"
        with ctx.app.db.session() as db:
            frame_ids = persist_frames(db, nid, ctx.job_id, run.net.scheduler, 0, 0, keep_payload=True,  # type: ignore[arg-type]
                                       run_tag=tag)
            event_ids = persist_events(db, nid, run.net.scheduler.events, run_tag=tag)  # type: ignore[arg-type]
            expected = scenario.expected[mode]
            summary = models.SecurityEventRow(
                network_id=nid, step=run.net.scheduler.step_no, severity="high", type="LAB_ATTACK_RESULT",
                device="adversary", peer=None, run_tag=tag,
                details_json={"scenario": scenario.id, "mode": mode, "result": verdict.result,
                              "expected": expected, "matches_expectation": verdict.result == expected})
            db.add(summary)
            db.flush()
            summary_id = summary.id
        ctx.app.broker.publish(nid, "security_event", {"type": "LAB_ATTACK_RESULT", "device": "adversary",
                                                       "severity": "high", "details": summary.details_json})
        runs[mode] = {
            "result": verdict.result, "expected": expected, "matches_expectation": verdict.result == expected,
            "explanation": verdict.explanation, "run_tag": tag,
            "evidence_frame_rows": [frame_ids[f] for f in verdict.evidence_frame_ids if f in frame_ids],
            "evidence_event_rows": [event_ids[j] for j in verdict.event_indices if j < len(event_ids)],
            "summary_event": summary_id,
            "secrets_obtained": list(verdict.secrets_obtained),  # names only (M6-T3)
            "measurements": verdict.measurements, "steps": run.net.scheduler.step_no,
            "frames": len(frame_ids), "events": len(event_ids),
        }
    return {"scenario": scenario.id, "title": scenario.title, "gap": scenario.gap, "template": template,
            "params": params, "seed": seed, "runs": runs}
