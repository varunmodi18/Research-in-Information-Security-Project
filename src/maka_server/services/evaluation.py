"""Evaluation (FR-17, IMPLEMENTATION_PLAN.md M7-T5/T6).

* The `evaluation` job runs the original-vs-enhanced comparison (eval/bench/compare.py) on
  fresh lab runtimes and stores the result as an EvaluationRun.
* `reference()` gathers what the Evaluation page shows besides runs: RP9 Tables 2-6 reproduced
  with their annotations, the formal results (or "not obtained"), parameter security levels,
  the latest committed comparison, and the limitations of the evidence (§6.7).
"""

from __future__ import annotations

import json
import sys
from functools import lru_cache
from typing import Any

from maka_server import models
from maka_server.errors import ApiError
from maka_server.jobs import JobCancelled, JobContext, handler
from maka_server.schemas import SECURITY_LEVELS
from maka_server.settings import REPO_ROOT

LIMITATIONS = [
    ("Devices, radio and timing are simulated; there is no energy measurement. RP9-constant figures are "
     "estimates (operation counts × RP9's sensor-node constants), not device measurements."),
    ("Pure-Python, non-constant-time arithmetic; demonstration-grade parameters (about 60-bit for demo, "
     "80-bit for secure)."),
    "Symbolic tools assume perfect cryptography and a bounded number of sessions.",
    ("There is no computational security proof for MAKA-E; its argument relies on the analogy with "
     "TLS 1.3 psk_dhe_ke and SOK key distribution under standard assumptions."),
    "Lab outcomes for RP9's original mode demonstrate weaknesses only within the implemented attacker model.",
    "Passing tests are not a proof of cryptographic security.",
]
ALLOWED_TOPOLOGIES = ("paper", "small", "net")
ALLOWED_PARAMS = ("toy", "demo", "secure")


def _import_eval() -> None:
    """eval/ lives at the repository root, beside src/ (IMPLEMENTATION_PLAN.md §4.2)."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.append(str(REPO_ROOT))


@handler("evaluation")
def job_evaluation(ctx: JobContext) -> dict[str, Any]:
    _import_eval()
    from eval.bench import compare

    topologies = list(ctx.args.get("topologies") or ["net"])
    params = list(ctx.args.get("params") or ["demo"])
    seeds = int(ctx.args.get("seeds", 5))
    if not (set(topologies) <= set(ALLOWED_TOPOLOGIES) and set(params) <= set(ALLOWED_PARAMS) and 1 <= seeds <= 10):
        raise ApiError(422, "VALIDATION_FAILED", "Bad evaluation", "topologies, params or seeds out of range")
    if "secure" in params and topologies != ["paper"]:
        raise ApiError(422, "VALIDATION_FAILED", "Too slow", "secure parameters run on the paper topology only")
    configs = [compare.Config(v, t, ps) for ps in params for t in topologies for v in compare.VARIANTS]
    config = {"topologies": topologies, "params": params, "seeds": seeds}
    with ctx.app.db.session() as db:
        run = models.EvaluationRun(job_id=ctx.job_id, config_json=config, state="running")
        db.add(run)
        db.flush()
        run_id = run.id

    def progress(fraction: float, phase: str) -> None:
        ctx.progress(fraction, phase, force=True)
        if ctx.cancelled():
            raise JobCancelled

    try:
        results = compare.run(configs, list(range(1, seeds + 1)), progress=progress)
    except BaseException as exc:
        with ctx.app.db.session() as db:
            row = db.get(models.EvaluationRun, run_id)
            if row is not None:
                row.state = "cancelled" if isinstance(exc, JobCancelled) else "failed"
        raise
    legacy = REPO_ROOT / "docs" / "baseline" / "legacy_run.json"
    legacy_s = next((r["median_s"] for r in json.loads(legacy.read_text())["results"] if r["fixture"] == "net"),
                    None) if legacy.exists() else None
    result = {"results": results, "thresholds": compare.thresholds(results, legacy_s)}
    with ctx.app.db.session() as db:
        row = db.get(models.EvaluationRun, run_id)
        if row is not None:
            row.result_json, row.state = result, "succeeded"
    return {"run_id": run_id, "configs": len(configs)}


@lru_cache(maxsize=1)
def reference() -> dict[str, Any]:
    _import_eval()
    from eval import comparison, cost_model, storage

    from maka.original_rt import messages as om
    from maka.original_rt import network as onet

    net = onet.build("toy", "paper", seed=20260927, secure_pseudo_ids=False)
    net.onboard()
    table2 = {}
    for role, ident, formula in (("CM", "CM-0101", "1T_HG + 4T_SM + 2T_E/D + 1T_P"),
                                 ("CH", "CH-01", "1T_HG + 4T_SM + 4T_E/D + 1T_P")):
        t = net.ledger.total(ident)
        table2[role] = {"rp9_formula": formula, "measured": {op: t.get(op, 0) for op in ("T_HG", "T_SM", "T_E/D", "T_P")}}
    bits = {phase: sum(e.frame.paper_bits for e in net.scheduler.bus.transcript if e.frame.label in labels)
            for phase, labels in om.TABLE3_LABELS.items()}
    table3 = [{"phase": "key generation", "rp9": 640, "measured": bits["key generation"], "note": ""},
              {"phase": "registration", "rp9": 1760, "measured": bits["registration"],
               "note": "+160 bits: ID_CH added to PSEUDO_CH_CM (IA-14)"},
              {"phase": "authentication", "rp9": 2400, "measured": bits["authentication"], "note": ""},
              {"phase": "session key agreement", "rp9": 0, "measured": 0,
               "note": "no frames are sent during §5.5 (counted, not assumed)"}]
    derived = storage.derive_rows("toy")
    table4 = [{"phase": ph, "rp9": r, "derived": d, "note": "" if r == d else "RP9 states no retention policy (AM-07)"}
              for ph, r, d in zip(storage.PHASES, storage.PUBLISHED, derived)]
    table5 = [{"scheme": n, "formula": f, "published_ms": pub, "recomputed_ms": round(comparison.recompute(f), 4),
               "flag": flag} for n, f, pub, flag in comparison.TABLE5]
    table6 = {"features": comparison.F_LABELS, "rows": comparison.TABLE6}
    formal_path = REPO_ROOT / "formal" / "avispa" / "results" / "SUMMARY.json"
    formal = json.loads(formal_path.read_text()) if formal_path.exists() else {"results": {}, "hlpsl": "not obtained"}
    artifacts = sorted((REPO_ROOT / "artifacts" / "eval").glob("compare_*.json"))
    latest = None
    for path in reversed(artifacts):
        if not path.stem.endswith("_quick"):
            latest = {"file": str(path.relative_to(REPO_ROOT)), **json.loads(path.read_text())}
            break
    return {
        "table2": table2, "table3": table3, "table4": table4, "table5": table5, "table6": table6,
        "cost_constants_ms": cost_model.ALL,
        "formal": formal, "security_levels": SECURITY_LEVELS, "limitations": LIMITATIONS,
        "latest_comparison": latest,
    }
