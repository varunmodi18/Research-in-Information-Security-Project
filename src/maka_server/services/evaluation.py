"""Evaluation (FR-17, IMPLEMENTATION_PLAN.md M7-T5/T6).

* The `evaluation` job runs the original-vs-enhanced comparison (eval/bench/compare.py) on
  fresh lab runtimes and stores the result as an EvaluationRun.
* `reference()` gathers what the Evaluation page shows besides runs: RP9 Tables 2-6 reproduced
  with their annotations, the formal results (AVISPA on the HLPSL models and OFMC 2024 on the AnB
  models, each read from its committed SUMMARY.json, or "not obtained"), parameter security levels,
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
FORMAL_DIR = REPO_ROOT / "formal" / "avispa"
AVISPA_MODELS = {
    "rp9_transcribed": "RP9 Figs. 4-8 as printed",
    "rp9_fixed": "RP9, fixing only what a tool rejects (D1, D8)",
    "rp9_executable": "RP9 made executable (D1-D6, D8, D9)",
    "rp9_insider": "RP9 executable, intruder is a legitimate CM",
    "maka_e": "MAKA-E key exchange",
    "maka_e_nopsk_control": "MAKA-E without PSK (negative control)",
}
# What a row's verdict means where the verdict alone would mislead (formal/avispa/README.md).
AVISPA_NOTES = {
    "rp9_transcribed": "OFMC reproduces Fig. 9 exactly (SAFE, 1501 nodes, depth 7), but only 3 of 8 transitions can "
                       "ever run, so no authentication goal is exercised: the SAFE is vacuous (OB-11).",
    "rp9_fixed": "Still vacuous: the same 3 of 8 transitions run (D2-D7, D9 are not fixed here).",
    "rp9_executable": "Attacked because RP9's HLPSL has no A2 = (ID_BS xor ID_CH)*A1 check (F(r.G) is opaque): a "
                      "property of the model, not by itself evidence of P-01 (OB-12).",
    "rp9_insider": "An insider holding S. P-01 itself is shown by OFMC 2024 on the AnB model, which models the "
                   "scalar multiplication.",
    "maka_e": "Every transition can run. The untyped CL-AtSe attack is a field-boundary ambiguity the "
              "length-prefixed encoding excludes (tested).",
    "maka_e_nopsk_control": "Negative control: must be, and is, attacked.",
}
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
    formal_path = FORMAL_DIR / "results" / "SUMMARY.json"
    formal = json.loads(formal_path.read_text()) if formal_path.exists() else {"results": {}, "hlpsl": "not obtained"}
    artifacts = sorted((REPO_ROOT / "artifacts" / "eval").glob("compare_*.json"))
    latest = None
    for path in reversed(artifacts):
        if not path.stem.endswith("_quick"):
            latest = {"file": str(path.relative_to(REPO_ROOT)), **json.loads(path.read_text())}
            break
    return {
        "table2": table2, "table3": table3, "table4": table4, "table5": table5, "table6": table6,
        "cost_constants_ms": cost_model.ALL, "transcription_check": comparison.TRANSCRIPTION_CHECK,
        "formal": formal, "formal_avispa": avispa_rows(), "security_levels": SECURITY_LEVELS, "limitations": LIMITATIONS,
        "latest_comparison": latest,
    }


def avispa_rows() -> dict[str, Any]:
    """The AVISPA table (follow-up Part C4): one row per model and back-end for the run with all
    goals, plus that back-end's one-goal-at-a-time verdicts and the model's executability probes.
    Everything is copied from formal/avispa/results/avispa/SUMMARY.json, nothing is computed."""
    path = FORMAL_DIR / "results" / "avispa" / "SUMMARY.json"
    if not path.exists():
        return {"obtained": False, "rows": []}
    summary = json.loads(path.read_text())
    rows = []
    for model, label in AVISPA_MODELS.items():
        data = summary["models"].get(model)
        if data is None:
            continue
        probes = data["executability_ofmc2006"]
        executes = sum(v == "executes" for v in probes.values())
        for run in (r for r in data["runs"] if r["goal"] == "all goals"):
            per_goal = [{"goal": r["goal"], "verdict": r["verdict"]} for r in data["runs"]
                        if r["goal"] != "all goals" and r["backend"] == run["backend"]]
            rows.append({"model": model, "label": label, "note": AVISPA_NOTES.get(model, ""),
                         "sessions": data["sessions"], "backend": run["backend"],
                         "verdict": run["verdict"], "violated": run.get("violated", ""),
                         "message": run.get("message", ""), "statistics": run.get("statistics", {}),
                         "file": "formal/avispa/" + run["file"], "per_goal": per_goal,
                         "executable_transitions": f"{executes}/{len(probes)}" if probes else "",
                         "translated_by_original": data["translation"].get("32", {}).get("accepted", False)})
    return {"obtained": True, "tool_chain": summary["tool_chain"], "paper_fig9": summary["paper_fig9"], "rows": rows}
