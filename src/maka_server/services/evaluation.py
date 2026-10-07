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
    "rp9_executable": "Our minimally repaired version of RP9's model (fixes D1-D6, D8, D9)",
    "rp9_insider": "Our minimally repaired version of RP9's model, with the intruder as a legitimate CM",
    "maka_e": "MAKA-E key exchange",
    "maka_e_nopsk_control": "MAKA-E without PSK (negative control)",
}
# What a row's verdict means where the verdict alone would mislead (formal/avispa/README.md).
AVISPA_NOTES = {
    "rp9_transcribed": "OFMC reproduces Fig. 9 exactly (SAFE, 1501 nodes, depth 7), but only 3 of 8 transitions can "
                       "ever run, so no authentication goal is exercised: the SAFE is vacuous (OB-11).",
    "rp9_fixed": "Still vacuous: the same 3 of 8 transitions run (D2-D7, D9 are not fixed here).",
    "rp9_executable": "Our minimally repaired version of RP9's model (fixes D1-D6, D8, D9) is UNSAFE because the "
                      "model has no A2 = (ID_BS xor ID_CH)*A1 check (F(r.G) is opaque): a property of the model, "
                      "not by itself evidence of P-01 (OB-12).",
    "rp9_insider": "An insider holding S, in our minimally repaired version of RP9's model. P-01 itself is shown by "
                   "OFMC 2024 on the AnB model, which models the scalar multiplication.",
    "maka_e": "Every transition can run. The untyped CL-AtSe attack is a field-boundary ambiguity the "
              "length-prefixed encoding excludes (tested).",
    "maka_e_nopsk_control": "Negative control: must be, and is, attacked.",
}
# The OFMC 2024 (AnB) models, for the summary table.
ANB_MODELS = {
    "maka_e_ake": "MAKA-E key exchange (AnB)",
    "maka_e_ake_nopsk_control": "MAKA-E without PSK (negative control, AnB)",
    "maka_e_ake_fs": "MAKA-E, PSK leaked after the session (forward secrecy, AnB)",
    "maka_e_ake_fs_nodh_control": "MAKA-E without DH, PSK leaked (negative control, AnB)",
    "rp9_auth": "RP9 authentication, dishonest CH or CM (AnB, scalar multiplication modelled)",
    "rp9_auth_honest_ch": "RP9 authentication, insider CM (P-01; AnB)",
    "rp9_auth_outsider": "RP9 authentication, outsiders only (AnB)",
}
FS_SENTENCE = ("No attack at 1 session; the 2-session trace is impersonation after long-term key compromise, which "
               "the AnB language cannot exclude, so forward secrecy is not established symbolically beyond 1 session.")
# One plain-language sentence per model for the summary table (follow-up cleanup, item 4).
SUMMARY_SENTENCES = {
    "rp9_transcribed": "RP9's model as printed: OFMC gives Fig. 9's SAFE exactly, but only 3 of its 8 steps can ever "
                       "run, so nothing about authentication is actually checked.",
    "rp9_fixed": "Fixing only what the tools reject changes nothing: still SAFE, still only 3 of 8 steps can run.",
    "rp9_executable": "In our minimally repaired version of RP9's model (fixes D1-D6, D8, D9) every step runs and the "
                      "authentication goals are attacked, because the model leaves out the check RP9's "
                      "authentication relies on.",
    "rp9_insider": "In our minimally repaired version, a legitimate member learns the cluster secret sec1 and defeats "
                   "authentication; RP9's specific insider forgery needs the AnB model.",
    "maka_e": "No attack on authentication or key secrecy in 4 sessions with the intruder in either role, and every "
              "step runs. Untyped, CL-AtSe finds a field-boundary trick that the real encoding rejects.",
    "maka_e_nopsk_control": "Without the PSK the same exchange is attacked by every tool, so the model can see the "
                            "attacks it is meant to exclude.",
    "maka_e_ake": "No attack in 1, 2 or 3 sessions.",
    "maka_e_ake_nopsk_control": "Without the PSK the exchange is attacked: the check is sensitive.",
    "maka_e_ake_fs": FS_SENTENCE,
    "maka_e_ake_fs_nodh_control": "Without Diffie-Hellman, the keys of a completed session leak once the PSK leaks: "
                                  "the model detects that loss.",
    "rp9_auth": "With the intruder as a dishonest CH or CM, RP9's authentication is attacked in 1 session.",
    "rp9_auth_honest_ch": "An insider member impersonates the CH to another member (P-01).",
    "rp9_auth_outsider": "Outsiders only: no attack in 1 session. In 2, without a receiver-side nonce record, replay "
                         "succeeds; RP9's replay protection rests entirely on that record, which RP9 does not specify.",
}
OFMC, CL225, CL234 = "OFMC (2006/02/13)", "CL-AtSe 2.2-5", "CL-AtSe 2.3-4"
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
        "formal": formal, "formal_avispa": avispa_rows(), "formal_summary": formal_summary(formal),
        "security_levels": SECURITY_LEVELS, "limitations": LIMITATIONS,
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
    goals: list[dict[str, str]] = []
    for model, label in AVISPA_MODELS.items():
        data = summary["models"].get(model)
        if data is None:
            continue
        probes = data["executability_ofmc2006"]
        executes = sum(v == "executes" for v in probes.values())
        for run in (r for r in data["runs"] if r["goal"] == "all goals"):
            rows.append({"model": model, "label": label, "note": AVISPA_NOTES.get(model, ""),
                         "sessions": data["sessions"], "backend": run["backend"],
                         "verdict": run["verdict"], "violated": run.get("violated", ""),
                         "message": run.get("message", ""), "statistics": run.get("statistics", {}),
                         "file": "formal/avispa/" + run["file"],
                         "executable_transitions": f"{executes}/{len(probes)}" if probes else "",
                         "translated_by_original": data["translation"].get("32", {}).get("accepted", False)})
        for goal in sorted({str(r["goal"]) for r in data["runs"] if r["goal"] != "all goals"}):
            cell = {str(r["backend"]): str(r["verdict"]) for r in data["runs"] if r["goal"] == goal}
            goals.append({"model": model, "label": label, "goal": goal, "ofmc": cell.get(OFMC, "—"),
                          "clatse": cell.get(CL225, "—")})
    return {"obtained": True, "tool_chain": summary["tool_chain"], "paper_fig9": summary["paper_fig9"], "rows": rows,
            "goals": goals}


def _verdicts(data: dict[str, Any], backend: str) -> str:
    """'SAFE', or 'SAFE (untyped: UNSAFE)' when an untyped run exists, for the all-goals runs."""
    runs = {str(r["backend"]): str(r["verdict"]) for r in data["runs"] if r["goal"] == "all goals"}
    v = runs.get(backend, "—")
    untyped = runs.get(f"{backend}, untyped")
    return f"{v} (untyped: {untyped})" if untyped else v


def _transitions(probes: dict[str, str]) -> str:
    """'7/8 (1 probe timed out)': a probe without a verdict is not a step that never runs."""
    runs = sum(v == "executes" for v in probes.values())
    open_ = sum(v not in ("executes", "never executes") for v in probes.values())
    return f"{runs}/{len(probes)}" + (f" ({open_} probe{'s' if open_ > 1 else ''} timed out)" if open_ else "")


def formal_summary(anb: dict[str, Any]) -> list[dict[str, str]]:
    """One row per model for the summary above the detailed formal tables, from the same
    SUMMARY.json files (tests/test_formal.py checks it against them)."""
    path = FORMAL_DIR / "results" / "avispa" / "SUMMARY.json"
    rows: list[dict[str, str]] = []
    if path.exists():
        models = json.loads(path.read_text())["models"]
        for model, label in AVISPA_MODELS.items():
            data = models.get(model)
            if data is None:
                continue
            probes = data["executability_ofmc2006"]
            cl = _verdicts(data, CL225)
            other = {str(r["verdict"]) for r in data["runs"] if r["goal"] == "all goals" and r["backend"] == CL234}
            if other and other != {cl.split(" ")[0]}:
                cl += f"; 2.3-4: {other.pop()}"
            rows.append({"model": model, "kind": "AVISPA (HLPSL)", "represents": label, "ofmc": _verdicts(data, OFMC),
                         "clatse": cl,
                         "transitions": _transitions(probes),
                         "sentence": SUMMARY_SENTENCES[model]})
    for model, label in ANB_MODELS.items():
        runs = anb.get("results", {}).get(model, [])
        if not runs:
            continue
        ofmc = "; ".join(f"{r['sessions']} session{'s' if r['sessions'] > 1 else ''}: "
                         f"{'attack' if r['summary'] == 'ATTACK_FOUND' else 'no attack'}" for r in runs)
        rows.append({"model": model, "kind": "OFMC 2024 (AnB)", "represents": label, "ofmc": ofmc,
                     "clatse": "not run (AnB is read by OFMC only)", "transitions": "—",
                     "sentence": SUMMARY_SENTENCES[model]})
    return rows
