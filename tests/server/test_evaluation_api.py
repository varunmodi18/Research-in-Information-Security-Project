"""M7-T6 through the API: the evaluation job stores a run; reference material is served to viewers;
evaluations are refused on product networks."""

from __future__ import annotations

import json

from .conftest import Api


def test_evaluation_job_stores_a_run(operator_api: Api) -> None:
    lab = operator_api.create_network(kind="lab", mode="enhanced", params="toy", template="paper")
    job = operator_api.run_job(lab["id"], "evaluation", {"topologies": ["paper"], "params": ["toy"], "seeds": 1})
    assert job["state"] == "succeeded", job
    runs = operator_api.get("/api/evaluation/runs").json()
    assert runs[0]["id"] == job["result"]["run_id"] and runs[0]["state"] == "succeeded"
    run = operator_api.get(f"/api/evaluation/runs/{runs[0]['id']}").json()
    variants = {r["variant"] for r in run["result"]["results"]}
    assert variants == {"original+secure", "original+clear", "enhanced"}
    enhanced = next(r for r in run["result"]["results"] if r["variant"] == "enhanced")
    assert enhanced["pairings_per_cm"] <= 2
    assert {t["metric"] for t in run["result"]["thresholds"]} >= {"pairings per CM during onboarding"}


def test_evaluation_validation_and_kind(operator_api: Api) -> None:
    lab = operator_api.create_network(kind="lab", mode="enhanced", params="toy", template="paper")
    bad = operator_api.run_job(lab["id"], "evaluation", {"topologies": ["huge"]})
    assert bad["state"] == "failed" and bad["error"].startswith("VALIDATION_FAILED")
    product = operator_api.create_network(kind="product", mode="enhanced", params="toy", template="paper")
    r = operator_api.job(product["id"], "evaluation", {})
    assert r.status_code == 422 and r.json()["code"] == "MODE_NOT_ALLOWED"


def test_reference_material(api: Api) -> None:
    api.login("viewer")
    ref = api.get("/api/evaluation/reference").json()
    # Table 2 as measured: 2 pairings on the CM path vs RP9's stated 1T_P per role
    assert ref["table2"]["CM"]["measured"]["T_P"] >= 1
    assert [r["rp9"] for r in ref["table3"]] == [640, 1760, 2400, 0]
    flags = " ".join(r["flag"] for r in ref["table5"])
    assert "ER-02" in flags and "AM-04" in flags
    assert {"demo", "secure"} <= set(ref["security_levels"])
    assert any("not a proof" in line for line in ref["limitations"])
    assert ref["formal"]["results"] or ref["formal"].get("hlpsl") == "not obtained"
    # nothing secret-looking in reference material (§4.4)
    assert "Pr_" not in json.dumps(ref["table2"])


def test_reference_serves_the_committed_behaviour_results(api: Api) -> None:
    """docs/BEHAVIOUR.md: the Evaluation page's experimental section reads the latest committed
    results artefact (without the per-window explanation list), and it is labelled as such."""
    from pathlib import Path

    api.login("viewer")
    b = api.get("/api/evaluation/reference").json()["behaviour"]
    root = Path(__file__).resolve().parents[2]
    latest = max((root / "artifacts" / "behaviour").glob("results_*.json"))
    committed = json.loads(latest.read_text())
    assert b["file"] == str(latest.relative_to(root)) and b["date"] == committed["date"]
    assert b["experimental"] is True and b["results"] == committed["results"]
    assert b["benign_false_alarms"] == committed["benign_false_alarms"]
    assert "explanations" not in b and b["explained_windows"] == len(committed["explanations"])
    assert {r["detector"] for r in b["results"]} == {"z-score baseline", "Isolation Forest"}
    assert any("Alerts only" in line for line in b["limitations"])
