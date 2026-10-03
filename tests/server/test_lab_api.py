"""M6-T1/T3 through the API: lab scenarios on lab networks, evidence stored under a run tag,
no secret values in results; migrations upgrade an older populated database."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from maka_server.migrate import upgrade

from .conftest import Api


def test_lab_scenario_job_both_modes(operator_api: Api) -> None:
    lab = operator_api.create_network(kind="lab", mode="original", params="toy", template="small", seed=20260927)
    scenarios = operator_api.get("/api/lab/scenarios").json()
    assert [s["id"] for s in scenarios] == [f"L{i}" for i in range(1, 9)]
    job = operator_api.run_job(lab["id"], "lab_scenario", {"scenario": "L3"})
    assert job["state"] == "succeeded", job
    runs: dict[str, Any] = job["result"]["runs"]
    assert runs["original"]["result"] == "ATTACK SUCCEEDED" and runs["enhanced"]["result"] == "ATTACK BLOCKED"
    for mode, run in runs.items():
        assert run["matches_expectation"] is True
        frames = operator_api.get(f"/api/networks/{lab['id']}/frames?run_tag={run['run_tag']}&limit=1000").json()["items"]
        assert {f["id"] for f in frames} >= set(run["evidence_frame_rows"]) and run["evidence_frame_rows"], mode
        assert all(f["run_tag"] == run["run_tag"] for f in frames)
        events = operator_api.get(f"/api/events?run_tag={run['run_tag']}&limit=1000").json()["items"]
        assert {e["id"] for e in events} >= set(run["evidence_event_rows"])
        assert any(e["type"] == "LAB_ATTACK_RESULT" for e in events)
    # the lab network's own frame log is not mixed with scenario evidence
    assert operator_api.get(f"/api/networks/{lab['id']}/frames").json()["items"] == []


def test_l5_result_has_names_not_values(operator_api: Api) -> None:
    lab = operator_api.create_network(kind="lab", mode="enhanced", params="toy", template="small", seed=7)
    job = operator_api.run_job(lab["id"], "lab_scenario", {"scenario": "L5"})
    text = json.dumps(job["result"])
    for run in job["result"]["runs"].values():
        assert run["secrets_obtained"]
    hexes = [h for h in re.findall(r"[0-9a-f]{32,}", text)]
    names_text = json.dumps([r["secrets_obtained"] for r in job["result"]["runs"].values()])
    assert all(h in names_text for h in hexes)  # only public session ids, inside entry names


def test_scenario_validation(operator_api: Api) -> None:
    lab = operator_api.create_network(kind="lab", mode="original", params="toy", template="small")
    bad = operator_api.run_job(lab["id"], "lab_scenario", {"scenario": "L99"})
    assert bad["state"] == "failed" and bad["error"].startswith("VALIDATION_FAILED")


def test_migration_upgrades_a_populated_m3_database(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'old.db'}"
    upgrade(url, "0001")
    con = sqlite3.connect(tmp_path / "old.db")
    con.execute("INSERT INTO networks (id, created_at, name, kind, mode, params, template, status, "
                "bs_device_id, step, options_json) VALUES (1, '2026-10-03', 'old', 'lab', 'original', 'toy', "
                "'paper', 'idle', 'BS-01', 3, '{}')")
    con.execute("INSERT INTO frames (id, created_at, network_id, frame_id, step, sent_step, src, dst, label, "
                "bytes_len, paper_bits, verdict, fate, checks_json) VALUES (1, '2026-10-03', 1, 1, 1, 0, 'A', "
                "'B', 'EM1', 10, 800, 'ACCEPT', 'delivered', '[]')")
    con.commit()
    con.close()
    upgrade(url)
    con = sqlite3.connect(tmp_path / "old.db")
    assert con.execute("SELECT label, run_tag FROM frames").fetchall() == [("EM1", None)]
    assert con.execute("SELECT version_num FROM alembic_version").fetchone() == ("0002",)
