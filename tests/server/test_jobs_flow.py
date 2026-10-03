"""M3-T3..T5: original-mode lab onboarding through the API, jobs, recovery, SSE, keystore at rest."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from sqlalchemy import select

from maka.runtime.keystore import SecretClass
from maka_server import models
from maka_server.keystore_store import EncryptedKeystoreAdapter
from maka_server.main import create_app
from maka_server.settings import Settings

from ..leakscan import scan_bytes
from .conftest import Api


def test_m3_t5_onboard_lab_original_network(operator_api: Api, lab_paper: dict[str, Any]) -> None:
    nid = lab_paper["id"]
    job = operator_api.run_job(nid, "onboard")
    assert job["state"] == "succeeded", job
    labels = [f["label"] for f in operator_api.get(f"/api/networks/{nid}/frames").json()["items"]]
    for label in ("BEACON", "PSEUDO_BS_CH", "PSEUDO_CH_CM", "EM1", "EM2", "EM3"):
        assert label in labels
    detail = operator_api.get(f"/api/networks/{nid}").json()
    assert {d["ident"]: d["status"] for d in detail["devices"]} == {
        "BS-01": "active", "CH-01": "active", "CM-0101": "active"}
    events = operator_api.get(f"/api/events?network={nid}").json()["items"]
    assert sum(e["type"] == "ORIG_AUTH_OK" for e in events) == 3
    frame = operator_api.get(f"/api/networks/{nid}/frames?label=EM1").json()["items"][0]
    assert frame["verdict"] == "ACCEPT" and {"name": "A2' == A2", "ok": True, "reason": ""} in frame["checks"]


def test_step_mode_and_readings(operator_api: Api, lab_paper: dict[str, Any]) -> None:
    nid = lab_paper["id"]
    assert operator_api.run_job(nid, "onboard", {"step_mode": True})["result"]["mode"] == "step"
    stepped = operator_api.run_job(nid, "step", {"count": 3})
    assert stepped["result"]["steps"] == 3
    assert len(operator_api.get(f"/api/networks/{nid}/frames").json()["items"]) == 3
    operator_api.run_job(nid, "step", {"until": "quiescent"})
    sent = operator_api.run_job(nid, "send_readings", {"count": 2})
    assert sent["state"] == "succeeded" and sent["result"]["sent"] == 2
    events = operator_api.get(f"/api/events?network={nid}&type=AGGREGATION_UNDEFINED").json()["items"]
    assert len(events) == 2  # RP9 stops at the CH (AM-05)


def test_forward_variant_delivers_readings(operator_api: Api) -> None:
    net = operator_api.create_network(kind="lab", mode="original", params="toy", template="small", seed=3,
                                      forward_ciphertexts=True)
    operator_api.run_job(net["id"], "onboard")
    operator_api.run_job(net["id"], "send_readings", {"count": 1})
    readings = operator_api.get(f"/api/networks/{net['id']}/readings").json()["items"]
    assert sorted(r["device"] for r in readings) == ["CM-0101", "CM-0102", "CM-0103"]
    assert all(r["value"].startswith('{"kind": "simulated reading"') for r in readings)


def test_v_rec_01_worker_failure_mid_onboarding(operator_api: Api, app, lab_paper) -> None:  # type: ignore[no-untyped-def]
    nid = lab_paper["id"]
    failed = operator_api.run_job(nid, "onboard", {"_fail_at_step": 5})
    assert failed["state"] == "failed" and "injected worker failure" in failed["error"]
    assert operator_api.get(f"/api/networks/{nid}").json()["status"] == "failed"
    rt = app.state.ctx.registry.peek(nid)
    for dev in rt.scheduler.devices.values():  # recovery rule: nothing session-derived remains
        assert not dev.keystore.has("ksym") and dev.status == "provisioned"
    assert operator_api.get(f"/api/networks/{nid}/devices/CM-0101").json()["sessions"] == []
    assert operator_api.run_job(nid, "onboard")["state"] == "succeeded"


def test_v_rec_02_restart_aborts_running_jobs(settings: Settings) -> None:
    app1 = create_app(settings)
    ctx = app1.state.ctx
    with ctx.db.session() as db:
        db.add(models.Job(network_id=None, type="onboard", args_json={}, idempotency_key="left-running",
                          state="running"))
    aborted = create_app(settings).state.ctx.jobs.recover_on_startup()
    with ctx.db.session() as db:
        job = db.scalar(select(models.Job).where(models.Job.idempotency_key == "left-running"))
        assert job is not None and job.id in aborted and job.state == "aborted"


def test_v_rec_03_serialised_jobs_and_idempotency(operator_api: Api, lab_paper: dict[str, Any]) -> None:
    nid = lab_paper["id"]
    first = operator_api.job(nid, "onboard", key="same-key-123")
    again = operator_api.job(nid, "onboard", key="same-key-123")
    assert first.json()["job_id"] == again.json()["job_id"] and again.json()["created"] is False
    conflict = operator_api.job(nid, "step", {"count": 1}, key="same-key-123")
    assert conflict.status_code == 409 and conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"
    second = operator_api.job(nid, "send_readings", {"count": 1})
    a = operator_api.wait(first.json()["job_id"])
    b = operator_api.wait(second.json()["job_id"])
    assert a["state"] == b["state"] == "succeeded"
    assert a["finished_at"] <= b["finished_at"]  # serialised: the second ran after the first


def test_cancel_queued_job(operator_api: Api, app, lab_paper) -> None:  # type: ignore[no-untyped-def]
    nid = lab_paper["id"]
    gate = threading.Event()
    rt = app.state.ctx.registry.get(nid)
    rt.lock.acquire()  # hold the network so the job stays queued/blocked
    try:
        j1 = operator_api.job(nid, "onboard").json()["job_id"]
        j2 = operator_api.job(nid, "send_readings", {"count": 1}).json()["job_id"]
        assert operator_api.post(f"/api/jobs/{j2}/cancel").status_code == 202
    finally:
        rt.lock.release()
        gate.set()
    assert operator_api.wait(j1)["state"] == "succeeded"
    assert operator_api.wait(j2)["state"] == "cancelled"


def _sse_ids(text: str) -> list[int]:
    return [int(line[4:]) for line in text.splitlines() if line.startswith("id: ")]


def test_v_sse_01_resume_with_last_event_id(operator_api: Api, lab_paper: dict[str, Any]) -> None:
    nid = lab_paper["id"]
    operator_api.run_job(nid, "onboard")
    full = operator_api.get(f"/api/networks/{nid}/stream?once=true").text
    ids = _sse_ids(full)
    assert ids == sorted(ids) and len(ids) == len(set(ids)) and len(ids) > 10
    assert "event: frame" in full and "event: security_event" in full and "event: job_progress" in full
    cut = ids[len(ids) // 2]
    resumed = operator_api.get(f"/api/networks/{nid}/stream?once=true",
                               headers={"Last-Event-ID": str(cut)}).text
    assert _sse_ids(resumed) == [i for i in ids if i > cut]


def test_keystore_at_rest_is_encrypted_and_bound(app, lab_paper) -> None:  # type: ignore[no-untyped-def]
    ctx = app.state.ctx
    with ctx.db.session() as db:
        rows = list(db.scalars(select(models.KeystoreEntry)))
        dev = {d.id: d.ident for d in db.scalars(select(models.Device))}
    assert rows
    adapter = EncryptedKeystoreAdapter(ctx.registry.kek, lab_paper["id"])
    with ctx.db.session() as db:
        loaded = adapter.load(db, rows[0].device_id, dev[rows[0].device_id])
        assert loaded
        wrong = EncryptedKeystoreAdapter(bytes(32), lab_paper["id"])
        try:
            wrong.load(db, rows[0].device_id, dev[rows[0].device_id])
            raise AssertionError("decryption under the wrong KEK must fail")
        except RuntimeError:
            pass


def test_v_leak_04_db_file_has_no_plaintext_secrets(operator_api: Api, app, settings: Settings) -> None:  # type: ignore[no-untyped-def]
    net = operator_api.create_network(kind="lab", mode="original", params="demo", template="paper", seed=11)
    secrets: dict[str, object] = {}
    rt = app.state.ctx.registry.get(net["id"])
    for dev in rt.scheduler.devices.values():
        for name, value in dev.keystore.snapshot().items():
            if dev.keystore.cls_of(name) == SecretClass.SECRET:
                secrets[f"{dev.identity}.{name}.pre"] = value
    operator_api.run_job(net["id"], "onboard")
    rt = app.state.ctx.registry.get(net["id"])
    for dev in rt.scheduler.devices.values():
        for name, value in dev.keystore.snapshot().items():
            if dev.keystore.cls_of(name) == SecretClass.SECRET:
                secrets[f"{dev.identity}.{name}"] = value
    assert any(k.endswith(".pr") for k in secrets) and any(".k.pre" in k for k in secrets)
    db_path = Path(settings.db_url.removeprefix("sqlite:///"))
    blobs = [p.read_bytes() for p in db_path.parent.glob(db_path.name + "*")]
    assert scan_bytes(secrets, blobs) == []
