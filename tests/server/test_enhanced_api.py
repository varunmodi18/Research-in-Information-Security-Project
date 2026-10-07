"""M5-T1: MAKA-E product networks through the API, recovery in enhanced mode, and leakage
checks across every GET endpoint, the SSE stream and the exports (V-LEAK-02..04)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from maka.runtime.keystore import SecretClass
from maka_server.settings import Settings

from ..leakscan import scan_bytes, scan_text
from .conftest import Api


def _product(api: Api, template: str = "small", **kw: Any) -> dict[str, Any]:
    return api.create_network(kind="product", mode="enhanced", params="toy", template=template, **kw)


def _statuses(api: Api, nid: int) -> dict[str, str]:
    return {d["ident"]: d["status"] for d in api.get(f"/api/networks/{nid}").json()["devices"]}


def _events(api: Api, nid: int, etype: str) -> list[dict[str, Any]]:
    return api.get(f"/api/events?network={nid}&type={etype}&limit=1000").json()["items"]  # type: ignore[no-any-return]


def test_journey_j1_onboard_and_transmit(operator_api: Api) -> None:
    net = _product(operator_api, "net")
    assert operator_api.run_job(net["id"], "onboard")["state"] == "succeeded"
    assert set(_statuses(operator_api, net["id"]).values()) == {"active"}
    assert len(_events(operator_api, net["id"], "HANDSHAKE_OK")) == 21  # J1: one per handshake
    operator_api.run_job(net["id"], "send_readings", {"count": 2})
    readings = operator_api.get(f"/api/networks/{net['id']}/readings").json()["items"]
    assert len(readings) == 18 and len(_events(operator_api, net["id"], "DATA_ACCEPTED")) == 18
    sessions = operator_api.get(f"/api/networks/{net['id']}/devices/CM-0101").json()["sessions"]
    assert {(s["purpose"], s["state"]) for s in sessions} == {("CM-BS", "ESTABLISHED"), ("CM-CH", "ESTABLISHED")}
    assert all(set(s) == {"a", "b", "purpose", "state", "sid_hex", "established_step", "epoch", "sent", "recv",
                          "superseded_by"} for s in sessions)


def test_journey_j3_revoke_then_reprovision(operator_api: Api) -> None:
    net = _product(operator_api)
    nid = net["id"]
    operator_api.run_job(nid, "onboard")
    assert operator_api.run_job(nid, "revoke", {"device": "CM-0102"})["state"] == "succeeded"
    assert _statuses(operator_api, nid)["CM-0102"] == "revoked"
    assert _events(operator_api, nid, "DEVICE_REVOKED") and _events(operator_api, nid, "REVOKE_ACKED")
    operator_api.run_job(nid, "send_readings", {"devices": ["CM-0102"]})
    assert _events(operator_api, nid, "UNAUTHENTICATED_PEER")
    again = operator_api.run_job(nid, "revoke", {"device": "CM-0102"})
    assert again["state"] == "failed" and again["error"].startswith("REVOKED_IDENTITY")
    reuse = operator_api.run_job(nid, "reprovision", {"device": "CM-0102", "new_ident": "CM-0102"})
    assert reuse["state"] == "failed" and "REVOKED_IDENTITY" in reuse["error"]
    ok = operator_api.run_job(nid, "reprovision", {"device": "CM-0102", "new_ident": "CM-0102-r1"})
    assert ok["state"] == "succeeded", ok
    assert _statuses(operator_api, nid)["CM-0102-r1"] == "active"


def test_rekey_cluster_rotates_keys(operator_api: Api) -> None:
    net = _product(operator_api)
    operator_api.run_job(net["id"], "onboard")
    assert operator_api.run_job(net["id"], "rekey", {"device": "CH-01"})["state"] == "succeeded"
    assert len(_events(operator_api, net["id"], "KEY_ROTATED")) == 2 * (1 + 2 * 3)


def test_designate_replacement_ch(operator_api: Api) -> None:
    net = _product(operator_api)
    nid = net["id"]
    operator_api.run_job(nid, "onboard")
    operator_api.run_job(nid, "revoke", {"device": "CH-01"})
    job = operator_api.run_job(nid, "designate", {"cluster": "CH-01", "ch": "CH-01-r1"})
    assert job["state"] == "succeeded", job
    st = _statuses(operator_api, nid)
    assert st["CH-01-r1"] == "active" and all(st[c] == "active" for c in ("CM-0101", "CM-0102", "CM-0103"))


def test_d2_console_shows_ch_revoked_awaiting_redesignation(operator_api: Api) -> None:
    nid = _product(operator_api)["id"]
    operator_api.run_job(nid, "onboard")
    operator_api.run_job(nid, "revoke", {"device": "CH-01"})
    operator_api.run_job(nid, "send_readings", {"devices": ["CM-0101"]})
    devices = {d["ident"]: d for d in operator_api.get(f"/api/networks/{nid}").json()["devices"]}
    for cm in ("CM-0101", "CM-0102", "CM-0103"):
        assert (devices[cm]["designated"], devices[cm]["designation_state"]) == (
            "CH-01", "ch_revoked_awaiting_redesignation")
    assert devices["CM-0101"]["undelivered"] == 1 and devices["CH-01"]["designation_state"] is None
    detail = operator_api.get(f"/api/networks/{nid}/devices/CM-0102").json()["device"]
    assert detail["designation_state"] == "ch_revoked_awaiting_redesignation"
    operator_api.run_job(nid, "designate", {"cluster": "CH-01", "ch": "CH-01-r1"})
    devices = {d["ident"]: d for d in operator_api.get(f"/api/networks/{nid}").json()["devices"]}
    assert {(devices[c]["designated"], devices[c]["designation_state"]) for c in ("CM-0101", "CM-0102", "CM-0103")} \
        == {("CH-01-r1", "ok")}
    assert devices["CM-0101"]["undelivered"] == 1


def test_d2_a_revoked_member_is_not_listed_as_awaiting(operator_api: Api) -> None:
    nid = _product(operator_api)["id"]
    operator_api.run_job(nid, "onboard")
    operator_api.run_job(nid, "revoke", {"device": "CM-0103"})
    operator_api.run_job(nid, "revoke", {"device": "CH-01"})
    devices = {d["ident"]: d for d in operator_api.get(f"/api/networks/{nid}").json()["devices"]}
    assert devices["CM-0101"]["designation_state"] == "ch_revoked_awaiting_redesignation"
    assert devices["CM-0103"]["status"] == "revoked" and devices["CM-0103"]["designation_state"] is None


def test_reset_network(operator_api: Api) -> None:
    net = _product(operator_api, "paper")
    nid = net["id"]
    operator_api.run_job(nid, "onboard")
    operator_api.run_job(nid, "revoke", {"device": "CM-0101"})
    assert operator_api.run_job(nid, "reset_network")["state"] == "succeeded"
    assert set(_statuses(operator_api, nid).values()) == {"provisioned", "active"}  # BS active
    assert operator_api.run_job(nid, "onboard")["state"] == "succeeded"


def test_periodic_readings_interleave_with_jobs(operator_api: Api) -> None:
    net = _product(operator_api, "paper")
    nid = net["id"]
    operator_api.run_job(nid, "onboard")
    operator_api.run_job(nid, "start_periodic", {"every_steps": 5})
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and len(operator_api.get(f"/api/networks/{nid}/readings").json()["items"]) < 3:
        time.sleep(0.2)
    assert operator_api.run_job(nid, "rekey", {"device": "CM-0101"})["state"] == "succeeded"
    operator_api.run_job(nid, "stop_periodic")
    assert len(operator_api.get(f"/api/networks/{nid}/readings").json()["items"]) >= 3


def test_rp9_networks_refuse_revocation(operator_api: Api, lab_paper: dict[str, Any]) -> None:
    job = operator_api.run_job(lab_paper["id"], "revoke", {"device": "CM-0101"})
    assert job["state"] == "failed" and job["error"].startswith("MODE_NOT_ALLOWED")


def test_v_web_06_lab_jobs_refused_on_product(operator_api: Api) -> None:
    net = _product(operator_api, "paper")
    r = operator_api.job(net["id"], "lab_scenario", {"scenario": "L3"})
    assert r.status_code == 422 and r.json()["code"] == "MODE_NOT_ALLOWED"


def test_v_rec_01_enhanced_failure_aborts_sessions(operator_api: Api, app) -> None:  # type: ignore[no-untyped-def]
    net = _product(operator_api, "small")
    nid = net["id"]
    failed = operator_api.run_job(nid, "onboard", {"_fail_at_step": 12})
    assert failed["state"] == "failed"
    rt = app.state.ctx.registry.peek(nid)
    for dev in rt.scheduler.devices.values():
        assert not [n for n in dev.keystore.names() if n.startswith(("sess:", "eph:", "hs:"))]
        assert dev.status in ("provisioned", "registered", "active") and (dev.role == "BS" or dev.status != "active")
    sessions = operator_api.get(f"/api/networks/{nid}/devices/CH-01").json()["sessions"]
    assert sessions and all(s["state"] == "ABORTED" for s in sessions)
    assert operator_api.run_job(nid, "onboard")["state"] == "succeeded"
    assert set(_statuses(operator_api, nid).values()) == {"active"}


def _all_secrets(app) -> dict[str, object]:  # type: ignore[no-untyped-def]
    out: dict[str, object] = {}
    reg = app.state.ctx.registry
    for nid in list(reg._live):
        for dev in reg.peek(nid).scheduler.devices.values():
            for name, value in dev.keystore.snapshot().items():
                if dev.keystore.cls_of(name) == SecretClass.SECRET:
                    out[f"{nid}/{dev.identity}/{name}"] = value
    return out


def test_v_leak_02_03_04_no_secret_in_api_sse_exports_or_db(app, settings: Settings) -> None:  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        api = Api(client)
        api.login("operator")
        prod = _product(api, "small", name="leak-prod")
        lab = api.create_network(name="leak-lab", kind="lab", mode="original", params="toy", template="small", seed=5)
        for n in (prod, lab):
            api.run_job(n["id"], "onboard")
            api.run_job(n["id"], "send_readings", {"count": 1})
        secrets = _all_secrets(app)
        assert any(k.endswith("/pr") for k in secrets) and any("/sess:" in k for k in secrets)
        api.login("admin")
        texts = []
        for n in (prod, lab):
            nid = n["id"]
            for path in (f"/api/networks/{nid}", f"/api/networks/{nid}/frames?limit=1000",
                         f"/api/networks/{nid}/readings", f"/api/events?network={nid}&limit=1000",
                         f"/api/events/export?format=csv&network={nid}", f"/api/events/export?format=json&network={nid}",
                         f"/api/networks/{nid}/stream?once=true"):
                texts.append(api.get(path).text)
            for d in api.get(f"/api/networks/{nid}").json()["devices"]:
                texts.append(api.get(f"/api/networks/{nid}/devices/{d['ident']}").text)
        for path in ("/api/networks", "/api/auth/me", "/api/admin/users", "/api/admin/audit", "/api/openapi.json"):
            texts.append(api.get(path).text)
        for job_id in range(1, 9):
            texts.append(api.get(f"/api/jobs/{job_id}").text)
        assert scan_text(secrets, texts) == []  # V-LEAK-02, -03
    db = Path(settings.db_url.removeprefix("sqlite:///"))
    assert scan_bytes(secrets, [p.read_bytes() for p in db.parent.glob(db.name + "*")]) == []  # V-LEAK-04
