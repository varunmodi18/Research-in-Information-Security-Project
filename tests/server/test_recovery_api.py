"""Cluster-head replacement through the API (docs/RECOVERY.md): status read by viewers, recovery
run by operators only, lab-only fault injection, and the alert on a lossy CH."""

from __future__ import annotations

from typing import Any

from .conftest import Api


def _onboarded(api: Api, **body: Any) -> dict[str, Any]:
    net = api.create_network(params="toy", template="small", **body)
    assert api.run_job(net["id"], "onboard")["state"] == "succeeded"
    return net


def _devices(api: Api, nid: int) -> dict[str, dict[str, Any]]:
    return {d["ident"]: d for d in api.get(f"/api/networks/{nid}").json()["devices"]}


def test_status_lists_ranked_candidates_and_viewers_can_read_it(operator_api: Api) -> None:
    net = _onboarded(operator_api)
    operator_api.login("viewer")
    body = operator_api.get(f"/api/networks/{net['id']}/recovery").json()
    assert body["available"] is True and body["trigger_detector"] == "z-score baseline"
    assert body["trust_detector"] in ("Isolation Forest", "z-score baseline")
    (cluster,) = body["clusters"]
    assert cluster["cluster"] == "CH-01" and cluster["ch"] == "CH-01" and cluster["suspected"] is False
    assert sorted(c["ident"] for c in cluster["candidates"]) == ["CM-0101", "CM-0102", "CM-0103"]
    assert cluster["recommended"] == cluster["candidates"][0]["ident"]
    assert set(cluster["candidates"][0]) == {"ident", "trust", "reliability", "rejections", "rejections_norm", "score"}
    # viewers cannot act
    r = operator_api.job(net["id"], "recover_cluster", {"cluster": "CH-01", "member": "CM-0101"})
    assert r.status_code == 403


def test_operator_promotes_a_member_and_the_cluster_recovers(operator_api: Api) -> None:
    net = _onboarded(operator_api)
    job = operator_api.run_job(net["id"], "recover_cluster", {"cluster": "CH-01", "member": "CM-0102"})
    assert job["state"] == "succeeded", job
    assert job["result"]["replaced"] == "CH-01" and job["result"]["members_active"] == ["CM-0101", "CM-0103"]
    devs = _devices(operator_api, net["id"])
    assert devs["CM-0102"]["role"] == "CH" and devs["CM-0102"]["status"] == "active"
    assert devs["CH-01"]["status"] == "revoked"
    assert all(devs[m]["designated"] == "CM-0102" and devs[m]["status"] == "active" for m in ("CM-0101", "CM-0103"))
    status = operator_api.get(f"/api/networks/{net['id']}/recovery").json()
    assert [c["ch"] for c in status["clusters"]] == ["CM-0102"]
    # readings flow through the new cluster head
    assert operator_api.run_job(net["id"], "send_readings", {"devices": ["CM-0101", "CM-0103"]})["state"] == "succeeded"
    events = operator_api.get(f"/api/events?network={net['id']}&type=DATA_ACCEPTED&limit=200").json()["items"]
    assert {e["details"].get("via") for e in events if e["step"] > job["result"]["steps"]} >= {"CM-0102"}


def test_promotion_is_refused_for_non_members(operator_api: Api) -> None:
    net = _onboarded(operator_api)
    assert operator_api.run_job(net["id"], "revoke", {"device": "CM-0103"})["state"] == "succeeded"
    # refused at submission, so no job fails and the network is not reset by the §4.8 rule
    for member in ("CM-0103", "BS-01", "CH-01"):
        r = operator_api.job(net["id"], "recover_cluster", {"cluster": "CH-01", "member": member})
        assert r.status_code == 422 and r.json()["code"] == "VALIDATION_FAILED", (member, r.text)
    unknown = operator_api.job(net["id"], "recover_cluster", {"cluster": "CH-09", "member": "CM-0101"})
    assert unknown.status_code == 404
    devs = _devices(operator_api, net["id"])
    assert devs["CH-01"]["status"] == "active" and devs["CM-0101"]["status"] == "active"


def test_fault_injection_is_lab_only_and_raises_the_alert(operator_api: Api) -> None:
    product = _onboarded(operator_api)
    r = operator_api.job(product["id"], "inject_fault", {"device": "CH-01"})
    assert r.status_code == 422 and r.json()["code"] == "MODE_NOT_ALLOWED"
    lab = _onboarded(operator_api, kind="lab", mode="enhanced", seed=3)
    for args in ({"device": "CM-0101"}, {"device": "CH-01", "forward_fraction": 1.0}):
        bad = operator_api.job(lab["id"], "inject_fault", args)
        assert bad.status_code == 422 and bad.json()["code"] == "VALIDATION_FAILED", args
    job = operator_api.run_job(lab["id"], "inject_fault", {"device": "CH-01", "forward_fraction": 0.3})
    assert job["state"] == "succeeded", job
    suspected = False
    for _ in range(30):
        operator_api.run_job(lab["id"], "send_readings", {})
        operator_api.run_job(lab["id"], "step", {"count": 15})
        cluster = operator_api.get(f"/api/networks/{lab['id']}/recovery").json()["clusters"][0]
        if cluster["suspected"]:
            suspected = True
            break
    assert suspected and sum(cluster["flags"]) >= 2
    # the alert never acts on its own
    assert _devices(operator_api, lab["id"])["CH-01"]["status"] == "active"


def test_rp9_networks_have_no_recovery(operator_api: Api, lab_paper: dict[str, Any]) -> None:
    body = operator_api.get(f"/api/networks/{lab_paper['id']}/recovery").json()
    assert body["available"] is False
    r = operator_api.job(lab_paper["id"], "recover_cluster", {"cluster": "CH-01", "member": "CM-0101"})
    assert r.status_code == 422 and r.json()["code"] == "MODE_NOT_ALLOWED"
