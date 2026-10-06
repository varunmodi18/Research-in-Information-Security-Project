"""V-WEB-01..08: authentication, authorisation, CSRF, rate limiting, expiry, isolation, headers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update

from maka_server import models

from .conftest import Api

NID = 1
# (method, path, minimum role, exact status for an allowed role) for every §4.5 endpoint, against a
# database holding network 1 (lab, original, paper) and no job or evaluation run. Bodies are `{}`, so
# endpoints that need a body answer 422; a role below the minimum always gets 403 FORBIDDEN, checked
# before the resource is looked up. /api/auth/login is public and has its own tests.
ENDPOINTS = [
    ("GET", "/api/auth/me", "viewer", 200),
    ("POST", "/api/auth/logout", "viewer", 204),
    ("GET", "/api/networks", "viewer", 200),
    ("POST", "/api/networks", "operator", 422),
    ("GET", f"/api/networks/{NID}", "viewer", 200),
    ("DELETE", f"/api/networks/{NID}", "admin", 422),
    ("POST", f"/api/networks/{NID}/jobs", "operator", 422),
    ("GET", "/api/jobs/1", "viewer", 404),
    ("POST", "/api/jobs/1/cancel", "operator", 404),
    ("GET", f"/api/networks/{NID}/devices/BS-01", "viewer", 200),
    ("GET", f"/api/networks/{NID}/frames", "viewer", 200),
    ("GET", f"/api/networks/{NID}/readings", "operator", 200),
    ("GET", f"/api/networks/{NID}/stream?once=true", "viewer", 200),
    ("GET", "/api/events", "viewer", 200),
    ("GET", "/api/events/export", "viewer", 200),
    ("GET", "/api/lab/scenarios", "operator", 200),
    ("GET", "/api/evaluation/reference", "viewer", 200),
    ("GET", "/api/evaluation/runs", "viewer", 200),
    ("GET", "/api/evaluation/runs/1", "viewer", 404),
    ("GET", "/api/admin/users", "admin", 200),
    ("POST", "/api/admin/users", "admin", 422),
    ("PATCH", "/api/admin/users/1", "admin", 200),
    ("POST", "/api/admin/reset-demo", "admin", 422),
    ("GET", "/api/admin/audit", "admin", 200),
]
RANK = {"viewer": 0, "operator": 1, "admin": 2}


@pytest.mark.parametrize(("method", "path", "_role", "_status"), ENDPOINTS)
def test_v_web_01_unauthenticated_is_401(api: Api, method: str, path: str, _role: str, _status: int) -> None:
    r = api.client.request(method, path)
    assert r.status_code == 401, (method, path, r.status_code)
    assert r.headers["content-type"].startswith("application/problem+json")
    assert r.json()["code"] == "UNAUTHENTICATED"


@pytest.mark.parametrize("who", ["viewer", "operator", "admin"])
def test_v_web_02_role_matrix(api: Api, who: str) -> None:
    api.login("operator")
    assert api.create_network(kind="lab", mode="original", params="toy", template="paper")["id"] == NID
    api.send("POST", "/api/auth/logout")
    api.login(who)
    for method, path, minimum, status in ENDPOINTS:
        if path == "/api/auth/logout":
            continue  # would end the session the matrix runs in; covered by test_logout_ends_the_session
        r = api.send(method, path, json={})
        if RANK[who] >= RANK[minimum]:
            assert r.status_code == status, (who, method, path, r.status_code, r.text[:200])
        else:
            assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN", (who, method, path, r.text[:200])


def test_v_web_03_csrf(api: Api) -> None:
    api.login("operator")
    body = {"name": "csrf-net", "kind": "lab", "mode": "original", "params": "toy"}
    assert api.post("/api/networks", body, csrf="").status_code == 403
    r = api.post("/api/networks", body, csrf="wrong-token")
    assert r.status_code == 403 and r.json()["code"] == "CSRF_FAILED"
    assert api.post("/api/networks", body).status_code == 201


def test_v_web_04_login_rate_limit(api: Api) -> None:
    for _ in range(5):
        assert api.login("viewer", "wrong-password!").status_code == 401
    r = api.login("viewer")  # correct password, but locked now
    assert r.status_code == 429 and r.json()["code"] == "LOGIN_LOCKED"
    assert api.login("operator").status_code == 200  # other users unaffected


def test_v_web_05_session_expiry(api: Api, app) -> None:  # type: ignore[no-untyped-def]
    api.login("viewer")
    assert api.get("/api/auth/me").status_code == 200
    with app.state.ctx.db.session() as db:
        db.execute(update(models.AuthSession).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    assert api.get("/api/auth/me").status_code == 401


def test_logout_ends_the_session(api: Api) -> None:
    api.login("viewer")
    assert api.post("/api/auth/logout").status_code == 204
    assert api.get("/api/auth/me").status_code == 401


def test_v_web_06_product_networks_refuse_original_mode(operator_api: Api) -> None:
    r = operator_api.post("/api/networks", {"name": "p1", "kind": "product", "mode": "original", "params": "toy"})
    assert r.status_code == 422 and r.json()["code"] == "MODE_NOT_ALLOWED"


def test_v_web_07_security_headers(api: Api) -> None:
    for path in ("/api/health", "/api/networks", "/"):
        h = api.get(path).headers
        assert h["content-security-policy"] == "default-src 'self'; frame-ancestors 'none'"
        assert h["x-content-type-options"] == "nosniff" and h["referrer-policy"] == "no-referrer"


def test_v_web_08_viewer_cannot_read_readings(api: Api, lab_paper) -> None:  # type: ignore[no-untyped-def]
    api.login("viewer")
    r = api.get(f"/api/networks/{lab_paper['id']}/readings")
    assert r.status_code == 403


def test_login_cookie_flags(api: Api) -> None:
    r = api.login("viewer")
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_audit_log_records_state_changes(api: Api, app) -> None:  # type: ignore[no-untyped-def]
    api.login("operator")
    api.post("/api/networks", {"name": "audited", "kind": "lab", "mode": "original", "params": "toy"})
    api.login("admin")
    rows = api.get("/api/admin/audit").json()["items"]
    actions = {(r["username"], r["action"]) for r in rows}
    assert ("operator", "POST /api/networks") in actions and ("operator", "login") in actions
