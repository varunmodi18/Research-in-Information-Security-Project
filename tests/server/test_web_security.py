"""V-WEB-01..08: authentication, authorisation, CSRF, rate limiting, expiry, isolation, headers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update

from maka_server import models

from .conftest import Api

NID = 1
# (method, path, minimum role) for every §4.5 endpoint; None = any authenticated user.
ENDPOINTS = [
    ("GET", "/api/auth/me", "viewer"),
    ("POST", "/api/auth/logout", "viewer"),
    ("GET", "/api/networks", "viewer"),
    ("POST", "/api/networks", "operator"),
    ("GET", f"/api/networks/{NID}", "viewer"),
    ("DELETE", f"/api/networks/{NID}", "admin"),
    ("POST", f"/api/networks/{NID}/jobs", "operator"),
    ("GET", "/api/jobs/1", "viewer"),
    ("POST", "/api/jobs/1/cancel", "operator"),
    ("GET", f"/api/networks/{NID}/devices/BS-01", "viewer"),
    ("GET", f"/api/networks/{NID}/frames", "viewer"),
    ("GET", f"/api/networks/{NID}/readings", "operator"),
    ("GET", "/api/events", "viewer"),
    ("GET", "/api/events/export", "viewer"),
    ("GET", "/api/lab/scenarios", "operator"),
    ("GET", "/api/evaluation/runs/1", "viewer"),
    ("GET", "/api/admin/users", "admin"),
    ("POST", "/api/admin/users", "admin"),
    ("PATCH", "/api/admin/users/1", "admin"),
    ("POST", "/api/admin/reset-demo", "admin"),
    ("GET", "/api/admin/audit", "admin"),
]
RANK = {"viewer": 0, "operator": 1, "admin": 2}


@pytest.mark.parametrize(("method", "path", "_role"), ENDPOINTS)
def test_v_web_01_unauthenticated_is_401(api: Api, method: str, path: str, _role: str) -> None:
    r = api.client.request(method, path)
    assert r.status_code == 401, (method, path, r.status_code)
    assert r.headers["content-type"].startswith("application/problem+json")
    assert r.json()["code"] == "UNAUTHENTICATED"


@pytest.mark.parametrize("who", ["viewer", "operator", "admin"])
def test_v_web_02_role_matrix(api: Api, who: str) -> None:
    api.login(who)
    for method, path, minimum in ENDPOINTS:
        if path == "/api/auth/logout":
            continue
        r = api.send(method, path, json={})
        allowed = RANK[who] >= RANK[minimum]
        if allowed:
            assert r.status_code != 403, (who, method, path, r.text)
        else:
            assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN", (who, method, path, r.text)


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
