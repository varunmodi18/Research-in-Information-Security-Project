"""Server test fixtures: an isolated app per test (temp SQLite DB, MAKA_ENV=test)."""

from __future__ import annotations

import time
import warnings
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

warnings.filterwarnings("ignore", message=".*httpx2.*")
from fastapi.testclient import TestClient

from maka_server.main import create_app
from maka_server.services.users import create_user
from maka_server.settings import Settings

PASSWORDS = {"admin": "admin-password-123", "operator": "operator-pass-123", "viewer": "viewer-password-1"}


@dataclass
class Api:
    client: TestClient
    csrf: str = ""

    def login(self, username: str, password: str | None = None) -> Any:
        r = self.client.post("/api/auth/login", json={"username": username,
                                                      "password": password or PASSWORDS[username]})
        if r.status_code == 200:
            self.csrf = r.json()["csrf_token"]
        return r

    def get(self, path: str, **kw: Any) -> Any:
        return self.client.get(path, **kw)

    def send(self, method: str, path: str, json: Any = None, csrf: str | None = None, **kw: Any) -> Any:
        headers = {"X-CSRF-Token": self.csrf if csrf is None else csrf}
        return self.client.request(method, path, json=json, headers=headers, **kw)

    def post(self, path: str, json: Any = None, **kw: Any) -> Any:
        return self.send("POST", path, json, **kw)

    def job(self, network_id: int, type: str, args: dict[str, Any] | None = None, key: str | None = None) -> Any:
        key = key or f"k{time.monotonic_ns()}"
        return self.post(f"/api/networks/{network_id}/jobs", {"type": type, "args": args or {},
                                                               "idempotency_key": key})

    def wait(self, job_id: int, timeout: float = 120.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            body = self.get(f"/api/jobs/{job_id}").json()
            if body["state"] in ("succeeded", "failed", "cancelled", "aborted"):
                return body  # type: ignore[no-any-return]
            if time.monotonic() > deadline:
                raise TimeoutError(body)
            time.sleep(0.05)

    def run_job(self, network_id: int, type: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        r = self.job(network_id, type, args)
        assert r.status_code == 202, r.text
        return self.wait(r.json()["job_id"])

    def create_network(self, **body: Any) -> dict[str, Any]:
        body.setdefault("name", f"net-{time.monotonic_ns() % 10**9}")
        r = self.post("/api/networks", body)
        assert r.status_code == 201, r.text
        return r.json()  # type: ignore[no-any-return]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(env="test", db_url=f"sqlite:///{tmp_path / 'maka.db'}", static_dir=tmp_path / "no-ui",
                    params_default="toy")


@pytest.fixture
def app(settings: Settings):  # type: ignore[no-untyped-def]
    application = create_app(settings)
    ctx = application.state.ctx
    for role, pw in PASSWORDS.items():
        create_user(ctx, role, pw, role)
    return application


@pytest.fixture
def client(app) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    with TestClient(app) as c:
        yield c


@pytest.fixture
def api(client: TestClient) -> Api:
    return Api(client)


@pytest.fixture
def operator_api(api: Api) -> Api:
    assert api.login("operator").status_code == 200
    return api


@pytest.fixture
def lab_paper(operator_api: Api) -> dict[str, Any]:
    return operator_api.create_network(kind="lab", mode="original", params="toy", template="paper", seed=7)
