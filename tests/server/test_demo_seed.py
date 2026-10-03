"""M8-T1: seed-demo creates exactly the demo state; reset-demo (API job and CLI) restores it."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from maka_server import __main__ as cli
from maka_server.services import demo
from maka_server.settings import Settings

from .conftest import Api


@pytest.fixture(autouse=True)
def toy_vineyard(monkeypatch: pytest.MonkeyPatch) -> None:
    # the real Vineyard is net/demo; the shape of the state is what is tested, so keep it fast
    monkeypatch.setattr(demo, "DEMO_NETWORKS", tuple(n.model_copy(update={"params": "toy"}) for n in demo.DEMO_NETWORKS))


def _state(api: Api) -> list[tuple[Any, ...]]:
    return sorted((n["name"], n["kind"], n["mode"], n["template"], n["seed"], n["status"])
                  for n in api.get("/api/networks").json())


EXPECTED = [("Lab-Paper", "lab", "original", "paper", 20260927, "idle"),
            ("Vineyard", "product", "enhanced", "net", None, "idle")]


def test_reset_demo_job_restores_exact_state(api: Api) -> None:
    assert api.login("admin").status_code == 200
    extra = api.create_network(kind="lab", mode="enhanced", params="toy", template="paper")
    job = api.wait(api.post("/api/admin/reset-demo", {"confirm": "RESET"}).json()["job_id"])
    assert job["state"] == "succeeded", job
    assert _state(api) == EXPECTED
    vineyard = next(n for n in api.get("/api/networks").json() if n["name"] == "Vineyard")
    onboard = api.run_job(vineyard["id"], "onboard")
    assert onboard["state"] == "succeeded"
    assert extra["name"] not in {n["name"] for n in api.get("/api/networks").json()}
    # a second reset returns to the same idle state and drops the onboarding history
    job = api.wait(api.post("/api/admin/reset-demo", {"confirm": "RESET"}).json()["job_id"])
    assert job["state"] == "succeeded" and _state(api) == EXPECTED
    assert api.get("/api/events?limit=10").json()["items"] == []
    assert api.get("/api/admin/audit").json()["items"]  # the audit trail survives


def test_seed_demo_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = f"sqlite:///{tmp_path / 'demo.db'}"
    monkeypatch.setenv("MAKA_ENV", "test")
    monkeypatch.setenv("MAKA_DB_URL", db)
    pw = tmp_path / "pw.txt"
    pw.write_text("admin=admin-demo-password\noperator:operator-demo-pw\nviewer = viewer-demo-password\n")
    monkeypatch.setenv("MAKA_DEMO_PASSWORDS_FILE", str(pw))
    from maka_server import settings as settings_mod

    if hasattr(settings_mod.get_settings, "cache_clear"):
        settings_mod.get_settings.cache_clear()
    assert cli.main(["seed-demo"]) == 0
    assert cli.main(["seed-demo"]) == 0  # idempotent: users kept, networks reset
    assert cli.main(["reset-demo"]) == 0
    from fastapi.testclient import TestClient

    from maka_server.main import create_app

    with TestClient(create_app(Settings(env="test", db_url=db, static_dir=tmp_path / "x"))) as c:
        api = Api(c)
        r = c.post("/api/auth/login", json={"username": "viewer", "password": "viewer-demo-password"})
        assert r.status_code == 200
        assert _state(api) == EXPECTED
    pw.write_text("admin:admin-demo-password\n")
    monkeypatch.setenv("MAKA_DB_URL", f"sqlite:///{tmp_path / 'other.db'}")
    if hasattr(settings_mod.get_settings, "cache_clear"):
        settings_mod.get_settings.cache_clear()
    assert cli.main(["seed-demo"]) == 2  # missing passwords are refused, never defaulted


def test_broker_forget_keeps_ids_monotonic() -> None:
    from maka_server.sse import Broker

    b = Broker()
    b.publish(1, "frame", {"n": 1})
    b.publish(1, "frame", {"n": 2})
    b.forget(1)  # network 1 deleted; a new network may reuse the id
    assert b.since(1, 0) == []
    assert b.publish(1, "frame", {"n": 3}).id == 3  # a reconnecting client never sees ids go backwards
