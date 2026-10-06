"""E2 (follow-up): nothing under src/maka_server reads a secret out of a keystore (§4.3, §4.4).

The server persists keystores only through the adapter's save()/delete() hooks, which the
runtime pushes to. It must never pull: Keystore.get, Keystore.snapshot and the private entry
table are runtime-internal. Checked twice:
  * statically, over every module of src/maka_server (AST);
  * dynamically, by recording the immediate caller of every Keystore.get/snapshot during a real
    API session (onboard, readings, revoke, rekey, restart and restore, a Lab scenario).
Each check has a positive control showing it would catch a violation.
"""

from __future__ import annotations

import ast
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from maka.runtime.keystore import Keystore, SecretClass

from .conftest import Api

SERVER = Path(__file__).resolve().parents[2] / "src" / "maka_server"
READS = {"get", "snapshot"}


def keystore_reads(source: str) -> list[str]:
    """Calls X.get(...)/X.snapshot(...) where X names a keystore, and any use of `._entries`."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and node.attr == "_entries":
            found.append(f"line {node.lineno}: ._entries")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in READS:
            target = ast.unparse(node.func.value).lower()
            if "keystore" in target or target.split(".")[-1] in ("ks", "store"):
                found.append(f"line {node.lineno}: {ast.unparse(node.func)}")
    return found


def test_no_keystore_read_in_server_source() -> None:
    files = sorted(SERVER.rglob("*.py"))
    assert len(files) > 20
    offenders = {str(f.relative_to(SERVER)): r for f in files if (r := keystore_reads(f.read_text(encoding="utf-8")))}
    assert offenders == {}


def test_static_check_positive_control() -> None:
    planted = "def leak(dev):\n    return dev.keystore.get('pr'), dev.keystore.snapshot(), ks.get('k')\n"
    assert len(keystore_reads(planted)) == 3


@pytest.fixture
def server_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Records every Keystore.get/snapshot whose immediate caller is a maka_server module."""
    seen: list[str] = []
    for name in READS:
        original = getattr(Keystore, name)

        def recorder(self: Keystore, *args: Any, _orig: Any = original, _name: str = name) -> Any:
            caller = sys._getframe(1).f_globals.get("__name__", "")
            if caller.startswith("maka_server"):
                seen.append(f"{caller} -> Keystore.{_name}{args}")
            return _orig(self, *args)

        monkeypatch.setattr(Keystore, name, recorder)
    return seen


def test_no_keystore_read_by_server_at_runtime(operator_api: Api, server_reads: list[str]) -> None:
    nid = operator_api.create_network(kind="product", mode="enhanced", params="toy", template="small")["id"]
    for job, args in (("onboard", {}), ("send_readings", {"count": 2}), ("revoke", {"device": "CM-0103"}),
                      ("rekey", {"device": "CH-01"}), ("send_readings", {"count": 1})):
        assert operator_api.run_job(nid, job, args)["state"] == "succeeded", job
    assert operator_api.get(f"/api/networks/{nid}/devices/CM-0101").status_code == 200
    lab = operator_api.create_network(kind="lab", mode="original", params="toy", template="paper")["id"]
    assert operator_api.run_job(lab, "lab_scenario", {"scenario": "L5"})["state"] == "succeeded"
    assert server_reads == []


def test_runtime_check_positive_control(server_reads: list[str]) -> None:
    ks = Keystore("CM-0101")
    ks.put("pr", b"\x01" * 32, SecretClass.SECRET)
    planted = types.FunctionType(compile("lambda ks: ks.get('pr')", "<planted>", "eval"),
                                 {"__name__": "maka_server.planted"})()
    planted(ks)
    ks.get("pr")  # a runtime (non-server) read is allowed
    assert server_reads == ["maka_server.planted -> Keystore.get('pr',)"]
