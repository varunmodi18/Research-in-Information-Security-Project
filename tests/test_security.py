"""Seven §6.1 analyses hold; correspondence table structure; no comparative operation
counting anywhere (hygiene)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from security.maka import (
    s1_replay,
    s2_dos,
    s3_ch_impersonation,
    s4_mutual_authentication,
    s5_sybil,
    s6_session_key_secrecy,
    s7_eavesdropping,
)

from maka import rng, trace

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES = [s1_replay, s2_dos, s3_ch_impersonation, s4_mutual_authentication,
           s5_sybil, s6_session_key_secrecy, s7_eavesdropping]


@pytest.mark.parametrize("mod", MODULES)
def test_security_analysis_holds(mod) -> None:
    rng.seed(21)
    trace.init(run_id=f"test-{mod.__name__}", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    assert mod.run("toy") is True


def test_illustrations_are_labelled() -> None:
    """M1-T9: s2 and s5 cannot fail, so they are labelled illustrations, not tests."""
    assert s2_dos.KIND == "ILLUSTRATION" and s5_sybil.KIND == "ILLUSTRATION"
    assert all(getattr(m, "KIND", "TEST") == "TEST" for m in MODULES if m not in (s2_dos, s5_sybil))


def test_v_eval_04_s7_fails_if_encryption_is_ineffective(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mutation: make every AEAD 'decryption' ignore the key; s7's wrong-key attempt then
    succeeds and the analysis must report FAILS."""
    from maka import aead

    real = aead.decrypt
    monkeypatch.setattr(aead, "decrypt", lambda key, blob, *, ad: real(_KEYS[-1], blob, ad=ad)
                        if _KEYS else real(key, blob, ad=ad))
    original_encrypt = aead.encrypt

    def recording_encrypt(key, plaintext, *, ad, nonce=None):  # type: ignore[no-untyped-def]
        _KEYS.append(key)
        return original_encrypt(key, plaintext, ad=ad, nonce=nonce)

    _KEYS.clear()
    monkeypatch.setattr(aead, "encrypt", recording_encrypt)
    rng.seed(21)
    trace.init(run_id="test-s7-mutation", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    assert s7_eavesdropping.run("toy") is False


_KEYS: list[bytes] = []


def test_no_comparative_operation_counting_in_security_modules() -> None:
    """PLAN.md P11.1 s2: 'Do not count operations avoided versus the ICMDS run'."""
    forbidden = {"operations_avoided", "operations_saved", "vs_icmds"}
    offenders = []
    for f in (REPO_ROOT / "security").rglob("*.py"):
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.lower() in forbidden:
                offenders.append(f"{f}:{node.lineno}")
    assert not offenders
