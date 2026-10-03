"""V-DOC-01: documentation does not overstate the code (IMPLEMENTATION_PLAN.md M1-T10, I-15)."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = sorted((REPO_ROOT / "docs").glob("*.md")) + [REPO_ROOT / "README.md"]
SOURCES = sorted((REPO_ROOT / "src").rglob("*.py"))


def _windows(path: Path) -> list[tuple[int, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [(i + 1, " ".join(lines[i:i + 2])) for i in range(len(lines))]


def test_ia04_encryption_claims_name_the_flag() -> None:
    """Pseudo-identities are encrypted only with secure_pseudo_ids on; a doc saying IA-04
    encrypts them must say so."""
    offenders = []
    for doc in DOCS:
        for n, text in _windows(doc):
            if "IA-04" in text and re.search(r"encrypt|IBE", text) and not re.search(
                    r"secure[_-]pseudo[_-]ids", text):
                offenders.append(f"{doc.name}:{n}")
    assert not offenders, offenders


def test_no_claim_that_k_is_overwritten() -> None:
    """k is deleted (`del`), not overwritten; Python ints cannot be wiped."""
    claim = re.compile(r"(\bk\b[^.\n]*\boverwrit|\boverwrit[^.\n]*\bk\b)", re.IGNORECASE)
    negated = re.compile(r"(cannot|can't|not) be overwritten", re.IGNORECASE)
    offenders = []
    for path in DOCS + SOURCES:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if claim.search(line) and not negated.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{n}")
    assert not offenders, offenders


def test_er03_is_not_misquoted() -> None:
    """RP9 prints e(P,P) != 1 (ER-03); no doc may say RP9 prints e(P,P) = 1."""
    bad = re.compile(r"RP9[^.\n]*prints\s+e\(P,\s*P\)\s*=\s*1")
    offenders = [f"{p.name}:{n}" for p in DOCS + SOURCES
                 for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if bad.search(line)]
    assert not offenders, offenders


def test_hlpsl_header_does_not_claim_faithful_transcription() -> None:
    header = (REPO_ROOT / "formal" / "avispa" / "maka.hlpsl").read_text(encoding="utf-8")[:800]
    assert "preserved" not in header and "NOT a faithful transcription" in header


def test_api_doc_is_generated_from_current_code() -> None:
    """docs/API.md's endpoint and job tables match the app (M8-T3); regenerate with `make openapi`."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen_api_doc", REPO_ROOT / "tools" / "gen_api_doc.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert (REPO_ROOT / "docs" / "API.md").read_text(encoding="utf-8") == mod.render()


def test_no_doc_or_ui_text_claims_proven_or_deployment_grade_security() -> None:
    """§7.3 item 5: no document or UI string claims proven or deployment-grade security."""
    claim = re.compile(r"\b(provably secure|proven secure|formally proven|deployment[- ]grade security|"
                       r"production[- ]ready security|guarantees? security)\b", re.IGNORECASE)
    negation = re.compile(r"\b(no|not|never|nothing|without|nor|isn't|aren't|cannot)\b", re.IGNORECASE)
    ui = sorted((REPO_ROOT / "web" / "src").rglob("*.tsx"))
    offenders = []
    for path in [*DOCS, *ui]:
        for n, text in _windows(path):
            m = claim.search(text)
            if m and not negation.search(text):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{n}: {m.group(0)}")
    assert not offenders, offenders
