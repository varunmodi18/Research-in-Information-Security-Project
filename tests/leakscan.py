"""Secret scanner for the V-LEAK tests (IMPLEMENTATION_PLAN.md §6.3).

Given the SECRET-class values a run produced, searches text and bytes for their decimal, hex,
base64 and raw-byte representations. Short values are skipped where a coincidental match in
unrelated output would be likely (the tests use `demo` parameters, so real secrets are long).
"""

from __future__ import annotations

import base64
from collections.abc import Iterable

from maka.curve import Point
from maka.field import Fp2


def _int_forms(v: int) -> tuple[list[str], list[bytes]]:
    texts, raws = [], []
    if v.bit_length() >= 24:
        texts.append(str(v))
        texts.append(f"{v:x}")
        raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
        raws.append(raw)
        texts.append(base64.b64encode(raw).decode())
    return texts, raws


def forms(value: object) -> tuple[list[str], list[bytes]]:
    """(text representations, byte representations) of one secret value."""
    if isinstance(value, bool):
        return [], []
    if isinstance(value, int):
        return _int_forms(value)
    if isinstance(value, Point):
        if value.is_infinity():
            return [], []
        tx, rx = _int_forms(value.x.val)  # type: ignore[union-attr]
        ty, ry = _int_forms(value.y.val)  # type: ignore[union-attr]
        return tx + ty, rx + ry
    if isinstance(value, Fp2):
        ta, ra = _int_forms(value.a.val)
        tb, rb = _int_forms(value.b.val)
        return ta + tb, ra + rb
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
        if len(b) < 8:
            return [], []
        return ([b.hex(), base64.b64encode(b).decode(), base64.urlsafe_b64encode(b).decode().rstrip("=")],
                [b])
    raise TypeError(f"no representation rule for {type(value).__name__}")


def scan_text(secrets: dict[str, object], texts: Iterable[str]) -> list[str]:
    hits = []
    corpus = list(texts)
    for name, value in secrets.items():
        reps, _ = forms(value)
        for rep in reps:
            if any(rep in t or rep.upper() in t for t in corpus):
                hits.append(f"{name}: {rep[:24]}...")
    return hits


def scan_bytes(secrets: dict[str, object], blobs: Iterable[bytes]) -> list[str]:
    hits = []
    corpus = list(blobs)
    for name, value in secrets.items():
        reps, raws = forms(value)
        needles = raws + [r.encode() for r in reps]
        for needle in needles:
            if any(needle in b for b in corpus):
                hits.append(f"{name}: {needle[:12]!r}...")
    return hits
