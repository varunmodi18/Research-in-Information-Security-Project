"""Observability core: the transcript every demonstration writes to.

Realises: PLAN.md §6.1, P1.1. Every human-readable artefact this project produces flows
through this module. A hygiene test forbids `print(` anywhere else under `src/`.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_REGISTER_COLORS = {
    "ER": "\033[91m",  # red   — genuine errata
    "AM": "\033[93m",  # amber — ambiguity/underspecification
    "IA": "\033[94m",  # blue  — our implementation choice
    "OB": "\033[96m",  # cyan  — observation
    "SD": "\033[95m",  # magenta — secondary-source
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


@dataclass
class Tracer:
    """Dual-sink tracer: stdout plus a human log and a JSONL event stream."""

    run_id: str
    out_dir: Path
    color: bool = True
    verbosity: int = 2
    disclose_secrets: bool = False  # CLI --disclose-secrets only (IMPLEMENTATION_PLAN.md §4.4 rule 1)

    _log_fh: Any = field(default=None, init=False)
    _jsonl_fh: Any = field(default=None, init=False)
    _section: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        # Held open for the Tracer's lifetime (closed explicitly by close()), not scoped to a
        # single call -- a `with` block doesn't fit this usage.
        self._log_fh = open(self.out_dir / f"{self.run_id}.log", "a", encoding="utf-8")  # noqa: SIM115
        self._jsonl_fh = open(self.out_dir / f"{self.run_id}.jsonl", "a", encoding="utf-8")  # noqa: SIM115

    def _emit(self, text: str, event: dict[str, Any]) -> None:
        print(text)
        self._log_fh.write(text + "\n")
        self._log_fh.flush()
        event = {"ts": time.time(), **event}
        self._jsonl_fh.write(json.dumps(event, default=str) + "\n")
        self._jsonl_fh.flush()

    def _color(self, code: str, text: str) -> str:
        if not self.color:
            return text
        return f"{code}{text}{_RESET}"

    # -- structural -----------------------------------------------------

    def banner(self, title: str, subtitle: str | None = None) -> None:
        bar = "=" * max(len(title), len(subtitle or ""), 20)
        lines = [bar, self._color(_BOLD, title)]
        if subtitle:
            lines.append(subtitle)
        lines.append(bar)
        self._emit("\n".join(lines), {"type": "banner", "title": title, "subtitle": subtitle})

    def section(self, n: str | int, title: str) -> None:
        self._section = n if isinstance(n, int) else self._section + 1
        text = f"\n--- §{n} {title} " + "-" * max(0, 60 - len(str(title)))
        self._emit(text, {"type": "section", "n": n, "title": title})

    def step(self, actor: str, text: str) -> None:
        self._emit(f"[{actor}] {text}", {"type": "step", "actor": actor, "text": text})

    # -- values -----------------------------------------------------------

    def value(self, name: str, obj: Any, note: str | None = None) -> None:
        rendered = render(obj, verbosity=self.verbosity)
        suffix = f"   {self._color(_BOLD, note)}" if note else ""
        self._emit(f"  {name:<14} = {rendered}{suffix}",
                    {"type": "value", "name": name, "value": repr(obj), "note": note})

    def redacted(self, name: str, value: Any) -> str:
        """The rendering of a SECRET-class value (§4.4): `«secret:name»`, plus an 8-hex SHA-256
        fingerprint when MAKA_ENV=test (seeded test mode only). The value itself appears only
        when the tracer was built with disclose_secrets."""
        if self.disclose_secrets:
            return f"{render(value, verbosity=self.verbosity)} [DISCLOSED: --disclose-secrets]"
        tag = f"«secret:{name}»"
        if os.environ.get("MAKA_ENV") == "test":
            tag += f" fp={hashlib.sha256(repr(value).encode()).hexdigest()[:8]}"
        return tag

    def secret(self, name: str, value: Any, note: str | None = None) -> None:
        """Records that a SECRET-class value exists without recording the value (I-09)."""
        rendered = self.redacted(name, value)
        suffix = f"   {self._color(_BOLD, note)}" if note else ""
        self._emit(f"  {name:<14} = {rendered}{suffix}",
                    {"type": "secret", "name": name, "value": rendered, "note": note})

    def event(self, kind: str, actor: str, **details: Any) -> None:
        """A security event (IMPLEMENTATION_PLAN.md §4.10), e.g. ORIG_AUTH_FAIL."""
        extra = " ".join(f"{k}={v}" for k, v in details.items())
        self._emit(f"  [EVENT] {kind} at {actor} {extra}".rstrip(),
                    {"type": "event", "event": kind, "actor": actor, **details})

    def formula(self, lhs: str, rhs_symbolic: str, rhs_value: Any) -> None:
        rendered = render(rhs_value, verbosity=self.verbosity)
        self._emit(f"  {lhs} = {rhs_symbolic} = {rendered}",
                    {"type": "formula", "lhs": lhs, "symbolic": rhs_symbolic, "value": repr(rhs_value)})

    def frame(self, src: str, dst: str, label: str, nbits: int, body: dict[str, Any]) -> None:
        header = f"+-- {label} " + "-" * 10 + f" {nbits} bits --+"
        lines = [header, f"| {src} --> {dst}"]
        for k, v in body.items():
            lines.append(f"|   {k} = {render(v, verbosity=self.verbosity)}")
        lines.append("+" + "-" * (len(header) - 2) + "+")
        self._emit("\n".join(lines),
                    {"type": "frame", "src": src, "dst": dst, "label": label, "nbits": nbits,
                     "body": {k: repr(v) for k, v in body.items()}})

    def check(self, desc: str, ok: bool, expected: Any, actual: Any) -> bool:
        verdict = self._color("\033[92m", "PASS") if ok else self._color("\033[91m", "FAIL")
        text = (f"  [CHECK] {desc}: {verdict}\n"
                f"          expected = {render(expected, self.verbosity)}\n"
                f"          actual   = {render(actual, self.verbosity)}")
        self._emit(text, {"type": "check", "desc": desc, "ok": ok,
                           "expected": repr(expected), "actual": repr(actual)})
        return ok

    def table(self, headers: list[str], rows: list[list[Any]], caption: str) -> None:
        widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h))
                  for i, h in enumerate(headers)]
        def fmt_row(r: list[Any]) -> str:
            return " | ".join(str(c).ljust(w) for c, w in zip(r, widths))
        lines = [f"Table: {caption}", fmt_row(headers), "-+-".join("-" * w for w in widths)]
        lines.extend(fmt_row(r) for r in rows)
        self._emit("\n".join(lines),
                    {"type": "table", "headers": headers, "rows": [[repr(c) for c in r] for r in rows],
                     "caption": caption})

    # -- register-tagged narration -----------------------------------------

    def register(self, entry_id: str, text: str) -> None:
        entry_class = entry_id.split("-")[0]
        color = _REGISTER_COLORS.get(entry_class, "")
        tag = self._color(color + _BOLD, f"[{entry_id}]")
        self._emit(f"  {tag} {text}", {"type": "register", "id": entry_id, "text": text})

    def undefined(self, op: str, reason: str) -> None:
        box = (f"+{'-' * 78}+\n"
               f"| UNDEFINED IN SOURCE: {op}\n"
               f"| {reason}\n"
               f"+{'-' * 78}+")
        self._emit(box, {"type": "undefined", "op": op, "reason": reason})

    def underspecified(self, what: str, reason: str) -> None:
        box = (f"+{'-' * 78}+\n"
               f"| UNDER-SPECIFIED: {what}\n"
               f"| {reason}\n"
               f"+{'-' * 78}+")
        self._emit(box, {"type": "underspecified", "what": what, "reason": reason})

    def conditional(self, premise: str, source: str, caveat: str) -> None:
        box = (f"+{'-' * 78}+\n"
               f"| CONDITIONAL SCENARIO\n"
               f"| premise: {premise}\n"
               f"| source:  {source}\n"
               f"| caveat:  {caveat}\n"
               f"+{'-' * 78}+")
        self._emit(box, {"type": "conditional", "premise": premise, "source": source, "caveat": caveat})

    def timing(self, label: str, seconds: float) -> None:
        self._emit(f"  [TIMING] {label}: {seconds * 1000:.3f} ms",
                    {"type": "timing", "label": label, "seconds": seconds})

    def close(self) -> None:
        self._log_fh.close()
        self._jsonl_fh.close()


# -- type-aware rendering --------------------------------------------------

def render(obj: Any, verbosity: int = 2) -> str:
    renderer = _RENDERERS.get(type(obj).__name__)
    if renderer is not None:
        return renderer(obj, verbosity)
    if isinstance(obj, bytes):
        return _render_bytes(obj, verbosity)
    if isinstance(obj, bool):
        return str(obj)
    if isinstance(obj, int):
        return f"{obj} (0x{obj:x})" if verbosity >= 2 else str(obj)
    return str(obj)


def _render_bytes(b: bytes, verbosity: int) -> str:
    hexs = b.hex()
    if verbosity >= 3 or len(hexs) <= 16:
        shown = hexs
    else:
        shown = f"{hexs[:8]}...{hexs[-8:]}"
    return f"0x{shown} ({len(b) * 8} bits)"


_RENDERERS: dict[str, Any] = {}


def register_renderer(type_name: str, fn: Any) -> None:
    """Lets field.py/curve.py/pairing.py register Fp/Fp2/Point formatters without a circular import."""
    _RENDERERS[type_name] = fn


class NullTracer(Tracer):
    """Discards everything. Used by the device runtime, whose observability is its event
    stream (maka.runtime.events), so primitives can call trace.active() without a transcript."""

    def __init__(self) -> None:
        super().__init__(run_id="null", out_dir=Path("."), color=False, verbosity=0)

    def __post_init__(self) -> None:  # no files
        pass

    def _emit(self, text: str, event: dict[str, Any]) -> None:
        pass

    def close(self) -> None:
        pass


# -- context-local active tracer, used by callers that don't thread a Tracer explicitly --

_active_var: ContextVar[Tracer | None] = ContextVar("maka_tracer", default=None)


def init(run_id: str, out_dir: str | Path = "artifacts/transcripts", color: bool = True,
         verbosity: int = 2, disclose_secrets: bool = False) -> Tracer:
    if disclose_secrets and os.environ.get("MAKA_ENV") in ("demo", "prod"):
        raise PermissionError("--disclose-secrets is refused when MAKA_ENV is demo or prod")
    tracer = Tracer(run_id=run_id, out_dir=Path(out_dir), color=color and sys.stdout.isatty(),
                    verbosity=verbosity, disclose_secrets=disclose_secrets)
    _active_var.set(tracer)
    return tracer


@contextmanager
def using(tracer: Tracer) -> Iterator[Tracer]:
    token = _active_var.set(tracer)
    try:
        yield tracer
    finally:
        _active_var.reset(token)


def use(tracer: Tracer) -> Tracer:
    _active_var.set(tracer)
    return tracer


_fallback: Tracer | None = None


def set_fallback(tracer: Tracer | None) -> None:
    """Process-wide tracer for contexts that never chose one (the server sets NullTracer)."""
    global _fallback
    _fallback = tracer


def active() -> Tracer:
    tracer = _active_var.get()
    if tracer is None:
        tracer = _fallback if _fallback is not None else init(run_id=f"adhoc-{int(time.time())}")
    return tracer
