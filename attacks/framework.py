"""Shared scaffolding for the RP9 §4 attack demonstrations."""

from __future__ import annotations

from maka import trace


def verdict(module: str, rp9_section: str, text: str) -> None:
    t = trace.active()
    t.banner(f"{module} -- {rp9_section}", text)
