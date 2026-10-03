"""Lab scenarios L1-L8 (IMPLEMENTATION_PLAN.md §3.6). Populated in M6."""

from __future__ import annotations

from typing import Any, Protocol


class Scenario(Protocol):
    def describe(self) -> dict[str, Any]: ...


ALL: list[Scenario] = []
