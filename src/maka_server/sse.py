"""Server-Sent Events broker (IMPLEMENTATION_PLAN.md §4.5, M3-T4).

One broadcast channel per network (and one global channel, key None) with monotonic event
IDs and a replay buffer of the last 1,000 events for Last-Event-ID resumption. Publishers
are worker threads; subscribers are async request handlers that poll the buffer.
Payloads are public metadata only (§4.4).
"""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any

BUFFER = 1000


@dataclass(frozen=True)
class SseEvent:
    id: int
    kind: str  # frame | security_event | device_status | job_progress
    data: dict[str, Any]

    def encode(self) -> str:
        return f"id: {self.id}\nevent: {self.kind}\ndata: {json.dumps(self.data, default=str)}\n\n"


class Broker:
    def __init__(self, buffer: int = BUFFER) -> None:
        self._lock = threading.Lock()
        self._next_id: dict[int | None, int] = {}
        self._buffers: dict[int | None, deque[SseEvent]] = {}
        self._size = buffer

    def publish(self, network_id: int | None, kind: str, data: dict[str, Any]) -> SseEvent:
        with self._lock:
            nid = self._next_id.get(network_id, 0) + 1
            self._next_id[network_id] = nid
            event = SseEvent(nid, kind, data)
            self._buffers.setdefault(network_id, deque(maxlen=self._size)).append(event)
            return event

    def since(self, network_id: int | None, last_id: int) -> list[SseEvent]:
        """Buffered events with id > last_id, oldest first (no duplicates on reconnect)."""
        with self._lock:
            return [e for e in self._buffers.get(network_id, ()) if e.id > last_id]

    def last_id(self, network_id: int | None) -> int:
        with self._lock:
            return self._next_id.get(network_id, 0)
