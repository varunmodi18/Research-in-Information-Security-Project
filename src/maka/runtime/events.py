"""Security events, verification checks and per-step results (IMPLEMENTATION_PLAN.md §4.10).

Event details must hold PUBLIC values only (§4.4): identifiers, reason codes, counters,
sizes, session ids. Never a key, scalar or plaintext reading.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

INFO = "info"
WARN = "warn"
HIGH = "high"

# Event types (§4.10), with default severities.
SEVERITY: dict[str, str] = {
    # handshakes
    "HANDSHAKE_OK": INFO, "HANDSHAKE_FAIL": WARN, "KEY_CONFIRMED": INFO,
    # validation failures
    "DECODE_ERROR": WARN, "BAD_POINT": WARN, "BAD_TAG": HIGH, "WRONG_RECIPIENT": WARN,
    "BAD_PURPOSE": WARN, "UNAUTHORISED_PEER": HIGH, "RATE_LIMITED": WARN,
    "UNKNOWN_SESSION": WARN, "REPLAY_REJECTED": HIGH, "NOT_DESIGNATED": HIGH,
    "MEMBERSHIP_MISMATCH": HIGH, "TIMEOUT": WARN,
    # membership and lifecycle
    "CLAIM_REJECTED": HIGH, "DEVICE_REVOKED": WARN, "REVOKE_ACKED": INFO,
    "SESSION_SUPERSEDED": INFO, "KEY_ROTATED": INFO, "DEVICE_ACTIVE": INFO, "GRANT_ISSUED": INFO,
    "DESIGNATED": INFO, "SESSION_ABORTED": WARN,
    # data
    "DATA_ACCEPTED": INFO, "UNAUTHENTICATED_PEER": HIGH, "AGGREGATION_UNDEFINED": WARN,
    "BATCH_SENT": INFO, "SESSION_SUPERSEDED_DATA": WARN,
    # original-mode verification
    "ORIG_AUTH_OK": INFO, "ORIG_AUTH_FAIL": HIGH, "ORIG_REGISTERED": INFO, "ORIG_SESSION_KEY": INFO,
    # Lab
    "LAB_ATTACK_RESULT": HIGH,
}


@dataclass(frozen=True)
class SecurityEvent:
    type: str
    device: str
    step: int = -1
    severity: str = INFO
    peer: str | None = None
    sid: str | None = None
    frame_id: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"type": self.type, "device": self.device, "step": self.step,
                "severity": self.severity, "peer": self.peer, "sid": self.sid,
                "frame_id": self.frame_id, "details": dict(self.details)}


def make_event(event_type: str, device: str, peer: str | None = None, sid: str | None = None,
               severity: str | None = None, **details: Any) -> SecurityEvent:
    if event_type not in SEVERITY:
        raise ValueError(f"unknown event type {event_type!r}; extend events.SEVERITY deliberately")
    return SecurityEvent(type=event_type, device=device, peer=peer, sid=sid,
                         severity=severity or SEVERITY[event_type], details=details)


@dataclass(frozen=True)
class Check:
    """One receiver-side verification step, shown in the timeline (FR-15)."""

    name: str
    ok: bool
    reason: str = ""


ACCEPT = "ACCEPT"
REJECT = "REJECT"
DROPPED = "DROPPED"  # never reached a device (adversary drop, or no such device)
TIMER = "TIMER"
COMMAND = "COMMAND"
IDLE = "IDLE"
