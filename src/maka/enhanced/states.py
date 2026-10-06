"""AKE session states and per-device session bookkeeping (IMPLEMENTATION_PLAN.md §4.6.4).

Initiator: IDLE -> SENT_HS1 -> ESTABLISHED, or SENT_HS1 -> FAILED (timeout / bad HS2).
Responder: IDLE -> WAIT_HS3 -> ESTABLISHED, or WAIT_HS3 -> FAILED (timeout / bad HS3).
A newer ESTABLISHED session for the same (peer, purpose) supersedes the older one. Key bytes
never live here: a Session names its keystore entries (sess:<sid>:send / :recv).
"""

from __future__ import annotations

from dataclasses import dataclass

IDLE = "IDLE"
SENT_HS1 = "SENT_HS1"
WAIT_HS3 = "WAIT_HS3"
ESTABLISHED = "ESTABLISHED"
FAILED = "FAILED"
SUPERSEDED = "SUPERSEDED"
CLOSED = "CLOSED"  # destroyed by revocation
ABORTED = "ABORTED"  # destroyed by the recovery rule (§4.8)
PENDING = (SENT_HS1, WAIT_HS3)
INITIATOR, RESPONDER = "I", "R"


@dataclass
class Session:
    sid: bytes
    peer: str
    purpose: str
    role: str  # INITIATOR | RESPONDER
    state: str
    started_step: int
    via: str | None = None  # relay hop (the CH) for CM-BS sessions
    hs1: bytes = b""  # initiator keeps HS1 for the transcript hash
    th: bytes = b""  # responder keeps the transcript hash to check tag_I
    established_step: int | None = None
    epoch: int = 0
    send_seq: int = 0
    recv_last: int = 0
    hop_seq: int = 0  # CM side of a CM-CH session: last DATA_CM hop_seq sent (follow-up D1)
    hop_last: int = 0  # CH side: highest DATA_CM hop_seq accepted
    sent: int = 0
    recv: int = 0
    superseded_by: str | None = None

    @property
    def sid_hex(self) -> str:
        return self.sid.hex()

    def key(self, direction: str) -> str:
        return f"sess:{self.sid_hex}:{direction}"
