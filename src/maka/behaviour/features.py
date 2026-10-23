"""Per-device, per-window behaviour features (docs/BEHAVIOUR.md §Features).

A pure function of the scheduler's step log (frames sent and delivered) and the security events:
no device state, no keys, no plaintext. Every value is a count of public metadata (§4.4).
Window k covers scheduler steps [start + k*W, start + (k+1)*W). The base station is not scored.

- frames_sent / frames_received: frames the device put on the channel / had delivered to it.
- handshakes_initiated: HS1 messages the device sent as initiator (direct or relayed via its CH).
- handshakes_completed: KEY_CONFIRMED (as initiator) plus HANDSHAKE_OK (as responder) at the device.
- rekeys: KEY_ROTATED events at the device (each rotation also emits one SESSION_SUPERSEDED).
- rejections: events at the device whose type is a rejection reason code (REJECTION_CODES).
- readings_accepted_at_bs: DATA_ACCEPTED at the BS for this CM.
- seq_gaps_at_bs: inner sequence numbers the BS never saw before an accepted reading, per CM
  session; counted for the CM and for the CH that forwarded the reading.
- batch_items_forwarded: items in the device's BATCH_SENT events (CHs).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from maka.codec import DecodeError
from maka.enhanced import messages as em
from maka.runtime import device as dv
from maka.runtime.events import SecurityEvent
from maka.runtime.scheduler import StepResult

FEATURES = ("frames_sent", "frames_received", "handshakes_initiated", "handshakes_completed", "rekeys",
            "rejections", "readings_accepted_at_bs", "seq_gaps_at_bs", "batch_items_forwarded")
ROLES = (dv.CM, dv.CH)

# Verification failures a receiver reports (runtime/events.py). SESSION_SUPERSEDED counts only as
# a rejection (data on a superseded session); its rotation form carries `by` and is a rekey.
REJECTION_CODES = frozenset({
    "DECODE_ERROR", "BAD_POINT", "BAD_TAG", "WRONG_RECIPIENT", "BAD_PURPOSE", "UNAUTHORISED_PEER",
    "RATE_LIMITED", "UNKNOWN_SESSION", "REPLAY_REJECTED", "NOT_DESIGNATED", "MEMBERSHIP_MISMATCH",
    "SEQ_EXHAUSTED", "CLAIM_REJECTED", "UNAUTHENTICATED_PEER", "SESSION_SUPERSEDED_DATA",
})


def _initiator(label: str, payload: bytes) -> str | None:
    """The initiator named in an HS1 (unwrapping a relay), or None for any other frame."""
    try:
        if label == "RELAY:HS1":
            payload = em.decode_relay(payload)[1]
        elif label != "HS1":
            return None
        return em.decode_hs1(payload).id_i
    except DecodeError:
        return None


def extract(log: Sequence[StepResult], events: Iterable[SecurityEvent], roles: Mapping[str, str], *,
            start: int, n_windows: int, window: int = 20) -> list[dict[str, Any]]:
    """One row per (scored device, window): {"device", "role", "window", <FEATURES>}."""
    scored = sorted(d for d, r in roles.items() if r in ROLES)
    rows = {(d, k): dict.fromkeys(FEATURES, 0) for d in scored for k in range(n_windows)}

    def add(device: str | None, step: int, feature: str, n: int = 1) -> None:
        if device is None or step < start:
            return
        k = (step - start) // window
        row = rows.get((device, k))
        if row is not None:
            row[feature] += n

    for result in log:
        for f in result.emitted:
            add(f.src, f.step, "frames_sent")
            if _initiator(f.label, f.payload) == f.src:
                add(f.src, f.step, "handshakes_initiated")
        if result.kind == "deliver" and result.to is not None:
            add(result.to, result.step, "frames_received")

    last_seq: dict[tuple[str, str], int] = {}
    for e in events:
        if e.type in ("KEY_CONFIRMED", "HANDSHAKE_OK"):
            add(e.device, e.step, "handshakes_completed")
        elif e.type == "KEY_ROTATED":
            add(e.device, e.step, "rekeys")
        elif e.type == "BATCH_SENT":
            add(e.device, e.step, "batch_items_forwarded", int(e.details.get("items", 0)))
        elif e.type == "DATA_ACCEPTED" and roles.get(e.device) == dv.BS and e.peer is not None:
            add(e.peer, e.step, "readings_accepted_at_bs")
            key = (e.peer, str(e.sid))
            seq = int(e.details.get("seq", 0))
            gap = max(0, seq - last_seq.get(key, 0) - 1)
            last_seq[key] = max(seq, last_seq.get(key, 0))
            if gap:
                add(e.peer, e.step, "seq_gaps_at_bs", gap)
                add(e.details.get("via"), e.step, "seq_gaps_at_bs", gap)
        if e.type in REJECTION_CODES or (e.type == "SESSION_SUPERSEDED" and "by" not in e.details):
            add(e.device, e.step, "rejections")

    return [{"device": d, "role": roles[d], "window": k, **rows[(d, k)]} for d in scored for k in range(n_windows)]
