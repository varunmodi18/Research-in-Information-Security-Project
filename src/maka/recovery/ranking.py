"""Replacement-candidate ranking for cluster-head recovery (docs/RECOVERY.md §Ranking).

For each active, non-revoked member of the cluster, over the last N windows (default 10):

- trust = 1 - mean normalised anomaly score, each window's score divided by the detector's
  calibrated threshold for CMs and clipped to [0, 1];
- reliability = readings accepted at the BS / (accepted + sequence gaps); 0 with no readings;
- rejections = rejection events at other devices that name the member as their peer, normalised by
  the largest count among the candidates (0 if none).

score = 0.5·trust + 0.4·reliability - 0.1·normalised rejections; ties broken by identity. Pure
functions: `evidence` from feature rows and events, `rank` from evidence.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from maka.behaviour.features import REJECTION_CODES

W_TRUST, W_RELIABILITY, W_REJECTIONS = 0.5, 0.4, 0.1
HISTORY_WINDOWS = 10


@dataclass(frozen=True)
class Evidence:
    ident: str
    anomaly: tuple[float, ...]  # normalised anomaly score per window, each in [0, 1]
    accepted: int
    gaps: int
    rejections: int


@dataclass(frozen=True)
class Candidate:
    ident: str
    trust: float
    reliability: float
    rejections: int
    rejections_norm: float
    score: float

    def as_dict(self) -> dict[str, Any]:
        return {k: round(v, 4) if isinstance(v, float) else v for k, v in asdict(self).items()}


def _caused_rejection(e: Any) -> bool:
    return e.type in REJECTION_CODES or (e.type == "SESSION_SUPERSEDED" and "by" not in e.details)


def evidence(members: Iterable[str], rows: Sequence[Mapping[str, Any]], scores: Sequence[float],
             threshold: float, events: Iterable[Any], *, start: int, end: int) -> list[Evidence]:
    """`rows` are the members' feature rows for the windows in [start, end) and `scores` their
    anomaly scores (same order); `threshold` the scorer's CM threshold."""
    wanted = list(members)
    caused = {m: 0 for m in wanted}
    for e in events:
        if start <= e.step < end and e.peer in caused and e.device != e.peer and _caused_rejection(e):
            caused[e.peer] += 1
    out = []
    for m in wanted:
        mine = [(r, s) for r, s in zip(rows, scores, strict=True) if r["device"] == m]
        out.append(Evidence(
            ident=m, anomaly=tuple(min(1.0, max(0.0, s / threshold)) for _, s in mine),
            accepted=sum(int(r["readings_accepted_at_bs"]) for r, _ in mine),
            gaps=sum(int(r["seq_gaps_at_bs"]) for r, _ in mine), rejections=caused[m]))
    return out


def rank(candidates: Sequence[Evidence]) -> list[Candidate]:
    worst = max((c.rejections for c in candidates), default=0)
    out = []
    for c in candidates:
        trust = 1.0 - (sum(c.anomaly) / len(c.anomaly) if c.anomaly else 1.0)
        readings = c.accepted + c.gaps
        reliability = c.accepted / readings if readings else 0.0
        rej_norm = c.rejections / worst if worst else 0.0
        score = W_TRUST * trust + W_RELIABILITY * reliability - W_REJECTIONS * rej_norm
        out.append(Candidate(c.ident, trust, reliability, c.rejections, rej_norm, score))
    return sorted(out, key=lambda c: (-c.score, c.ident))
