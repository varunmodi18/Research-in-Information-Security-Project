"""Cluster status and the "CH suspected" alert (docs/RECOVERY.md). Alert only: nothing here acts.

`assess` reports, for every live cluster head, its last m behaviour-monitor flags, whether it is
suspected (flagged in k of the last m windows) and the ranked replacement candidates. Replacing a
cluster head is always an operator decision, confirmed in the console (`EnhancedNetwork.promote`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from maka.enhanced import network as en
from maka.enhanced.membership import REVOKED
from maka.recovery import monitor, ranking
from maka.runtime import device as dv


@dataclass(frozen=True)
class RecoveryConfig:
    window: int = 20
    history: int = ranking.HISTORY_WINDOWS  # windows of evidence for the ranking
    flag_windows: int = 2  # k: suspected when flagged in k ...
    of_last: int = 3  # ... of the last m windows


@dataclass
class ClusterStatus:
    cluster: str
    ch: str
    flags: list[bool]
    suspected: bool
    candidates: list[ranking.Candidate]
    trigger_detector: str = monitor.Z_BASELINE
    trust_detector: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"cluster": self.cluster, "ch": self.ch, "flags": self.flags, "suspected": self.suspected,
                "candidates": [c.as_dict() for c in self.candidates],
                "recommended": self.candidates[0].ident if self.candidates else None,
                "trigger_detector": self.trigger_detector, "trust_detector": self.trust_detector}


def candidates_of(net: en.EnhancedNetwork, cluster: str) -> list[str]:
    """Active, non-revoked members of the cluster (the BS registry and the device status)."""
    bs = net.bs()
    return sorted(cm.identity for cm in net.cms() if cm.status == dv.ACTIVE
                  and bs.registry[cm.identity].cluster == cluster and bs.registry[cm.identity].status != REVOKED)


def assess(net: en.EnhancedNetwork, start: int = 0, config: RecoveryConfig | None = None) -> list[ClusterStatus]:
    """Windows of `config.window` steps from `start`; only complete windows are scored."""
    cfg = config or RecoveryConfig()
    sched = net.scheduler
    complete = (sched.step_no - start) // cfg.window
    first = max(0, complete - max(cfg.of_last, cfg.history))
    lo, hi = start + first * cfg.window, start + complete * cfg.window
    roles = {ident: d.role for ident, d in sched.devices.items()}
    rows = monitor.windows(sched.log, sched.events, roles, start=lo, end=hi, window=cfg.window)
    z = monitor.baseline()
    scorer = monitor.trust_scorer()
    hist_lo = start + max(0, complete - cfg.history) * cfg.window
    bs = net.bs()
    out = []
    for cluster, ch in sorted(bs.cluster_ch.items()):
        if ch is None or bs.registry[ch].status == REVOKED:
            continue
        flags = [z.flag(r) for r in rows if r["device"] == ch][-cfg.of_last:]
        members = candidates_of(net, cluster)
        member_rows = [r for r in rows if r["device"] in members and lo + r["window"] * cfg.window >= hist_lo]
        scores = scorer.score(member_rows) if member_rows else []
        ev = ranking.evidence(members, member_rows, scores, scorer.threshold[dv.CM], sched.events,
                              start=hist_lo, end=hi)
        out.append(ClusterStatus(cluster, ch, flags, monitor.suspected(flags, cfg.flag_windows, cfg.of_last),
                                 ranking.rank(ev), trust_detector=scorer.name))
    return out
