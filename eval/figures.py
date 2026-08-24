"""RP9 Figs. 10-11 reproduced from RP9's published values only (P12.7). No measured
counterparts (see docs/DEFERRED.md)."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from eval.comparison import TABLE5
from maka import trace

FIGURES_DIR = Path("artifacts/figures")


def fig10_computation_comparison() -> Path:
    """Fig. 10: computation-cost comparison bar chart, from Table 5's published values."""
    t = trace.active()
    names = [row[0] for row in TABLE5]
    values = [row[2] if row[2] is not None else 50.039 for row in TABLE5]

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(range(len(names)), values)
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, rotation=35, ha="right", fontsize=7)
    ax.set_ylabel("computation cost (ms)")
    ax.set_title("Fig. 10 (reproduction) -- computation cost comparison, RP9 §8 values")
    fig.tight_layout()
    out = FIGURES_DIR / "fig10_computation_comparison.png"
    fig.savefig(out, dpi=200)
    plt.close(fig)
    (FIGURES_DIR / "fig10_computation_comparison.caption.txt").write_text(
        "Source: RP9 Table 5 published values (§8). Assumption: MAKA's bar uses this "
        "repository's recomputed 50.039 ms (matches RP9's stated total); other rows use "
        "RP9's published figures verbatim, including the ER-02/AM-04 flagged ones.",
        encoding="utf-8")
    t.value("fig10 written", str(out))
    return out


def fig11_communication_comparison() -> Path:
    """Fig. 11: communication-cost comparison, from RP9's published Table 3 total (registration
    + authentication + key generation), since RP9 does not itemise a separate Fig. 11 dataset
    beyond what Tables 3/5 already give."""
    t = trace.active()
    labels = ["key generation", "registration", "authentication", "session key agreement"]
    values = [640, 1760, 2400, 0]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(labels, values)
    ax.set_ylabel("bits")
    ax.set_title("Fig. 11 (reproduction) -- MAKA communication cost by phase, RP9 Table 3")
    fig.tight_layout()
    out = FIGURES_DIR / "fig11_communication_comparison.png"
    fig.savefig(out, dpi=200)
    plt.close(fig)
    (FIGURES_DIR / "fig11_communication_comparison.caption.txt").write_text(
        "Source: RP9 Table 3 published bit counts (§7.2), reproduced on F-PAPER. No assumption "
        "beyond RP9's own paper-model sizing (id=160b, point=320b).", encoding="utf-8")
    t.value("fig11 written", str(out))
    return out


def run() -> None:
    fig10_computation_comparison()
    fig11_communication_comparison()
