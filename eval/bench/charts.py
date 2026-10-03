"""Charts for the comparison report (M7-T5). Categorical slots 1-3 of the reference palette,
validated (light surface): CVD dE 9.2, normal-vision dE 27.6; slot 3 is below 3:1 contrast, so
every bar carries a visible value label and the Markdown report holds the same numbers as a table.
Magnitudes on different scales are drawn as small multiples, never on a second axis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e4e3df"
SERIES = {"original+secure": "#2a78d6", "original+clear": "#eb6834", "enhanced": "#1baf7a"}
LABEL = {"original+secure": "RP9 (pseudo-IDs encrypted)", "original+clear": "RP9 (as priced in Table 2)",
         "enhanced": "MAKA-E"}


def _style(ax: Any) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK_2, length=0, labelsize=8)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _bars(ax: Any, groups: list[str], values: dict[str, list[float]], fmt: str) -> None:
    n = len(values)
    width = 0.8 / n
    for i, (variant, vals) in enumerate(values.items()):
        xs = [g + (i - (n - 1) / 2) * width for g in range(len(groups))]
        bars = ax.bar(xs, vals, width, color=SERIES[variant], edgecolor=SURFACE, linewidth=2,
                      label=LABEL[variant])
        for bar, v in zip(bars, vals):
            ax.annotate(fmt.format(v), (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                        xytext=(0, 2), textcoords="offset points", ha="center", va="bottom", fontsize=7, color=INK_2)
    ax.set_xticks(range(len(groups)), groups)


def render(doc: dict[str, Any], out_dir: Path, stem: str) -> list[Path]:
    results = doc["results"]
    paths = []
    params_list = [p for p in ("toy", "demo", "secure") if any(r["params"] == p for r in results)]

    fig, axes = plt.subplots(1, len(params_list), figsize=(4.2 * len(params_list), 3.4), squeeze=False)
    fig.patch.set_facecolor(SURFACE)
    for ax, params in zip(axes[0], params_list):
        _style(ax)
        rows = [r for r in results if r["params"] == params]
        topos = [t for t in ("paper", "small", "net") if any(r["topology"] == t for r in rows)]
        values = {v: [next((r["onboard_s"]["median"] for r in rows if r["variant"] == v and r["topology"] == t), 0.0)
                      for t in topos] for v in SERIES}
        _bars(ax, topos, values, "{:.2f}")
        ax.set_title(f"{params} parameters", fontsize=9, color=INK, loc="left")
        ax.set_ylabel("onboarding, median s", fontsize=8, color=INK_2)
    axes[0][0].legend(frameon=False, fontsize=7, labelcolor=INK, loc="upper left")
    fig.suptitle("Onboarding wall time on the host (pure Python)", fontsize=10, color=INK, x=0.01, ha="left")
    fig.tight_layout()
    p = out_dir / f"{stem}_onboarding.png"
    fig.savefig(p, dpi=150, facecolor=SURFACE)
    plt.close(fig)
    paths.append(p)

    paper = [r for r in results if r["topology"] == "paper" and r["params"] == params_list[0]]
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    fig.patch.set_facecolor(SURFACE)
    _style(ax)
    roles = ["BS", "CH", "CM"]
    values = {v: [next((r["per_role"][role]["rp9_constant_ms_per_device"] for r in paper if r["variant"] == v), 0.0)
                  for role in roles] for v in SERIES}
    _bars(ax, roles, values, "{:.0f}")
    ax.set_ylabel("estimated ms per device", fontsize=8, color=INK_2)
    ax.legend(frameon=False, fontsize=7, labelcolor=INK, loc="upper right")
    ax.set_title("Estimated onboarding cost per device, paper topology", fontsize=9.5, color=INK, loc="left")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.text(0.01, 0.015, "Estimate, not a measurement: operation counts × RP9 Table 5 sensor-node constants.",
             fontsize=7, color=INK_2)
    p = out_dir / f"{stem}_cost_per_role.png"
    fig.savefig(p, dpi=150, facecolor=SURFACE)
    plt.close(fig)
    paths.append(p)
    return paths
