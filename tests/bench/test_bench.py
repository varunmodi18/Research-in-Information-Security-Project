"""M7-T5 tooling: the comparison harness, primitive regression check and API latency script
(V-PERF-01..04) produce well-formed results on small inputs."""

from __future__ import annotations

from pathlib import Path

import pytest
from eval.bench import compare, primitives


def test_compare_quick_config_and_thresholds() -> None:
    configs = [compare.Config(v, "paper", "toy") for v in compare.VARIANTS]
    results = compare.run(configs, [1, 2])
    assert [r["variant"] for r in results] == list(compare.VARIANTS)
    for r in results:
        assert r["complete"] and r["deterministic_ops"], r["variant"]
        assert set(r["per_role"]) == {"BS", "CH", "CM"}
    enhanced = results[-1]
    assert enhanced["pairings_per_cm"] == 2
    assert not any(enhanced["per_reading_cm_ops"].get(op) for op in ("T_P", "T_SM", "T_SM_val"))
    rows = {t["metric"]: t for t in compare.thresholds(results, None)}
    assert all(t["pass"] for t in rows.values()), rows
    # RP9 as priced in Table 2 (pseudo-IDs in clear) needs fewer CM operations than the secure variant
    clear, secure = results[1]["per_role"]["CM"], results[0]["per_role"]["CM"]
    assert clear["rp9_constant_ms_per_device"] <= secure["rp9_constant_ms_per_device"]
    md = compare.to_markdown({"meta": {"date": "d", "commit": "c", "cpu": "x", "os": "y", "python": "3",
                                       "seeds": [1, 2], "quick": True},
                              "results": results, "thresholds": list(rows.values()), "lab": []})
    assert "estimate" in md and "| enhanced |" in md.replace("MAKA-E", "enhanced") or "MAKA-E" in md


def test_charts_render(tmp_path: Path) -> None:
    pytest.importorskip("matplotlib")
    from eval.bench import charts

    results = compare.run([compare.Config(v, "paper", "toy") for v in compare.VARIANTS], [1])
    paths = charts.render({"results": results}, tmp_path, "t")
    assert [p.name for p in paths] == ["t_onboarding.png", "t_cost_per_role.png"]
    assert all(p.stat().st_size > 5000 for p in paths)


def test_primitive_regression_flags_only_slowdowns_beyond_20_percent() -> None:
    base = [{"name": "a", "params": "toy", "median_ms": 1.0}, {"name": "b", "params": "toy", "median_ms": 1.0},
            {"name": "c", "params": "toy", "median_ms": 1.0}]
    cur = [{"name": "a", "params": "toy", "median_ms": 1.19}, {"name": "b", "params": "toy", "median_ms": 1.25},
           {"name": "c", "params": "toy", "median_ms": 0.5}, {"name": "d", "params": "toy", "median_ms": 9.0}]
    rows = {r["name"]: r for r in primitives.regressions(cur, base)}
    assert set(rows) == {"a", "b", "c"}
    assert [rows[k]["regression"] for k in "abc"] == [False, True, False]
    assert "**yes**" in primitives.regressions_markdown(list(rows.values()))


@pytest.mark.slow
def test_api_latency_script_toy() -> None:
    from eval.bench import api_latency

    doc = api_latency.measure("toy", 40)
    assert doc["pass"] and len(doc["per_endpoint"]) == 10
    assert "p95" in api_latency.to_markdown(doc)
