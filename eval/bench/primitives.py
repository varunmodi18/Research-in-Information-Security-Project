"""M0-T4 / V-PERF-01: primitive timings on toy/demo/secure.

    python -m eval.bench.primitives --out docs/baseline/primitives

Iterations per IMPLEMENTATION_PLAN.md M0-T4: toy 200, demo 30, secure 5, after 3 warm-up
runs. Reports median and IQR in milliseconds. Writes `<out>.json` and `<out>.md`.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from eval.bench.timing import WARMUP, Timing, machine, measure
from maka import aead, hashing, ibe, ledger, pairing, params, rng, trace
from maka.field import fp2_to_bytes

ITERATIONS = {"toy": 200, "demo": 30, "secure": 5}


def _cases(params_name: str) -> dict[str, Callable[[int], object]]:
    p = params.get(params_name)
    c, g = p.curve, p.g
    r = rng.Rng(seed=20261002).spawn(params_name)
    k = r.below(c.r_group - 1) + 1
    k_pub = k * g
    pu = hashing.hash_to_point(c, b"BENCH-ID")
    pr = k * pu
    points = [r.below(c.r_group - 1) + 1 for _ in range(4)]
    a_pt, b_pt = points[0] * g, points[1] * g
    ct = ibe.encrypt(c, g, b"x" * 64, pu, k_pub)
    gt = pairing.modified_pairing(c, a_pt, b_pt)
    key = bytes(32)

    return {
        "hash_to_point (T_HG)": lambda i: hashing.hash_to_point(c, f"BENCH-{i}".encode()),
        "scalar_mul (T_SM)": lambda i: (points[2] + i % 7) * g,
        "point_add (T_PA)": lambda i: a_pt + b_pt,
        "weil_pairing (T_P)": lambda i: pairing.modified_pairing(c, a_pt, b_pt, backend="weil"),
        "tate_pairing (T_P alt)": lambda i: pairing.modified_pairing(c, a_pt, b_pt, backend="tate"),
        "ibe_encrypt (T_E/D)": lambda i: ibe.encrypt(c, g, b"x" * 64, pu, k_pub),
        "ibe_decrypt (T_E/D)": lambda i: ibe.decrypt(c, ct, pr),
        "aes_gcm_encrypt_64B (T_S)": lambda i: aead.encrypt(key, b"x" * 64, ad=b"bench"),
        "kdf_sha256 (hashing.kdf)": lambda i: hashing.kdf(fp2_to_bytes(gt), b"BENCH", 32),
    }


def run(param_sets: list[str], iterations: dict[str, int] | None = None) -> list[Timing]:
    iterations = iterations or ITERATIONS
    results: list[Timing] = []
    with tempfile.TemporaryDirectory() as tmp:
        trace.init(run_id="bench-primitives", out_dir=tmp, color=False, verbosity=0)
        rng.seed(20261002)
        with ledger.suppressed():
            for name in param_sets:
                for case, fn in _cases(name).items():
                    results.append(measure(case, name, fn, iterations[name]))
        trace.active().close()
    return results


def to_markdown(results: list[Timing], meta: dict[str, str]) -> str:
    lines = [
        "# Primitive timings",
        "",
        (f"Commit `{meta['commit']}` · {meta['cpu']} · {meta['os']} · Python {meta['python']} · "
         f"{WARMUP} warm-up runs discarded per case."),
        "",
        "Host wall-clock times of the pure-Python reference code. Not sensor-node figures.",
        "",
        "| params | operation | iterations | median (ms) | IQR (ms) |",
        "|---|---|---:|---:|---:|",
    ]
    for t in results:
        lines.append(f"| {t.params} | {t.name} | {t.iterations} | {t.median_ms:.4f} | {t.iqr_ms:.4f} |")
    return "\n".join(lines) + "\n"


def regressions(current: list[dict[str, object]], baseline: list[dict[str, object]],
                tolerance: float = 0.20) -> list[dict[str, object]]:
    """V-PERF-01: compare each primitive's median with the M0-T4 baseline; > tolerance slower is a
    regression to report (not to hide or tune away)."""
    base = {(b["name"], b["params"]): float(b["median_ms"]) for b in baseline}  # type: ignore[arg-type]
    rows = []
    for c in current:
        key = (c["name"], c["params"])
        if key not in base:
            continue
        ratio = float(c["median_ms"]) / base[key]  # type: ignore[arg-type]
        rows.append({"name": c["name"], "params": c["params"], "baseline_ms": round(base[key], 4),
                     "current_ms": round(float(c["median_ms"]), 4),  # type: ignore[arg-type]
                     "ratio": round(ratio, 3), "regression": ratio > 1 + tolerance})
    return rows


def regressions_markdown(rows: list[dict[str, object]]) -> str:
    lines = ["", "## Comparison with the M0-T4 baseline (V-PERF-01; > 20 % slower is reported)", "",
             "| primitive | params | baseline ms | current ms | ratio | regression |", "|---|---|---:|---:|---:|---|"]
    for r in rows:
        flag = "**yes**" if r["regression"] else "no"
        lines.append(f"| {r['name']} | {r['params']} | {r['baseline_ms']} | {r['current_ms']} | {r['ratio']} | {flag} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--params", nargs="+", default=["toy", "demo", "secure"],
                    choices=list(ITERATIONS))
    ap.add_argument("--out", default="docs/baseline/primitives")
    ap.add_argument("--baseline", help="JSON from an earlier run to compare against (V-PERF-01)")
    args = ap.parse_args(argv)

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    results = run(args.params)
    meta = {**machine(), "started": started}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc: dict[str, object] = {"meta": meta, "results": [t.as_dict() for t in results]}
    summary = to_markdown(results, meta)
    if args.baseline:
        reg = regressions(doc["results"], json.loads(Path(args.baseline).read_text())["results"])  # type: ignore[arg-type]
        doc["baseline"] = {"file": args.baseline, "comparison": reg}
        summary += regressions_markdown(reg)
    out.with_suffix(".json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    out.with_suffix(".md").write_text(summary, encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
