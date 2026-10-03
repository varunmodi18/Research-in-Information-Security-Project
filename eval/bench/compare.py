"""Original vs enhanced comparison (IMPLEMENTATION_PLAN.md §6.5, M7-T5; V-PERF-02, V-PERF-03).

    python -m eval.bench.compare                 # full matrix (several minutes on demo/secure)
    python -m eval.bench.compare --quick         # toy only, 2 seeds (tests, console jobs)

Runs RP9 original mode (secure pseudo-identities on and off) and MAKA-E on the paper, small and
net topologies, with toy and demo parameters (plus secure for paper), seeds 1..5, after one
discarded warm-up run per configuration. Per device role and phase it collects operation counts,
wall time, frames, actual bytes, RP9 paper-model bits and keystore sizes, plus the cost of one
reading per member. "RP9-constant time" multiplies the operation counts by RP9's Table 5
constants: it is an *estimate* of sensor-node cost, not a measurement.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eval import cost_model
from eval.bench.timing import machine
from maka.enhanced import network as en
from maka.original_rt import network as onet

ROLES = ("BS", "CH", "CM")
ONBOARDING_EXCLUDE = {"data", "lifecycle", "replay-demo"}
# RP9 prices only its own operation classes; our extra ones are mapped onto the closest:
# a subgroup check is a scalar multiplication, HKDF and the transcript hash are hashes.
COST_OF = {**cost_model.ALL, "T_SM_val": cost_model.T_SM, "T_HKDF": cost_model.T_H}
VARIANTS = {
    "original+secure": ("original", True),
    "original+clear": ("original", False),
    "enhanced": ("enhanced", None),
}


@dataclass(frozen=True)
class Config:
    variant: str
    topology: str
    params: str


def matrix(quick: bool) -> list[Config]:
    if quick:
        return [Config(v, t, "toy") for t in ("paper", "small") for v in VARIANTS]
    out = [Config(v, t, p) for p in ("toy", "demo") for t in ("paper", "small", "net") for v in VARIANTS]
    out += [Config(v, "paper", "secure") for v in VARIANTS]
    return out


def _build(cfg: Config, seed: int) -> Any:
    mode, secure = VARIANTS[cfg.variant]
    if mode == "original":
        return onet.build(cfg.params, cfg.topology, seed=seed, secure_pseudo_ids=bool(secure))
    return en.build(cfg.params, cfg.topology, seed=seed)


def _role_of(net: Any) -> dict[str, str]:
    return {ident: d.role for ident, d in net.scheduler.devices.items()}


def run_once(cfg: Config, seed: int) -> dict[str, Any]:
    net = _build(cfg, seed)
    roles = _role_of(net)
    peak: dict[str, int] = defaultdict(int)

    def track(_r: Any) -> None:
        for ident, d in net.scheduler.devices.items():
            peak[ident] = max(peak[ident], d.keystore.total_bytes())

    net.scheduler.hooks.append(track)
    t0 = time.perf_counter()
    net.onboard()
    onboard_s = time.perf_counter() - t0
    complete = all(d.status == "active" for d in net.scheduler.devices.values())
    keystore = {ident: d.keystore.total_bytes() for ident, d in net.scheduler.devices.items()}
    onboard_frames = len(net.scheduler.bus.transcript)

    # one reading per member: per-reading cost and size (§6.6)
    cms = [i for i, r in roles.items() if r == "CM"]
    before = {cm: dict(net.ledger.total(cm)) for cm in cms}
    t1 = time.perf_counter()
    for cm in cms:
        net.send_reading(cm, '{"kind": "simulated reading", "temperature_c": 21.4}')
    net.run()
    reading_s = (time.perf_counter() - t1) / max(1, len(cms))
    per_reading = defaultdict(list)
    for cm in cms:
        after = net.ledger.total(cm)
        for op in set(after) | set(before[cm]):
            per_reading[op].append(after.get(op, 0) - before[cm].get(op, 0))
    data_frames = [e.frame for e in net.scheduler.bus.transcript[onboard_frames:]
                   if e.frame.label == "DATA_CM"]

    ops: dict[str, dict[str, dict[str, int]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for entity, phase, op, n in net.ledger.as_rows():
        if entity in roles and phase not in ONBOARDING_EXCLUDE:
            ops[roles[entity]][phase][op] += n
    traffic: dict[str, dict[str, int]] = {r: defaultdict(int) for r in ROLES}
    for e in net.scheduler.bus.transcript[:onboard_frames]:
        f = e.frame
        if f.injected:
            continue
        src_role = roles.get(f.src)
        if src_role:
            traffic[src_role]["frames_sent"] += 1
            traffic[src_role]["bytes_sent"] += len(f.payload)
            traffic[src_role]["paper_bits_sent"] += f.paper_bits
        dst_role = roles.get(f.dst)
        if dst_role:
            traffic[dst_role]["frames_received"] += 1
            traffic[dst_role]["bytes_received"] += len(f.payload)
    count = {r: sum(1 for x in roles.values() if x == r) for r in ROLES}
    return {
        "seed": seed, "complete": complete, "onboard_s": onboard_s, "reading_s": reading_s,
        "steps": net.scheduler.step_no, "device_count": count,
        "ops": {r: {ph: dict(v) for ph, v in phases.items()} for r, phases in ops.items()},
        "traffic": {r: dict(v) for r, v in traffic.items()},
        "keystore_bytes": {r: max((keystore[i] for i in roles if roles[i] == r), default=0) for r in ROLES},
        "peak_keystore_bytes": {r: max((peak[i] for i in roles if roles[i] == r), default=0) for r in ROLES},
        "per_reading_cm_ops": {op: max(v) for op, v in per_reading.items() if max(v)},
        "data_cm_bytes": max((len(f.payload) for f in data_frames), default=0),
        "reading_payload_bytes": len('{"kind": "simulated reading", "temperature_c": 21.4}'),
        "pairings_per_cm": max((sum(n for ph in ops["CM"].values() for o, n in ph.items() if o == "T_P")
                                / max(1, count["CM"]),), default=0),
    }


def _per_device(ops: dict[str, dict[str, int]], n: int) -> dict[str, float]:
    total: dict[str, float] = defaultdict(float)
    for phase in ops.values():
        for op, v in phase.items():
            total[op] += v / max(1, n)
    return dict(total)


def rp9_constant_ms(ops: dict[str, float]) -> float:
    return sum(n * COST_OF.get(op, 0.0) for op, n in ops.items() if op != "T_PA")


def _without_pa(ops: dict[str, dict[str, dict[str, int]]]) -> dict[str, Any]:
    return {r: {ph: {o: n for o, n in v.items() if o != "T_PA"} for ph, v in phases.items()} for r, phases in ops.items()}


def summarise(cfg: Config, runs: list[dict[str, Any]]) -> dict[str, Any]:
    times = [r["onboard_s"] for r in runs]
    q = statistics.quantiles(times, n=4, method="inclusive") if len(times) >= 2 else [times[0]] * 3
    first = runs[0]
    per_role = {}
    for role in ROLES:
        n = first["device_count"][role]
        ops = _per_device(first["ops"].get(role, {}), n)
        per_role[role] = {
            "devices": n, "ops_per_device": {k: round(v, 3) for k, v in sorted(ops.items())},
            "rp9_constant_ms_per_device": round(rp9_constant_ms(ops), 3),
            "phases": first["ops"].get(role, {}),
            "traffic_per_device": {k: round(v / max(1, n), 1) for k, v in first["traffic"][role].items()},
            "keystore_bytes": first["keystore_bytes"][role], "peak_keystore_bytes": first["peak_keystore_bytes"][role],
        }
    return {
        "variant": cfg.variant, "topology": cfg.topology, "params": cfg.params, "seeds": [r["seed"] for r in runs],
        "complete": all(r["complete"] for r in runs),
        "onboard_s": {"median": statistics.median(times), "q1": q[0], "q3": q[2], "iqr": q[2] - q[0]},
        "steps": first["steps"], "per_role": per_role,
        "pairings_per_cm": first["pairings_per_cm"],
        "per_reading_cm_ops": first["per_reading_cm_ops"],
        "reading_s": statistics.median(r["reading_s"] for r in runs),
        "data_cm_bytes": first["data_cm_bytes"], "reading_payload_bytes": first["reading_payload_bytes"],
        # T_PA is excluded: point additions inside double-and-add depend on the (seeded) scalar's bits
        "deterministic_ops": all(_without_pa(r["ops"]) == _without_pa(first["ops"]) for r in runs),
    }


def run(configs: Iterable[Config], seeds: list[int], progress: Any = None) -> list[dict[str, Any]]:
    configs = list(configs)
    out = []
    for i, cfg in enumerate(configs):
        if progress:
            progress(i / len(configs), f"{cfg.variant} {cfg.topology} {cfg.params}")
        run_once(cfg, 0)  # warm-up, discarded (§6.5)
        out.append(summarise(cfg, [run_once(cfg, s) for s in seeds]))
    return out


def thresholds(results: list[dict[str, Any]], legacy_net_demo_s: float | None) -> list[dict[str, Any]]:
    """§6.6 thresholds, evaluated on the enhanced results."""
    rows = []
    enh = [r for r in results if r["variant"] == "enhanced"]
    net_demo = next((r for r in enh if r["topology"] == "net" and r["params"] == "demo"), None)
    if net_demo is not None:
        t = net_demo["onboard_s"]["median"]
        bound = min(60.0, 1.5 * legacy_net_demo_s) if legacy_net_demo_s else 60.0
        rows.append({"metric": "NFR-PERF-01 enhanced onboarding net/demo (s)", "value": round(t, 2),
                     "threshold": f"<= {bound:.1f}", "pass": t <= bound})
    if enh:
        worst = max(r["pairings_per_cm"] for r in enh)
        rows.append({"metric": "pairings per CM during onboarding", "value": worst, "threshold": "<= 2",
                     "pass": worst <= 2})
        ops = [r["per_reading_cm_ops"] for r in enh]
        pk = max(o.get("T_P", 0) + o.get("T_SM", 0) + o.get("T_SM_val", 0) for o in ops)
        sym = max(o.get("T_S", 0) + o.get("T_MAC", 0) for o in ops)
        rows.append({"metric": "per-reading CM public-key operations", "value": pk, "threshold": "0", "pass": pk == 0})
        rows.append({"metric": "per-reading CM AEAD + MAC operations", "value": sym, "threshold": "<= 2",
                     "pass": sym <= 2})
        over = max(r["data_cm_bytes"] - r["reading_payload_bytes"] for r in enh)
        rows.append({"metric": "bytes per reading on the CM->CH hop, minus payload", "value": over,
                     "threshold": "<= 120", "pass": over <= 120})
    return rows


def to_markdown(doc: dict[str, Any]) -> str:
    m = doc["meta"]
    lines = [f"# Original vs enhanced comparison ({m['date']})", "",
             (f"Commit `{m['commit']}` · {m['cpu']} · {m['os']} · Python {m['python']} · seeds {m['seeds']} after one "
              "discarded warm-up per configuration."), "",
             ("Host wall-clock times of pure-Python code; *RP9-constant time* is an estimate (operation counts × "
              "RP9 Table 5 constants), not a sensor-node measurement."), "",
             "## Onboarding", "",
             "| variant | topology | params | complete | onboarding median (s) | IQR (s) | steps | pairings/CM |",
             "|---|---|---|---|---:|---:|---:|---:|"]
    for r in doc["results"]:
        lines.append(f"| {r['variant']} | {r['topology']} | {r['params']} | {'yes' if r['complete'] else 'NO'} | "
                     f"{r['onboard_s']['median']:.3f} | {r['onboard_s']['iqr']:.3f} | {r['steps']} | "
                     f"{r['pairings_per_cm']:.0f} |")
    lines += ["", "## Per device role (paper topology, per device, onboarding)", "",
              ("| params | variant | role | T_HG | T_SM | T_SM_val | T_P | T_E/D | T_HKDF | T_MAC | RP9-constant (ms) | "
               "bytes sent | paper bits sent | keystore B | peak keystore B |"),
              "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in doc["results"]:
        if r["topology"] != "paper":
            continue
        for role in ROLES:
            pr = r["per_role"][role]
            o = pr["ops_per_device"]
            tr = pr["traffic_per_device"]
            lines.append(f"| {r['params']} | {r['variant']} | {role} | {o.get('T_HG', 0):g} | {o.get('T_SM', 0):g} | "
                         f"{o.get('T_SM_val', 0):g} | {o.get('T_P', 0):g} | {o.get('T_E/D', 0):g} | {o.get('T_HKDF', 0):g} | "
                         f"{o.get('T_MAC', 0):g} | {pr['rp9_constant_ms_per_device']:.1f} | {tr.get('bytes_sent', 0):g} | "
                         f"{tr.get('paper_bits_sent', 0):g} | {pr['keystore_bytes']} | {pr['peak_keystore_bytes']} |")
    lines += ["", "## Per reading (one reading per CM)", "", ("| params | topology | variant | CM ops per reading | "
              "DATA_CM bytes | payload bytes |"), "|---|---|---|---|---:|---:|"]
    for r in doc["results"]:
        ops = ", ".join(f"{k} {v}" for k, v in sorted(r["per_reading_cm_ops"].items()) if k != "T_PA")
        lines.append(f"| {r['params']} | {r['topology']} | {r['variant']} | {ops} | {r['data_cm_bytes']} | "
                     f"{r['reading_payload_bytes']} |")
    if doc.get("thresholds"):
        lines += ["", "## Thresholds (§6.6)", "", "| metric | value | threshold | result |", "|---|---:|---|---|"]
        lines += [f"| {t['metric']} | {t['value']} | {t['threshold']} | {'PASS' if t['pass'] else 'FAIL'} |"
                  for t in doc["thresholds"]]
    if doc.get("lab"):
        lines += ["", "## Security comparison (Lab L1–L8, toy, small, seed 20260927)", "",
                  "| scenario | RP9 original | MAKA-E |", "|---|---|---|"]
        lines += [f"| {s['id']} {s['title']} | {s['original']} | {s['enhanced']} |" for s in doc["lab"]]
    return "\n".join(lines) + "\n"


def lab_table() -> list[dict[str, str]]:
    from maka.lab import scenarios as sc

    rows = []
    for s in sc.ALL:
        res = {m: s.execute(m).verdict.result for m in sc.MODES}  # type: ignore[union-attr]
        rows.append({"id": s.id, "title": s.title, **res})
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--out-dir", default="artifacts/eval")
    ap.add_argument("--no-lab", action="store_true")
    args = ap.parse_args(argv)
    seeds = list(range(1, (2 if args.quick else args.seeds) + 1))
    results = run(matrix(args.quick), seeds, progress=lambda f, s: print(f"[{f:4.0%}] {s}", flush=True))
    legacy = Path("docs/baseline/legacy_run.json")
    legacy_s = next((r["median_s"] for r in json.loads(legacy.read_text())["results"]
                     if r["fixture"] == "net"), None) if legacy.exists() else None
    date = time.strftime("%Y-%m-%d")
    doc = {"meta": {**machine(), "date": date, "seeds": seeds, "quick": args.quick},
           "results": results, "thresholds": thresholds(results, legacy_s),
           "lab": [] if args.no_lab else lab_table()}
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = out / f"compare_{date}{'_quick' if args.quick else ''}"
    stem.with_suffix(".json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    stem.with_suffix(".md").write_text(to_markdown(doc), encoding="utf-8")
    try:
        from eval.bench import charts

        charts.render(doc, out, stem.name)
    except ImportError:
        pass
    print(f"wrote {stem}.json, {stem}.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
