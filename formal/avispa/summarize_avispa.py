"""Parses the raw formal-tool outputs into JSON summaries (follow-up Part C).

- results/avispa/*  (AVISPA: HLPSL -> hlpsl2if -> OFMC / CL-AtSe)  ->  results/avispa/SUMMARY.json
- results/*.txt     (OFMC 2024 on the AnB models, run_all.sh)       ->  results/SUMMARY.json

Every run is classified from its own text, never assumed: SAFE / UNSAFE (with the goal the back-end
names), REFUSED (the back-end rejected the input), ERROR (crash or unparseable output) or TIMEOUT.
Statistics are copied as printed (OFMC: visited nodes, depth, search time; CL-AtSe: analysed and
reachable states). The executability probes are summarised per transition.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).parent
RES = HERE / "results" / "avispa"
MODELS = ["rp9_transcribed", "rp9_fixed", "rp9_executable", "rp9_insider", "maka_e", "maka_e_nopsk_control"]
# The sessions each HLPSL environment composes (bounded: exactly these, run in parallel).
SESSIONS = {
    "rp9_transcribed": "3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs)",
    "rp9_fixed": "3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs)",
    "rp9_executable": "3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs)",
    "rp9_insider": "3: (cm,ch,bs), (cm2,ch,bs), (i,ch,bs) with i a legitimate CM holding S",
    "maka_e": "4: (a,b) x2 honest, (i,b) with i's own PSK, (a,i) with i's own PSK",
    "maka_e_nopsk_control": "4: (a,b) x2 honest, (i,b), (a,i); no PSK in the tags",
}
BACKENDS = {"ofmc2006": "OFMC (2006/02/13)", "ofmc2006-untyped": "OFMC (2006/02/13), untyped",
            "clatse225": "CL-AtSe 2.2-5", "clatse225-untyped": "CL-AtSe 2.2-5, untyped", "clatse234": "CL-AtSe 2.3-4"}


def parse_run(text: str) -> dict[str, object]:
    exit_m = re.search(r"^# exit: (\d+)", text, re.MULTILINE)
    code = int(exit_m.group(1)) if exit_m else None
    out: dict[str, object] = {"exit": code}
    summ = re.search(r"^SUMMARY\s*\n\s*(\w+)", text, re.MULTILINE)
    if code is None:
        out["verdict"] = "INCOMPLETE"  # no exit line: the run was interrupted or is still running
    elif code == 124:
        out["verdict"] = "TIMEOUT"
    elif summ:
        out["verdict"] = summ.group(1)
    elif "left-hand side" in text:
        out["verdict"] = "REFUSED"
        out["message"] = next(line for line in text.splitlines() if "left-hand side" in line).strip()
    else:
        out["verdict"] = "ERROR"
        body = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        out["message"] = body[0][:200] if body else "(no output)"
    goal = re.search(r"^GOAL\s*\n\s*(.+)", text, re.MULTILINE)
    if goal and out["verdict"] == "UNSAFE":
        out["violated"] = goal.group(1).strip()
    stats: dict[str, object] = {}
    for key, pat in (("visited_nodes", r"visitedNodes:\s*(\d+)"), ("depth_plies", r"depth:\s*(\d+)"),
                     ("search_time", r"searchTime:\s*([\d.]+s)"), ("analysed_states", r"Analysed\s*:\s*(\d+)"),
                     ("reachable_states", r"Reachable\s*:\s*(\d+)")):
        m = re.search(pat, text)
        if m:
            stats[key] = int(m.group(1)) if m.group(1).isdigit() else m.group(1)
    if stats:
        out["statistics"] = stats
    return out


def translation(path: Path) -> dict[str, object]:
    """hlpsl2if's verdict on one model, its error and warning lines verbatim (minus the %% prefix)."""
    text = path.read_text(encoding="utf-8")
    lines = [ln.strip("% ").strip() for ln in text.splitlines() if ln.startswith("%%")]
    err = [ln for ln in lines if re.search(r"error|Err\(", ln)]
    warn = sorted({ln for ln in lines if "warning(" in ln})
    return {"accepted": "IF output in" in text, "errors": err, "warnings": warn, "file": str(path.relative_to(HERE))}


def summarize() -> dict[str, object]:
    models: dict[str, object] = {}
    for m in MODELS:
        tr = {k: translation(RES / "translate" / f"{m}.hlpsl2if-{k}.txt")
              for k in ("64", "32") if (RES / "translate" / f"{m}.hlpsl2if-{k}.txt").exists()}
        runs = []
        for f in sorted((RES / "runs").glob(f"{m}*.txt")):
            stem = f.name[:-4]
            name, _, backend = stem.rpartition(".")
            if name == m:
                goal = "all goals"
            elif name.startswith(m + "-"):
                rest = name[len(m) + 1:]
                if rest.startswith(("nopsk", "control")):
                    continue
                goal = rest
            else:
                continue
            runs.append({"goal": goal, "backend": BACKENDS.get(backend, backend), **parse_run(f.read_text()),
                         "file": str(f.relative_to(HERE))})
        order = list(BACKENDS.values())
        runs.sort(key=lambda r: (r["goal"] != "all goals", str(r["goal"]), order.index(str(r["backend"]))))
        probes = {}
        for f in sorted((RES / "probes" / m).glob("*.ofmc2006.txt")):
            t = re.search(r"probe_(\w+?)\.ofmc2006", f.name)
            v = parse_run(f.read_text())["verdict"]
            probes[t.group(1) if t else f.name] = {"UNSAFE": "executes", "SAFE": "never executes"}.get(str(v), str(v))
        models[m] = {"sessions": SESSIONS[m], "translation": tr, "runs": runs, "executability_ofmc2006": probes}
    return {
        "tool_chain": {
            "translator": "hlpsl2if (64-bit SPAN 1.6 package; accepts hash_func) -- original 32-bit hlpsl2if 2.0 also recorded",
            "backends": ["OFMC version of 2006/02/13 (original 32-bit SPAN 1.6)", "CL-AtSe 2.2-5 (original 32-bit SPAN 1.6)",
                         "CL-AtSe 2.3-4 (64-bit SPAN 1.6)"],
            "not_used": "OFMC 2012c of the 64-bit SPAN 1.6 package: calibration shows it does not search (TOOLING.md)",
            "model": "typed (SPAN default) unless marked untyped; bounded sessions as written in each environment",
        },
        "paper_fig9": {"backend": "OFMC", "verdict": "SAFE", "visited_nodes": 1501, "depth_plies": 7},
        "models": models,
    }


ANB_RUNS = re.compile(r"^(?P<model>\w+)\.sessions(?P<n>\d+)\.txt$")


def parse_anb(text: str) -> dict[str, object]:
    summ = re.search(r"^SUMMARY:\s*\n\s*(\w+)", text, re.MULTILINE)
    goal = re.search(r"^GOAL:\s*\n\s*(.+)", text, re.MULTILINE)
    out: dict[str, object] = {"summary": summ.group(1) if summ else "ERROR", "goal": goal.group(1).strip() if goal else ""}
    stats: dict[str, object] = {}
    for key, pat in (("time", r"^\s*TIME (\d+ ms)"), ("visited_nodes", r"visitedNodes:\s*(\d+)"),
                     ("depth_plies", r"depth:\s*(\d+)")):
        m = re.search(pat, text, re.MULTILINE)
        if m:
            stats[key] = int(m.group(1)) if m.group(1).isdigit() else m.group(1)
    out["statistics"] = stats
    date = re.search(r"^# date: (\S+)", text, re.MULTILINE)
    out["date"] = date.group(1) if date else ""
    return out


def summarize_anb() -> dict[str, object]:
    results: dict[str, list[dict[str, object]]] = {}
    for f in sorted((HERE / "results").glob("*.txt")):
        m = ANB_RUNS.match(f.name)
        if not m:
            continue
        run = {"sessions": int(m.group("n")), **parse_anb(f.read_text(encoding="utf-8")),
               "file": str(f.relative_to(HERE))}
        results.setdefault(m.group("model"), []).append(run)
    for runs in results.values():
        runs.sort(key=lambda r: int(str(r["sessions"])))
    dates = sorted(str(r["date"]) for runs in results.values() for r in runs if r["date"])
    return {"tool": "OFMC 2024 (AnB)", "date": dates[-1][:10] if dates else "", "results": results}


README = HERE / "README.md"
BEGIN, END = "<!-- BEGIN GENERATED RESULTS (summarize_avispa.py) -->", "<!-- END GENERATED RESULTS -->"


def _stats(st: dict[str, object] | None) -> str:
    if not st:
        return "—"
    parts = []
    for key, fmt in (("visited_nodes", "{} nodes"), ("depth_plies", "depth {}"), ("analysed_states", "{} analysed"),
                     ("reachable_states", "{} reachable"), ("search_time", "{}"), ("time", "{}")):
        if key in st:
            parts.append(fmt.format(st[key]))
    return ", ".join(parts)


def _verdict(run: dict[str, object]) -> str:
    v = str(run["verdict"])
    extra = run.get("violated") or run.get("message") or ""
    return f"**{v}**" + (f": `{extra}`" if extra else "")


def render(avispa: dict[str, object], anb: dict[str, object]) -> str:
    """The README's results block, from the two summaries (nothing typed by hand)."""
    models: dict[str, dict[str, object]] = avispa["models"]  # type: ignore[assignment]
    out = ["### AVISPA (HLPSL): translation", "",
           "| Model | hlpsl2if (64-bit SPAN 1.6) | hlpsl2if 2.0 (original 32-bit SPAN 1.6) |", "|---|---|---|"]
    for name, m in models.items():
        tr: dict[str, dict[str, object]] = m["translation"]  # type: ignore[assignment]
        cells = []
        for k in ("64", "32"):
            t = tr.get(k)
            if t is None:
                cells.append("—")
                continue
            note = "; ".join(f"`{e}`" for e in t["errors"]) or "; ".join(f"`{w}`" for w in t["warnings"])  # type: ignore[union-attr]
            cells.append(("accepted" if t["accepted"] else "**rejected**") + (f": {note}" if note else ""))
        out.append(f"| `{name}` | {cells[0]} | {cells[1]} |")
    out += ["", "### AVISPA (HLPSL): OFMC, CL-AtSe, all goals together", "",
            "| Model | Sessions | Back-end | Verdict | Statistics | Raw output |", "|---|---|---|---|---|---|"]
    for name, m in models.items():
        for r in (r for r in m["runs"] if r["goal"] == "all goals"):  # type: ignore[union-attr]
            out.append(f"| `{name}` | {m['sessions']} | {r['backend']} | {_verdict(r)} | {_stats(r.get('statistics'))} "
                       f"| `{r['file']}` |")
    out += ["", "### AVISPA (HLPSL): one goal at a time (`hlpsl2if --split`)", "",
            "| Model | Goal | OFMC (2006/02/13) | CL-AtSe 2.2-5 |", "|---|---|---|---|"]
    for name, m in models.items():
        goals = sorted({str(r["goal"]) for r in m["runs"] if r["goal"] != "all goals" and "untyped" not in str(r["backend"])})  # type: ignore[union-attr]
        for g in goals:
            cell = {}
            for r in m["runs"]:  # type: ignore[union-attr]
                if r["goal"] == g:
                    cell[r["backend"]] = f"{r['verdict']} ({_stats(r.get('statistics'))})" if r.get("statistics") else str(r["verdict"])
            out.append(f"| `{name}` | `{g}` | {cell.get('OFMC (2006/02/13)', '—')} | {cell.get('CL-AtSe 2.2-5', '—')} |")
    out += ["", "### Executability probes (OFMC 2006): which transitions can ever fire", "",
            "| Model | Can execute | Never execute |", "|---|---|---|"]
    for name, m in models.items():
        pr: dict[str, str] = m["executability_ofmc2006"]  # type: ignore[assignment]
        yes = [t for t, v in pr.items() if v == "executes"]
        no = [t for t, v in pr.items() if v == "never executes"]
        other = [f"{t} ({v})" for t, v in pr.items() if v not in ("executes", "never executes")]
        out.append(f"| `{name}` | {', '.join(yes) or '—'} ({len(yes)}/{len(pr)}) | {', '.join(no + other) or '—'} |")
    out += ["", "### OFMC 2024 (AnB models)", "",
            "| Model | Sessions | Verdict | Goal violated | Statistics (as printed) | Raw output |", "|---|---:|---|---|---|---|"]
    results: dict[str, list[dict[str, object]]] = anb["results"]  # type: ignore[assignment]
    for name, runs in results.items():
        for r in runs:
            goal = f"`{r['goal']}`" if r["summary"] == "ATTACK_FOUND" else "—"
            out.append(f"| `{name}` | {r['sessions']} | **{r['summary']}** | {goal} | {_stats(r.get('statistics'))} | `{r['file']}` |")
    return "\n".join(out) + "\n"


def write_readme(block: str) -> None:
    text = README.read_text(encoding="utf-8")
    head, _, rest = text.partition(BEGIN)
    _, _, tail = rest.partition(END)
    README.write_text(f"{head}{BEGIN}\n{block}{END}{tail}", encoding="utf-8")


def readme_block() -> str:
    text = README.read_text(encoding="utf-8")
    return text.partition(BEGIN)[2].partition(END)[0].removeprefix("\n")


def main() -> int:
    avispa, anb = summarize(), summarize_anb()
    (RES / "SUMMARY.json").write_text(json.dumps(avispa, indent=1) + "\n", encoding="utf-8")
    (HERE / "results" / "SUMMARY.json").write_text(json.dumps(anb, indent=1) + "\n", encoding="utf-8")
    if BEGIN in README.read_text(encoding="utf-8"):
        write_readme(render(avispa, anb))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
