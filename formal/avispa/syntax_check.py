"""HLPSL structural self-check (P11.7, extended by IMPLEMENTATION_PLAN.md M7-T1..T3).

Not a full HLPSL grammar: it checks the structure the AVISPA translator would reject or that
makes a goal meaningless --
  * balanced role ... end role blocks, a goal block, a trailing environment() call;
  * actions (request / witness / secret / SND / new()) on the left-hand side of =|> (D1, D2);
  * role invocations whose argument count differs from the role's parameter list;
  * goal identifiers that are never asserted by a witness/request/secret fact (D7).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from maka import trace

HERE = Path(__file__).parent
HLPSL_PATH = HERE / "maka.hlpsl"
MODELS = {
    "maka.hlpsl": "legacy model (not a faithful transcription; kept for history)",
    "rp9_transcribed.hlpsl": "RP9 Figs. 4-8 exactly as printed",
    "rp9_fixed.hlpsl": "RP9 Figs. 4-8 with minimal syntax fixes",
    "maka_e.hlpsl": "MAKA-E v1 AKE",
}
LHS_ACTIONS = re.compile(r"\b(request|witness|secret|wrequest|SND)\s*\(|new\(\)")


@dataclass(frozen=True)
class Finding:
    kind: str
    where: str
    detail: str


def _strip_comments(text: str) -> str:
    return "\n".join(line.split("%")[0] for line in text.splitlines())


def _split_args(s: str) -> list[str]:
    depth, cur, out = 0, "", []
    for ch in s:
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [a.strip() for a in out]


def _param_count(params: str) -> int:
    # "CM,CH,BS:agent, Pubs:public_key, ..." -> one name per comma-separated identifier
    names = 0
    for group in re.split(r":[^,]*?(?:\([^)]*\))?(?:,|$)", params):
        names += len([n for n in group.split(",") if n.strip()])
    return names


def lint(path: Path) -> list[Finding]:
    text = _strip_comments(path.read_text(encoding="utf-8"))
    out: list[Finding] = []
    starts = re.findall(r"^\s*role\s+\w+", text, re.MULTILINE)
    ends = re.findall(r"^\s*end role", text, re.MULTILINE)
    if len(starts) != len(ends):
        out.append(Finding("structure", path.name, f"{len(starts)} 'role' vs {len(ends)} 'end role'"))
    if not re.search(r"^\s*goal\b", text, re.MULTILINE) or "end goal" not in text:
        out.append(Finding("structure", path.name, "missing goal ... end goal block"))
    if "environment()" not in text.split("end goal")[-1]:
        out.append(Finding("structure", path.name, "missing trailing environment() invocation"))

    roles = {m.group(1): _param_count(m.group(2)) for m in
             re.finditer(r"role\s+(\w+)\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)", text)}
    for m in re.finditer(r"(?:composition|/\\)\s*(\w+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)", text):
        name, args = m.group(1), m.group(2)
        if name in roles and len(_split_args(args)) != roles[name]:
            out.append(Finding("arity", name, f"called with {len(_split_args(args))} args, declared {roles[name]}"))

    for role in re.finditer(r"role\s+(\w+).*?end role", text, re.DOTALL):
        for t in re.finditer(r"^\s*(\d+)\.\s*(.*?)=\|>", role.group(0), re.DOTALL | re.MULTILINE):
            lhs = t.group(2)
            for action in LHS_ACTIONS.findall(lhs) or (["new"] if "new()" in lhs else []):
                out.append(Finding("lhs-action", f"{role.group(1)} transition {t.group(1)}",
                                   f"{action or 'new'}(...) on the left of =|>"))

    goal = text.split("goal", 1)[-1].split("end goal")[0] if "end goal" in text else ""
    ids = set(re.findall(r"(?:secrecy_of|authentication_on|weak_authentication_on)\s+([\w, ]+)", goal))
    goal_ids = {i.strip() for group in ids for i in group.split(",") if i.strip()}
    asserted: set[str] = set()
    for fact in re.finditer(r"\b(?:secret|witness|request|wrequest)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)", text):
        asserted |= set(re.findall(r"\w+", fact.group(1)))
    for gid in sorted(goal_ids):
        if gid not in asserted:
            out.append(Finding("vacuous-goal", gid, "goal id never asserted by any secret/witness/request fact"))
    return out


def check(path: Path = HLPSL_PATH) -> list[str]:
    """Back-compatible API: structural errors only (strings)."""
    return [f"{f.where}: {f.detail}" for f in lint(path) if f.kind in ("structure", "arity")]


def run() -> dict[str, list[Finding]]:
    t = trace.active()
    results = {}
    for name, what in MODELS.items():
        findings = lint(HERE / name)
        results[name] = findings
        t.step("HLPSL", f"{name} ({what}): {len(findings)} finding(s)")
        for f in findings:
            t.step("HLPSL", f"  [{f.kind}] {f.where}: {f.detail}")
    return results
