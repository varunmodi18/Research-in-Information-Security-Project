"""P11.7: HLPSL syntax self-check (structural, not a full HLPSL grammar parser).

Verifies role/transition/goal structure, balanced role...end role blocks, and that every
protocol_id/secrecy/authentication identifier referenced in `goal` is declared in
`environment`.
"""

from __future__ import annotations

import re
from pathlib import Path

HLPSL_PATH = Path(__file__).parent / "maka.hlpsl"


def check(path: Path = HLPSL_PATH) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors = []

    role_starts = re.findall(r"^role\s+\w+", text, re.MULTILINE)
    role_ends = re.findall(r"^end role", text, re.MULTILINE)
    if len(role_starts) != len(role_ends):
        errors.append(f"unbalanced role blocks: {len(role_starts)} 'role' vs {len(role_ends)} 'end role'")

    if "goal" not in text or "end goal" not in text:
        errors.append("missing goal...end goal block")

    if "environment()" not in text.split("end goal")[-1]:
        errors.append("missing trailing environment() invocation")

    goal_block = text.split("goal", 1)[-1].split("end goal", 1)[0]
    ids_in_goal = set(re.findall(r"\b(sec\d+|em\d+)\b", goal_block))
    env_block = text.split("role environment", 1)[-1]
    ids_declared = set(re.findall(r"\b(sec\d+|em\d+)\b", env_block.split("composition", 1)[0]))
    missing = ids_in_goal - ids_declared
    if missing:
        errors.append(f"goal references undeclared identifiers: {missing}")

    required_roles = {"basestation", "clusterhead", "clustermember", "session", "environment"}
    found_roles = {m.split()[1] for m in role_starts}
    missing_roles = required_roles - found_roles
    if missing_roles:
        errors.append(f"missing required roles: {missing_roles}")

    return errors


def run() -> bool:
    from maka import trace

    t = trace.active()
    errors = check()
    t.check("HLPSL syntax self-check", not errors, [], errors)
    for e in errors:
        t.step("syntax-error", e)
    return not errors


if __name__ == "__main__":
    from maka import trace

    trace.init(run_id="hlpsl-syntax-check", verbosity=1)
    ok = run()
    raise SystemExit(0 if ok else 1)
