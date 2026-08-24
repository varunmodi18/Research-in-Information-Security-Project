"""S6: `maka formal --ban --avispa` -- mechanised BAN derivation R1-R12; HLPSL/OFMC artefact.

Realises: PLAN.md P11.3-P11.7.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from maka import trace


def run(ban: bool = True, avispa: bool = True) -> None:
    t = trace.active()
    t.banner("D5 -- Formal verification", "RP9 §6.2 BAN logic, §6.3 AVISPA/HLPSL")

    if ban:
        from formal.ban import maka_proof

        t.section("6.2", "BAN logic derivation")
        results = maka_proof.run()
        t.check("BAN Goals 1-4 all reached", all(results.values()), True, all(results.values()))

    if avispa:
        from formal.avispa import syntax_check

        t.section("6.3", "AVISPA/HLPSL")
        syntax_check.run()
        script = Path(__file__).resolve().parent.parent / "formal" / "avispa" / "run_ofmc.sh"
        t.step("run_ofmc.sh", f"invoking {script}")
        result = subprocess.run([str(script)], capture_output=True, text=True, timeout=60, check=False)
        for line in result.stdout.splitlines():
            t.step("ofmc", line)


if __name__ == "__main__":
    from maka import rng

    trace.init(run_id="d5-standalone", verbosity=2)
    rng.seed(0)
    run()
