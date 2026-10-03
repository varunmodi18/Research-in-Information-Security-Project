"""S5: `maka security --all` -- the seven §6.1 analyses; the five-row correspondence table.

Realises: PLAN.md P11.1, P11.2.
"""

from __future__ import annotations

from security.maka import (
    s1_replay,
    s2_dos,
    s3_ch_impersonation,
    s4_mutual_authentication,
    s5_sybil,
    s6_session_key_secrecy,
    s7_eavesdropping,
)

from maka import trace

CORRESPONDENCE = [
    ("Replay", "§4.1", "§6.1.1"),
    ("Denial of service", "§4.2", "§6.1.2"),
    ("CH impersonation", "§4.3", "§6.1.3"),
    ("Mutual authentication", "§4.4", "§6.1.4"),
    ("Sybil", "§4.5", "§6.1.5"),
]
NO_COUNTERPART = [
    ("Node capture / session-key leakage", "§4.6", "-- (§6.1.6 adjacent, framed as secrecy)"),
    ("Impossibility of session-key computation", "§4.7", "-- (no counterpart)"),
    ("Session key secrecy", "--", "§6.1.6"),
    ("Eavesdropping", "--", "§6.1.7"),
]


def run(params_name: str = "demo", fixture: str = "paper", verbosity: int = 2) -> None:
    t = trace.active()
    t.banner("D4 -- MAKA security evaluation", "RP9 §6.1.1-§6.1.7")

    modules = [s1_replay, s2_dos, s3_ch_impersonation, s4_mutual_authentication,
               s5_sybil, s6_session_key_secrecy, s7_eavesdropping]
    rows = []
    for mod in modules:
        holds = mod.run(params_name)
        if getattr(mod, "KIND", "TEST") == "ILLUSTRATION":
            verdict = "ILLUSTRATION (not falsifiable)"
        else:
            verdict = "HOLDS" if holds else "FAILS"
        rows.append([mod.__name__.rsplit(".", 1)[-1], verdict])

    t.section("verdict", "§6.1 verdict summary")
    t.table(["module", "verdict"], rows, "MAKA security analyses (§6.1)")

    t.section("correspondence", "§4 vs §6.1 correspondence table")
    t.table(["attack class", "§4 (ICMDS)", "§6.1 (MAKA)"], list(CORRESPONDENCE), "Corresponding items")
    t.table(["item", "§4", "§6.1"], list(NO_COUNTERPART), "No counterpart in the other section")


if __name__ == "__main__":
    from maka import rng

    trace.init(run_id="d4-standalone", verbosity=2)
    rng.seed(0)
    run(params_name="toy", fixture="paper")
