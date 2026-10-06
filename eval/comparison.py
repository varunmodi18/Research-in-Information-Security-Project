"""RP9 §8: Table 5 (computation-cost comparison) and Table 6 (feature comparison) (P12.5-6).

Revised by IMPLEMENTATION_PLAN.md M1-T9 (I-13): all 11 Table 5 rows and the full Table 6 are
transcribed from RP9. Table 5 shows each row's published time next to a time recomputed from
its printed formula with RP9's own constants (eval/cost_model.py); the recomputed column is
where ER-02 and the third-decimal mismatches show up. Transcription from the PDF must be
confirmed once by a human (IMPLEMENTATION_PLAN.md §8, V-EVAL-05): done by the project owner on
2026-10-06, who checked all 11 rows of Table 5 and all 99 cells of Table 6 against the PDF and
found them to match (TRANSCRIPTION_CHECK).
"""

from __future__ import annotations

from eval import cost_model
from maka import trace

# The human check V-EVAL-05 asks for (follow-up F8). tests/test_eval_honesty.py ties the counts to
# the tables below, so editing a table without re-checking it against the PDF fails a test.
TRANSCRIPTION_CHECK = {"date": "2026-10-06", "by": "the project owner", "source": "the RP9 PDF",
                       "table5_rows": 11, "table6_cells": 99, "result": "all match"}

# (scheme, formula as printed, published ms, flag). Order and values as printed in RP9 Table 5.
TABLE5 = [
    ("MAKA (this work)", "6T_SM + 5T_E/D + 3T_P", 50.039,
     "AM-04: MAKA row states 3T_P; summing Table 2 gives 2T_P"),
    ("Mehmood et al. [26] (ICMDS)", "3T_HG + 7T_SM + 2T_PA + 2T_P", 64.5156,
     "third-decimal mismatch vs recomputed"),
    ("Turkanovic et al. [11]", "12T_H", 0.0276, ""),
    ("Farash et al. [13]", "22T_H", 0.0506, ""),
    ("Shen et al. [16]", "2T_HG + 21T_SM + 11T_PA + 2T_S + 4T_H + 6T_MAC", 71.9448,
     "third-decimal mismatch vs recomputed"),
    ("Wu et al. [17]", "17T_H + 2T_SM", 0.0967, "ER-02: published time corresponds to 2T_PA, not 2T_SM"),
    ("Mishra et al. [20]", "18T_H", 0.0414, ""),
    ("Wang et al. [22]", "19T_H + 2T_SM", 0.1013, "ER-02: published time corresponds to 2T_PA, not 2T_SM"),
    ("Li et al. [25]", "10T_H + 2T_SM", 0.0806, "ER-02: published time corresponds to 2T_PA, not 2T_SM"),
    ("Amin et al. [27]", "26T_H", 0.0598, ""),
    ("Gupta et al. [28]", "10T_H", 0.023, ""),
]


def terms(formula: str) -> dict[str, int]:
    """'6T_SM + 5T_E/D' -> {'T_SM': 6, 'T_E/D': 5}."""
    out: dict[str, int] = {}
    for term in formula.split("+"):
        count, op = term.strip().split("T_", 1)
        out[f"T_{op}"] = int(count) if count else 1
    return out


def recompute(formula: str, substitute: dict[str, str] | None = None) -> float:
    """Time in ms from RP9's constants; `substitute` maps one op onto another (ER-02 check)."""
    substitute = substitute or {}
    return sum(n * cost_model.ALL[substitute.get(op, op)] for op, n in terms(formula).items())


def run_table5() -> list[list[object]]:
    t = trace.active()
    t.section("8-table5", "Table 5: computation-cost comparison")
    rows: list[list[object]] = []
    for name, formula, published, flag in TABLE5:
        recomputed = round(recompute(formula), 4)
        if "ER-02" in flag:
            with_pa = round(recompute(formula, {"T_SM": "T_PA"}), 4)
            t.check(f"{name}: published {published} ms equals the formula with T_PA for T_SM (ER-02)",
                    abs(with_pa - published) < 5e-4, published, with_pa)
        rows.append([name, formula, published, recomputed, flag])
    maka = recompute(TABLE5[0][1])
    t.check("MAKA row: 6T_SM+5T_E/D+3T_P == 50.039 ms", abs(maka - 50.039) < 0.001, 50.039, round(maka, 3))
    t.table(["scheme", "formula (as printed)", "published (ms)", "recomputed (ms)", "flag"], rows,
            "Table 5 -- RP9 values with recomputation from RP9's constants; no conclusion drawn")
    return rows


F_LABELS = ["F1 replay", "F2 DoS", "F3 eavesdropping", "F4 impersonation", "F5 device anonymity",
            "F6 session-key secrecy", "F7 mutual authentication", "F8 session-key agreement",
            "F9 no clock synchronisation"]
SCHEMES6 = ["MAKA (this work)", "[26]", "[11]", "[13]", "[16]", "[17]", "[20]", "[22]", "[25]",
            "[27]", "[28]"]
# RP9 Table 6, one string per feature F1..F9, one character per scheme in SCHEMES6 order:
# Y = check mark (printed as a tick), N = cross.
_TABLE6_ROWS = [
    "YNYYNNYYNYY",  # F1
    "YNYYNNYYNYY",  # F2
    "YNYYYYYYYYY",  # F3
    "YNNNNNYYYNY",  # F4
    "YNNNNYYYYNY",  # F5
    "YYYYYYYYYYY",  # F6
    "YNNNNYYYYYY",  # F7
    "YNYYYYYYYYY",  # F8
    "YYNNYYNNYNN",  # F9
]
TABLE6 = {scheme: [_TABLE6_ROWS[f][i] for f in range(len(F_LABELS))] for i, scheme in enumerate(SCHEMES6)}

F_TO_S6_1 = {
    "F1 replay": "s1_replay (§6.1.1)", "F2 DoS": "s2_dos (§6.1.2, illustration only)",
    "F3 eavesdropping": "s7_eavesdropping (§6.1.7)", "F4 impersonation": "s3_ch_impersonation (§6.1.3)",
    "F5 device anonymity": "no corresponding §6.1 analysis (structural property)",
    "F6 session-key secrecy": "s6_session_key_secrecy (§6.1.6)",
    "F7 mutual authentication": "s4_mutual_authentication (§6.1.4)",
    "F8 session-key agreement": "no corresponding §6.1 analysis (structural property)",
    "F9 no clock synchronisation": "structural (no timestamps used anywhere in the protocol)",
}


def run_table6() -> None:
    t = trace.active()
    t.section("8-table6", "Table 6: feature comparison (transcribed from RP9)")
    rows = [[name] + cells for name, cells in TABLE6.items()]
    t.table(["scheme"] + F_LABELS, rows, "Table 6 (Y = tick, N = cross, as printed)")
    t.table(["feature", "linked §6.1 analysis"], [[f, F_TO_S6_1[f]] for f in F_LABELS],
            "MAKA row: link to the §11.1 analysis addressing each feature")


def run(params_name: str = "demo") -> None:
    run_table5()
    run_table6()
