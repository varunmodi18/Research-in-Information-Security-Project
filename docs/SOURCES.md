# SOURCES

RP9 (Y. Harbi, Z. Aliouat, A. Refoufi, S. Harous, A. Bentaleb, *Ad Hoc Networks* 94, 101948, 2019)
is the artefact under implementation. Everything in this repository reproduces RP9 as written,
except where RP9 itself is inexecutable, which is recorded case by case as an erratum (§5.1 of
`PLAN.md`).

ICMDS-P (A. Mehmood, M. M. Umar, H. Song, *Ad Hoc Networks* 55, 97-106, 2017 — RP9's reference
[26]) is used under a strictly bounded policy (`PLAN.md` §5.5), split into two rules:

## Rule 1 — implementation content

ICMDS-P may contribute protocol implementation content only where RP9 explicitly delegates to it.

| ID | RP9 delegation | Resolved from ICMDS-P | Bound |
|---|---|---|---|
| SD-01 | §3, step 5(b): "The calculation of `a_0, a_1, ..., a_m` is provided in detail in [26]" | ICMDS-P §3(2)(a), eqs. (10)-(14) | Coefficient derivation only |

## Rule 2 — diagnostic cross-reading

ICMDS-P may additionally be consulted to verify RP9's transcription of, and claims about, ICMDS.
This may produce ER/OB findings, never SD ones, and may not change what is implemented except
where a stated erratum makes RP9's own summary literally inexecutable (ER-04 only).

| ID | What it checks |
|---|---|
| ER-04 | RP9 §3 step 5(d) decryption identity vs ICMDS-P eq. (17) |
| ER-05 | RP9 §3 step 5(a) vs ICMDS-P §3(1), actor selecting `s` |
| OB-06 | `R` used as both point and scalar in ICMDS-P |

This file is finalised in P13.6 as phases land.
