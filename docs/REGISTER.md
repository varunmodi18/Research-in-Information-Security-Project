# REGISTER

Five-way classification of every place this implementation had to make a decision RP9 does not
make for it, per `PLAN.md` §0 rule 3 and §5. Each entry: exact passage at issue, class, resolution,
and a runnable demonstration under `tests/register/`. This file is stubbed in P0.6 and finalised in
P13.6 — until then, entries are populated as the phase that implements them lands.

## ER — genuine errata (5)

- [ ] ER-01 — RP9 §5.4.1, `A4` subscript typo
- [ ] ER-02 — RP9 §8 Table 5, `T_SM`/`T_PA` rows
- [x] ER-03 — RP9 §2.2, non-degeneracy vs alternating (`src/maka/pairing.py::selftest` tests 5-6; `tests/test_pairing.py`)
- [ ] ER-04 — RP9 §3 step 5(d), missing exponent
- [ ] ER-05 — RP9 §3 step 5(a) vs ICMDS-P §3(1), `s`-selection actor

## AM — ambiguity or underspecification (9)

- [ ] AM-01 — Enc/Dec abstract
- [ ] AM-02 — "sent securely" mechanism
- [ ] AM-03 — `Nc` reused symbol
- [ ] AM-04 — Table 5 vs Table 2 accounting boundary
- [ ] AM-05 — Aggregate operation unspecified
- [ ] AM-06 — cost-table topology unstated
- [ ] AM-07 — Table 4 storage not itemised
- [ ] AM-08 — ICMDS coefficients delegated to [26]
- [ ] AM-09 — `x_i` unresolved G_2 -> scalar type

## IA — implementation assumptions (11)

- [x] IA-01 — language/dependency policy (`pyproject.toml`)
- [x] IA-02 — pairing instantiation, scalar domain Z_r (`src/maka/curve.py`, `src/maka/pairing.py`, `src/maka/params.py`)
- [ ] IA-03 — Enc/Dec instantiation (BF-IBE hybrid)
- [ ] IA-04 — "sent securely" instantiation
- [ ] IA-05 — nonce instances
- [ ] IA-06 — symmetric layer for sensed data
- [x] IA-07 — parameter sets (`tools/gen_params.py`, `src/maka/params.py`, `docs/PARAMETERS.md`)
- [ ] IA-08 — channel model
- [ ] IA-09 — hash constructions (H1, H2)
- [ ] IA-10 — ICMDS coefficient computation
- [ ] IA-11 — two-track x_i handling

## OB — observations (6)

- [ ] OB-01 — master key k held until destruction
- [ ] OB-02 — no forward secrecy in SK_{i-BS}
- [ ] OB-03 — 320-bit sizing vs k=2 pairing curve
- [ ] OB-04 — g is public; A1 alone is not the obstacle
- [ ] OB-05 — no revocation mechanism
- [ ] OB-06 — `R` point/scalar collision

## SD — secondary-source dependency (1)

- [ ] SD-01 — ICMDS coefficients a_0..a_m from ICMDS-P
