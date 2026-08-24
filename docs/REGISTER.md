# REGISTER

Five-way classification of every place this implementation had to make a decision RP9 does not
make for it, per `PLAN.md` §0 rule 3 and §5. Each entry: exact passage at issue, class, resolution,
and a runnable demonstration under `tests/register/`. This file is stubbed in P0.6 and finalised in
P13.6 — until then, entries are populated as the phase that implements them lands.

## ER — genuine errata (5)

- [x] ER-01 — RP9 §5.4.1, `A4` subscript typo (`src/maka/protocol/p4_node_authentication.py`; `tests/test_phase_authentication.py`)
- [x] ER-02 — RP9 §8 Table 5, `T_SM`/`T_PA` rows (`eval/comparison.py::TABLE5`)
- [x] ER-03 — RP9 §2.2, non-degeneracy vs alternating (`src/maka/pairing.py::selftest` tests 5-6; `tests/test_pairing.py`)
- [x] ER-04 — RP9 §3 step 5(d), missing exponent (`src/icmds/session_key.py::decrypt_identity_er04`; `tests/test_icmds_math.py`)
- [x] ER-05 — RP9 §3 step 5(a) vs ICMDS-P §3(1), `s`-selection actor (`src/icmds/session_key.py::setup`; `attacks/icmds/a7_sk_impossible.py`)

## AM — ambiguity or underspecification (9)

- [x] AM-01 — Enc/Dec abstract (resolved by IA-03)
- [x] AM-02 — "sent securely" mechanism (resolved by IA-04)
- [x] AM-03 — `Nc` reused symbol (resolved by IA-05)
- [x] AM-04 — Table 5 vs Table 2 accounting boundary (`eval/comparison.py::TABLE5`)
- [x] AM-05 — Aggregate operation unspecified (`src/maka/protocol/data_transmission.py`; not resolved, halt demonstrated)
- [x] AM-06 — cost-table topology unstated (`src/maka/fixtures.py`)
- [x] AM-07 — Table 4 storage not itemised (`eval/storage.py`)
- [x] AM-08 — ICMDS coefficients delegated to [26] (resolved by SD-01)
- [x] AM-09 — `x_i` unresolved G_2 -> scalar type (`src/icmds/session_key.py::encryption_setup`; IA-11)

## IA — implementation assumptions (11)

- [x] IA-01 — language/dependency policy (`pyproject.toml`)
- [x] IA-02 — pairing instantiation, scalar domain Z_r (`src/maka/curve.py`, `src/maka/pairing.py`, `src/maka/params.py`)
- [x] IA-03 — Enc/Dec instantiation (BF-IBE hybrid) (`src/maka/ibe.py`)
- [x] IA-04 — "sent securely" instantiation (`src/maka/protocol/p3_node_registration.py`, via `ibe.encrypt`)
- [x] IA-05 — nonce instances (N_reg/N_auth_CH/N_auth_CM in `src/maka/protocol/p3_node_registration.py`, `p4_node_authentication.py`)
- [x] IA-06 — symmetric layer for sensed data (`src/maka/aead.py`)
- [x] IA-07 — parameter sets (`tools/gen_params.py`, `src/maka/params.py`, `docs/PARAMETERS.md`)
- [x] IA-08 — channel model (`src/maka/channel.py`)
- [x] IA-09 — hash constructions (H1, H2) (`src/maka/hashing.py`)
- [x] IA-10 — ICMDS coefficient computation (`src/icmds/coefficients.py`)
- [x] IA-11 — two-track x_i handling (`attacks/icmds/a7_sk_impossible.py::_literal_branch`/`_diagnostic_branch`; `src/icmds/session_key.py::to_scalar`)

## OB — observations (6)

- [x] OB-01 — master key k held until destruction (`src/maka/entities/node.py`, `base_station.py`)
- [x] OB-02 — no forward secrecy in SK_{i-BS} (`src/maka/protocol/p5_session_key_agreement.py`)
- [x] OB-03 — 320-bit sizing vs k=2 pairing curve (`eval/communication.py`, `--sizing actual`)
- [x] OB-04 — g is public; A1 alone is not the obstacle (`src/maka/protocol/p4_node_authentication.py::_negative_paths`)
- [ ] OB-05 — no revocation mechanism
- [x] OB-06 — `R` point/scalar collision (`src/icmds/session_key.py::encrypt_literal`; `attacks/icmds/a7_sk_impossible.py`)

## SD — secondary-source dependency (1)

- [x] SD-01 — ICMDS coefficients a_0..a_m from ICMDS-P (`src/icmds/coefficients.py::compute_and_verify`)
