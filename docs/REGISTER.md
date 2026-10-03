# REGISTER

Five-way classification of every place this implementation had to make a decision RP9 does not
make for it, per `PLAN.md` §0 rule 3 and §5. Each entry: exact passage at issue, class, resolution,
and a runnable demonstration under `tests/register/`. Finalised at P13.6 with 32 entries; extended
by IMPLEMENTATION_PLAN.md M1 and M4 to 40 entries (5 ER, 9 AM, 17 IA, 8 OB, 1 SD).

## ER — genuine errata (5)

- [x] ER-01 — RP9 §5.4.1, `A4` subscript typo (`src/maka/protocol/p4_node_authentication.py`; `tests/test_phase_authentication.py`)
- [x] ER-02 — RP9 §8 Table 5, `T_SM`/`T_PA` rows (`eval/comparison.py::TABLE5`)
- [x] ER-03 — RP9 §2.2 prints `e(P,P) ≠ 1` as its non-degeneracy axiom; this axiom is unsatisfiable for the plain Weil pairing on a single cyclic group (which is alternating, `e(P,P) = 1`), which is why the distortion map is required (`src/maka/pairing.py::selftest` tests 5-6; `tests/test_pairing.py`)
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
- [x] IA-04 — "sent securely" instantiation: IBE encryption to the recipient (`H(ID_CH)` for PSEUDO_BS_CH, `Pu_CM` for PSEUDO_CH_CM) when the `secure_pseudo_ids` flag is on, which is the default since IMPLEMENTATION_PLAN.md M1-T4. With `--no-secure-pseudo-ids` (paper-table reproduction) they are sent in clear. Before M1 they were always sent in clear despite this entry (I-02) (`src/maka/protocol/p3_node_registration.py`)
- [x] IA-05 — nonce instances (N_reg/N_auth_CH/N_auth_CM in `src/maka/protocol/p3_node_registration.py`, `p4_node_authentication.py`)
- [x] IA-06 — symmetric layer for sensed data (`src/maka/aead.py`)
- [x] IA-07 — parameter sets (`tools/gen_params.py`, `src/maka/params.py`, `docs/PARAMETERS.md`)
- [x] IA-08 — channel model (`src/maka/channel.py`)
- [x] IA-09 — hash constructions (H1, H2) (`src/maka/hashing.py`)
- [x] IA-10 — ICMDS coefficient computation (`src/icmds/coefficients.py`)
- [x] IA-11 — two-track x_i handling (`attacks/icmds/a7_sk_impossible.py::_literal_branch`/`_diagnostic_branch`; `src/icmds/session_key.py::to_scalar`)
- [x] IA-12 — wire codec: length-prefixed, versioned messages; every decoded point is validated (on-curve, not infinity, `r·P = O`). The subgroup check costs one scalar multiplication, counted as `T_SM_val`, separate from `T_SM`, so RP9 Table 2 comparisons are unaffected (`src/maka/codec.py`)
- [x] IA-13 — identifiers are 1–20 bytes of `[A-Za-z0-9-]`, placed left-aligned in a zero-padded 160-bit field before `ID_a ⊕ ID_b` (RP9 §7.2's 160-bit IDs); a zero scalar raises `DegenerateScalarError` (`src/maka/protocol/p3_node_registration.py::xor_to_scalar`)
- [x] IA-14 — PSEUDO_CH_CM carries `ID_CH` in addition to `P_CM`, so the CM learns from a received message which CH to verify against; +160 paper bits per member, so Table 3 row 2 is `1760 + 160·n` (`src/maka/protocol/p3_node_registration.py`)
- [x] IA-15 — `r_CH`, `A1`, `A2`, `N_auth_CH` drawn once per CH round, one EM1 per member and a single EM2, as RP9 §5.4 describes; the previous per-member regeneration (I-08) is retired (`src/maka/protocol/p4_node_authentication.py`)
- [x] IA-17 — **MAKA-E v1** (enhanced mode, the default on product networks) replaces RP9 §5.1–§5.5 apart from the key material `Pr_i = k·H(ID_i)`: provisioning without `k` on devices (C1), pairwise PSKs `HKDF(ê(Pr_A, H(ID_B)))` (C2), a PSK-authenticated ephemeral-DH key exchange modelled on TLS 1.3 `psk_dhe_ke` (C3), and BS-authorised membership, designation, revocation and authenticated batching (C4). Specified in IMPLEMENTATION_PLAN.md §4.6 with the clarifications in `docs/PLAN_ERRATA.md` E-05. RP9 as published remains available as original mode on lab networks (`src/maka/enhanced/`; `tests/enhanced/`)
- [x] IA-16 — DATA_CM: AES-256-GCM with associated data `LP(ID_CM, ID_BS, seq)` and nonce `0^32 ‖ seq`, `seq` a per-sender counter (`src/maka/protocol/data_transmission.py`, `src/maka/aead.py`)

## OB — observations (6)

- [x] OB-01 — master key k held until destruction (`src/maka/entities/node.py`, `base_station.py`)
- [x] OB-02 — no forward secrecy in SK_{i-BS} (`src/maka/protocol/p5_session_key_agreement.py`)
- [x] OB-03 — 320-bit sizing vs k=2 pairing curve (`eval/communication.py`, `--sizing actual`)
- [x] OB-04 — g is public; A1 alone is not the obstacle (`src/maka/protocol/p4_node_authentication.py::_negative_paths`)
- [x] OB-05 — no revocation mechanism (recorded, nothing built; `tests/register/test_all_entries.py::test_ob05_no_revocation_mechanism_exists`)
- [x] OB-06 — `R` point/scalar collision (`src/icmds/session_key.py::encrypt_literal`; `attacks/icmds/a7_sk_impossible.py`)
- [x] OB-07 — RP9 Table 2 does not price secure pseudo-identity delivery: it adds `n+1` T_E/D at the CH, 1 T_E/D at each CM, and 1 T_E/D + 1 T_HG at the BS (measured: `tests/test_legacy_fixes.py::test_secure_pseudo_ids_cost_matches_ob07`). Paper-table reproduction therefore runs with `--no-secure-pseudo-ids` (`src/maka/protocol/p3_node_registration.py`)
- [x] OB-08 — in seeded mode, AES-GCM nonces (counter or RNG-drawn) and keys repeat across runs with the same seed, as NFR-REL-02 requires; a rerun only re-encrypts identical plaintexts, so nothing new is revealed. Product mode draws from the OS (`docs/PLAN_ERRATA.md` E-01; `src/maka/protocol/data_transmission.py`)

## SD — secondary-source dependency (1)

- [x] SD-01 — ICMDS coefficients a_0..a_m from ICMDS-P (`src/icmds/coefficients.py::compute_and_verify`)
