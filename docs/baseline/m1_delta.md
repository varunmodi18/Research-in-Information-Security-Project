# M1 delta: changed tests and golden files

IMPLEMENTATION_PLAN.md M1-T11 requires every changed golden file or test to be listed with its
reason. Baseline: 121 tests at `1d01073` (see `2026-10_baseline.md`).

## Golden files

| File | Changed? | Reason |
|---|---|---|
| `tests/golden/toy_scenario.jsonl` | No | It records a protocol-independent trace scenario (banner, arithmetic, one register line), so the M1-T2 pseudo-identity change does not reach it. No regeneration was needed |

## Existing tests changed

| Test | Change | Reason |
|---|---|---|
| `tests/baseline/test_report_claims.py` (a)–(e) | Strict `xfail` removed; now regression tests. (a) checks the encoded IBE payload instead of an `ibe.Ciphertext` object; (c) tampers through the new channel interceptor instead of monkeypatching `Channel.send`; (e) also checks hex and the JSONL stream, at verbosity 3 | M1 fixed I-02, I-03, I-01, I-05 and I-09; each flipped to XPASS (strict failure), as M0-T3 intended |
| `tests/baseline/test_report_claims.py` (f) | Passes `ad=b""` | M1-T8 made associated data a required argument |
| `tests/test_entities_and_fixtures.py::test_master_key_destroyed_after_keygen` | `x.k is None` → `not hasattr(x, "k")` | M1-T7: `k` is deleted, not rebound to `None` |
| `tests/register/test_all_entries.py::test_ob01_k_destroyed` | Same as above | Same |
| `tests/register/test_all_entries.py::test_ia06_aead_layer` | Passes `ad=` | M1-T8 |
| `tests/test_primitives.py::test_aead_round_trip_and_tamper_detection` | Passes `ad=` | M1-T8 |
| `tests/test_phase_registration.py::test_registration_table3_row2_on_paper` | `PSEUDO_CH_CM == 320` → `320 + 160` | M1-T4 / IA-14: PSEUDO_CH_CM carries `ID_CH`. RP9's published 1760 is unchanged in the code; the difference is reported as a documented delta |
| `tests/test_reproduction.py::test_table3_communication_hard_assertion` | `registration == 1760` → `1760 + 160` | Same as above |
| `tests/test_formal.py::test_ban_all_four_goals_reached` | Replaced by `test_ban_goal_verdicts` (Goals 3–4 `REACHED`, 1–2 `UNREACHABLE`) and `test_v_eval_03_altered_expected_belief_fails` | M1-T9 (I-12): the old test checked `belief is not None` and could not fail. Goals are now compared with RP9's goal statements |
| `tests/test_security.py` | Added `test_illustrations_are_labelled` and `test_v_eval_04_s7_fails_if_encryption_is_ineffective` | M1-T9: s2/s5 relabelled as illustrations; s7 is now a falsifiable experiment on a real DATA_CM frame |

Every other baseline test passes unchanged.

## Tests added in M1

| File | Covers |
|---|---|
| `tests/test_codec.py` | V-UNIT-01..05, V-FUZZ-01 (500 cases always; 10,000 cases under `slow`) |
| `tests/test_legacy_fixes.py` | V-UNIT-06, V-UNIT-08, V-ORIG-01..06 on the legacy path, OB-07 cost, M1-T5 failure enforcement (tampered EM3/EM2, dropped EM1), I-16 assert lint rule |
| `tests/test_eval_honesty.py` | V-EVAL-01, V-EVAL-02, V-EVAL-05 |
| `tests/test_leakage_cli.py`, `tests/leakscan.py` | V-LEAK-01 for `maka.cli run` (always) and `maka.cli all` (`slow`), plus a positive control with `--disclose-secrets` |
| `tests/test_docs.py` | V-DOC-01 |
| `tests/register/test_all_entries.py` | Demonstrations for new register entries IA-12..IA-16, OB-07, OB-08 |

## Behaviour changes visible in transcripts

- Pseudo-identities are IBE-encrypted by default (`--no-secure-pseudo-ids` restores the clear
  form); `eval` reproduces Tables 2–3 in the clear mode, which is how RP9 prices them.
- Table 3 row 2 reads 1920 on F-PAPER, reported as RP9's 1760 + 160 (IA-14).
- Table 4 shows values derived from stored state next to RP9's, with no forced agreement.
- Table 5 has all 11 rows with a recomputed column; Table 6 is fully transcribed.
- BAN Goals 1–2 now print `FAIL` (`UNREACHABLE`); this is the honest result, not a regression.
- `k`, `Pr_*`, `r_*`, session keys and IBE ephemerals print as `«secret:name»`.

## M1-T11 checkpoint result

- `pytest -m "not slow"`: 178 passed; `pytest -m slow`: 2 passed (10,000-case fuzz, CLI `all` leak scan).
- `ruff check .`: clean.
- `python -m maka.cli all --params demo`: exit 0 in 42.3 s (baseline 28.3 s). The increase comes
  from IBE-encrypted pseudo-identities (OB-07) in the protocol and security runs, from point
  validation on every decode (IA-12, `T_SM_val`), and from `s7` now running Phase 5 and data
  transmission. The only `FAIL` lines are ICMDS's expected `a7` verdict and BAN Goals 1–2
  (`UNREACHABLE`).
