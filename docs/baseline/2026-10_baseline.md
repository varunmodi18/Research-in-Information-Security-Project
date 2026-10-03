# Baseline, October 2026 (IMPLEMENTATION_PLAN.md M0)

Recorded before any behaviour change. Every later comparison cites this file.

| Item | Value |
|---|---|
| Commit | `1d01073` (P13 Drivers, tests, packaging, documentation) |
| Date | 2026-10-03 |
| CPU | 13th Gen Intel Core i7-13620H (16 logical CPUs) |
| OS | Ubuntu 24.04.5 LTS, Linux 7.0.0-34-generic |
| Python | 3.12.3 (project virtualenv `.venv`) |
| Key packages | cryptography 50.0.2, pytest 9.1.1, ruff 0.16.10, mypy 2.4.0, hypothesis 6.168.3 |

## M0-T1 Environment and baseline run

**Environment note.** `python3 -m venv .venv` fails on this host because `ensurepip` is not
installed (Debian/Ubuntu ship it separately as `python3.12-venv`). The virtualenv was created
with `python3 -m venv --without-pip .venv`, after which pip was bootstrapped with
`python3 -m pip --python .venv/bin/python install pip`. `pip install -e ".[dev]"` with build
isolation hung during the build step, so the dependencies were installed first and the
package was then installed with `pip install --no-build-isolation --no-deps -e .`.

| Command | Result |
|---|---|
| `pytest -v` | **121 passed** in 4.7 s. Matches the report's count. |
| `ruff check .` | All checks passed |
| `python -m maka.cli all --params demo` | Exit code 0, 28.3 s wall time. 385 `PASS` checks. The only two lines containing `FAIL` are the expected `a7_sk_impossible` "STRUCTURAL FAILURE" verdict on ICMDS (RP9 §4.7), not a failing check |

Tests per file at baseline: register 29, attacks 10, cli_smoke 7, curve 9, entities/fixtures 5,
field 13, formal 3, hygiene 4, icmds_math 3, pairing 4, phase_authentication 3,
phase_registration 3, phase_session_key 4, primitives 8, reproducibility 2, reproduction 4,
security 8, trace_golden 2.

## M0-T2 Were the Phase 3/4 fixes applied?

| Looked for | Found? |
|---|---|
| `CHANGES_PHASE3_PHASE4.md` | No |
| `src/maka/codec.py` | No |
| `secure_pseudo_ids` flag anywhere | No |
| `DegenerateScalarError` anywhere | No |

**Decision (rule "If absent"):** the fix prompt was not applied. I-01..I-06 are
*confirmed open*, and M1-T1..T4 implement them rather than verify them.

Dead-code candidates from IMPLEMENTATION_PLAN.md §1.3, checked with `grep`: `tabulate` (no
import anywhere; declared dependency only), `pairing._render_fp2_g2` (definition only),
`BaseStation.pending_registrations` (assignment only), `icmds.scheme.predistribute`
(definition only), `Channel.count` (definition only). All unused; removal happens in M1-T10.

## M0-T3 Report claims

Tests: `tests/baseline/test_report_claims.py` (`@pytest.mark.baseline`). Each test asserts the
correct behaviour, so a confirmed defect shows as `XFAIL` (strict). I also ran them with
`--runxfail` to check each one fails for the stated reason and not an incidental error.

| Claim | Gap | Verdict | Evidence from `--runxfail` |
|---|---|---|---|
| (a) PSEUDO frames are plaintext | I-02 | **Confirmed** | Frame payloads are a `Point` tuple and a `Point`, not ciphertexts |
| (b) BS registration ledger has 0 T_E/D | I-03 | **Confirmed** | `total('BS-01','registration') == {'T_SM': 2, 'T_PA': 68}` |
| (c) A tampered EM1 still verifies | I-01 | **Confirmed** | With EM1's last ciphertext byte flipped in the channel, the CM still emits `CM verifies CH: A2' == A2` with `ok: True` |
| (d) `xor_to_scalar("X","X",r) == 0`, no exception | I-05 | **Confirmed** | `DID NOT RAISE` |
| (e) `k` appears in the `.log` transcript at verbosity ≥ 1 | I-09 | **Confirmed** | The log contains `k (master key) = 6288705   [DEMO-ONLY DISCLOSURE]` |
| (f) AES-GCM nonces equal across same-seed runs | I-10 | **Confirmed**, kept by design in seeded mode | Identical 12-byte nonces from two runs at seed 99. See `docs/PLAN_ERRATA.md` E-01 |

No claim was refuted.

## M0-T4 Baseline performance

Full tables: [`primitives.md`](primitives.md) / [`primitives.json`](primitives.json)
(`python -m eval.bench.primitives`) and [`legacy_run.md`](legacy_run.md) /
[`legacy_run.json`](legacy_run.json) (`python -m eval.bench.legacy`). Iterations: toy 200,
demo 30, secure 5, each after 3 discarded warm-up runs.

Medians (ms):

| Operation | toy | demo | secure |
|---|---:|---:|---:|
| hash-to-point (T_HG) | 0.150 | 0.623 | 3.46 |
| scalar multiplication (T_SM) | 0.411 | 22.7 | 98.2 |
| point addition (T_PA) | 0.014 | 0.073 | 0.152 |
| modified Weil pairing (T_P) | 4.70 | 148.5 | 572.6 |
| modified Tate pairing | 1.56 | 65.2 | 269.1 |
| IBE encrypt (T_E/D) | 5.26 | 169.1 | 650.8 |
| IBE decrypt (T_E/D) | 4.74 | 148.2 | 552.8 |
| AES-256-GCM encrypt, 64 B (T_S) | 0.0024 | 0.0025 | 0.0025 |
| SHA-256 KDF (`hashing.kdf`) | 0.0007 | 0.0008 | 0.0009 |

These agree with the report's §7.2 figures (pairing 146 ms, SM 22.8 ms on `demo`).

Legacy reference path, `python -m maka.cli run --params demo` (fresh process, median of 3):
`paper` **2.70 s**, `net` **17.49 s**.

### Thresholds this sets (IMPLEMENTATION_PLAN.md §6.6)

- NFR-PERF-01 for enhanced onboarding of `net`/`demo`: ≤ 60 s **and** ≤ 1.5 × 17.49 s =
  **26.2 s**. The 1.5× bound is the tighter one.
- Design estimate for MAKA-E `net`/`demo` (21 handshakes, about 2 pairings and 6 scalar
  multiplications each, including point validation): 21 × (2 × 148.5 + 6 × 22.7) ms ≈ 9.1 s,
  before PSK caching and excluding scheduler overhead.
- V-PERF-01 compares later primitive timings against the table above and reports any
  regression greater than 20%.

## M0-T5 CI

`.github/workflows/ci.yml` runs `make ci` on Python 3.12: `ruff check .` and
`pytest -q -m "not slow"`, which includes the baseline tests. `make ci-slow` adds the slow
tests at checkpoints. Local result on this commit: green.
