# MAKA (Harbi et al., 2019) — reference implementation

A self-contained, fully instrumented, executable reproduction of the MAKA authentication and
key-management scheme (Y. Harbi, Z. Aliouat, A. Refoufi, S. Harous, A. Bentaleb, *Ad Hoc
Networks* 94, 101948, 2019 — "RP9"), its ICMDS baseline, RP9's cryptanalysis of ICMDS, RP9's
own security and formal-verification claims, and its performance/comparative evaluation.

Every claim reproduced here is traced back to a specific RP9 section, and every place this
implementation had to make a decision RP9 does not make for it is classified into one of five
register classes (errata, ambiguity, implementation assumption, observation, secondary-source
dependency) — see `docs/REGISTER.md` and `PLAN.md`, the execution order this repository was
built from.

## The MAKA console (v1.0.0)

On top of the reproduction, the repository contains a web console. It runs simulated sensor networks
under **MAKA-E**, an enhanced protocol that keeps RP9's identity-based keys but replaces the rest with
a PSK-authenticated ephemeral Diffie–Hellman exchange, BS-authorised membership and revocation
(`docs/SECURITY_ARGUMENT.md`). It also has a **Lab** that runs eight attacks against RP9 as published
and against MAKA-E, side by side, on real protocol bytes.

```bash
python3 -m venv .venv && make setup web web-build   # Python deps, npm ci, build the UI
export MAKA_KEK=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
PYTHONPATH=src .venv/bin/python -m maka_server seed-demo   # users admin/operator/viewer (passwords prompted) + demo networks
make serve                                     # http://127.0.0.1:8000
```

Configuration, backups and resets: `docs/OPERATIONS.md`. Docker is not supported (dropped by owner
decision, `docs/PLAN_ERRATA.md` E-07).

| Document | Contents |
|---|---|
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Pages, roles and workflows |
| [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) | The 12-minute demonstration, with fallbacks |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Configuration, KEK, backup and reset, logs |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How the pieces fit |
| [`docs/API.md`](docs/API.md) | HTTP API |
| [`docs/SECURITY_ARGUMENT.md`](docs/SECURITY_ARGUMENT.md), [`docs/RESIDUAL_RISKS.md`](docs/RESIDUAL_RISKS.md) | What MAKA-E claims, why, and what it does not |
| [`artifacts/eval/`](artifacts/eval/) | Original-vs-enhanced comparison, benchmarks |
| [`docs/OPEN_ISSUES.md`](docs/OPEN_ISSUES.md), [`CHANGELOG.md`](CHANGELOG.md) | What is not done, and what was |

**Limitations.**
- Devices, radio and timing are simulated, and there is no energy measurement.
- Arithmetic is pure Python and not constant-time, and the parameters are demonstration-grade: about
  60-bit (`demo`) or 80-bit (`secure`).
- The symbolic analysis is bounded, and there is no computational proof for MAKA-E.
- Passing tests are not a proof of cryptographic security.

## Quick start (reproduction CLI)

```bash
pip install -e ".[dev]"      # or: make setup
pytest -q                    # or: make test
python -m maka.cli all --params demo --fixture paper -v
```

## CLI

```
maka primitives --params {toy,demo,secure} [-vvv]     # curve, pairing self-test, hash-to-point, IBE
maka run --fixture {paper,net} [-vv]                   # the full MAKA protocol, all five phases
maka icmds --attacks all                                # ICMDS baseline + the seven §4 attacks
maka security --all                                     # the seven §6.1 security analyses
maka formal --ban --avispa                               # BAN derivation + HLPSL/OFMC
maka eval --all --fixture paper                          # Tables 2-6, Figures 10-11
maka all                                                  # everything, in sequence
```

Common flags: `--params {toy,demo,secure}`, `--fixture {paper,small,net}`, `--sizing {paper,actual}`,
`--seed N`, `-v`/`-vv`/`-vvv`, `--no-color`, `--out <dir>`, `--secure-pseudo-ids` (default) /
`--no-secure-pseudo-ids` (sends pseudo-identities in clear, as RP9's Table 2 pricing assumes),
`--disclose-secrets`.

`toy` uses a 32-bit curve — insecure by construction, but every trace is hand-followable at
`-vvv`. `demo` (256-bit, default) and `secure` (512-bit) are used for realistic timing.

## Annotated transcript excerpt

```
--- §5.4 Node authentication -----------------------------------------
  r_CH           = «secret:r_CH»   [IA-02] scalar drawn from Z_r* (RP9 writes Z_p; see IA-02)
  A1 = r_CH * g  = (911408649, 2044267400) [on-curve]
  A2 = r_CH * P_CH = (802063548, 1933501766) [on-curve]
  [ER-01] RP9 §5.4.1 prints A4 = r_CH * P_CM, which the CM cannot compute (it has
          no access to r_CH) and which fails the CH's own stated check. Implemented
          as A4 = r_CM * P_CM.
  [CHECK] CM verifies CH: A2' == A2: PASS
```

SECRET-class values (`k`, `Pr_i`, `r_*`, session keys, IBE ephemerals) are recorded only as
`«secret:name»`. `--disclose-secrets` prints them for teaching; it is refused when `MAKA_ENV`
is `demo` or `prod`.

## Fidelity

`docs/FIDELITY.md` (regenerate with `python tools/build_fidelity_matrix.py`) maps every RP9
§2-§8 subsection to the file(s) realising it: 100% coverage as of the last generation.

## What is NOT claimed to be RP9's

The following are this implementation's own scaffolding, entailed by the choices recorded in
`docs/REGISTER.md`'s IA (implementation assumption) entries — none of them is a missing RP9
parameter or a correction to RP9:

- **The concrete pairing** (Type-1 supersingular curve, distortion map, Miller's algorithm) —
  RP9 leaves the pairing entirely abstract (IA-02).
- **`K_pub = k*g`** — scaffolding required by our IBE instantiation of RP9's abstract Enc/Dec
  (IA-03), never printed without the `[IA-03 scaffolding]` marker.
- **The Boneh-Franklin IBE hybrid and AES-256-GCM adapter** — one concrete instantiation of
  RP9's abstract "asymmetric encryption/decryption" and "encryption/decryption" (IA-03, IA-06).
- **The `Z_r_group` scalar domain** — RP9 draws scalars from `Z_p`; our prime-order-subgroup
  instantiation substitutes `Z_r_group` (IA-02), printed at every sampling site.
- **ICMDS-P** (Mehmood et al., 2017 — RP9's reference [26]) is consulted only at RP9's explicit
  delegation point (SD-01, the ICMDS coefficient calculation) and, separately, to verify RP9's
  own transcription of ICMDS (`docs/SOURCES.md`'s Rule 2, which produced ER-04, ER-05, OB-06).
  It never supplies protocol content RP9 does not itself delegate.

## Repository map

- `src/maka/` — the cryptographic core and MAKA protocol (§2, §5).
- `src/icmds/` — the ICMDS baseline (§3).
- `attacks/icmds/` — RP9's seven-item cryptanalysis of ICMDS (§4).
- `security/maka/` — RP9's seven-item security analysis of MAKA (§6.1).
- `formal/` — BAN logic (§6.2) and AVISPA/HLPSL (§6.3).
- `eval/` — cost model and Tables 2-6 / Figures 10-11 (§7-§8).
- `demos/d1`-`d6` — the six chapter drivers `make demo` runs in sequence.
- `docs/REGISTER.md` — the five-class register of every ER/AM/IA/OB/SD decision.
- `docs/SOURCES.md` — the bounded policy governing ICMDS-P's two uses.
- `docs/DEFERRED.md` — what was considered and deliberately not built at this stage.
- `PLAN.md` — the execution order this repository was built from.
- `src/maka/runtime`, `src/maka/original_rt`, `src/maka/enhanced`, `src/maka/lab` — the device runtime,
  RP9 on it, MAKA-E, and the Lab adversary (console).
- `src/maka_server/`, `web/` — the console backend and UI; `.env.example` — configuration template.
- `eval/bench/` — benchmarks and the original-vs-enhanced comparison.
