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

## Quick start

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

Common flags: `--params {toy,demo,secure}`, `--fixture {paper,net}`, `--sizing {paper,actual}`,
`--seed N`, `-v`/`-vv`/`-vvv`, `--no-color`, `--out <dir>`.

`toy` uses a 32-bit curve — insecure by construction, but every trace is hand-followable at
`-vvv`. `demo` (256-bit, default) and `secure` (512-bit) are used for realistic timing.

## Annotated transcript excerpt

```
--- §5.4 Node authentication -----------------------------------------
  r_CH           = 6288705   [IA-02] scalar drawn from Z_r (RP9 writes Z_p; see IA-02)
  A1 = r_CH * g  = (911408649, 2044267400) [on-curve]
  A2 = r_CH * P_CH = (802063548, 1933501766) [on-curve]
  [ER-01] RP9 §5.4.1 prints A4 = r_CH * P_CM, which the CM cannot compute (it has
          no access to r_CH) and which fails the CH's own stated check. Implemented
          as A4 = r_CM * P_CM.
  [CHECK] CM verifies CH: A2' == A2: PASS
```

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
