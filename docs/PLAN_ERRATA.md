# Plan errata

Corrections and clarifications to `IMPLEMENTATION_PLAN.md` found while implementing it. The
plan itself is not edited (M0-T3). Each entry names the plan section it amends.

## E-01 · §2.2 I-10 and M0-T3 claim (f): seeded nonce repetition is retained by design

**Finding.** M0-T3 confirmed that AES-GCM nonces repeat across two runs at the same seed.

**Why it is not treated as a defect to remove.** NFR-REL-02 requires that the same seed and
inputs give an identical frame log, and the existing `tests/test_reproducibility.py` enforces
byte-identical transcripts. Any nonce derived from the seeded RNG, or from a per-key counter,
therefore repeats across same-seed runs, and so does the key. With the same key, nonce *and*
plaintext, GCM produces the same ciphertext, which reveals nothing new. The risk appears only
if a same-seed rerun encrypts a *different* plaintext under the same key, which seeded mode
does not do.

**Amended status of I-10.** Confirmed. The mitigation is what M1-T8 and §4.3 already specify:
mandatory associated data, per-key counter nonces on the data path, and `rng.SystemSource`
for product networks. Seeded repetition is documented as register entry OB-08. The M0-T3
test for (f) is therefore a normal test that documents the seeded behaviour, not a strict
`xfail`.

## E-02 · §2.2 statuses of I-01..I-06

M0-T2 found none of the Phase 3/4 fixes. Read I-01 to I-06 as **Confirmed** (M0-T3 claims a–e
confirm I-01, I-02, I-03, I-05 and I-09 directly; I-04 and I-06 follow from the same code
paths: the CH reads `cm.pu_i` from the member objects, and every encrypted plaintext is
`repr(...).encode()`).

## E-03 · §7.2 and M3-T7: host tooling

The development host has Python 3.12.3 and Node 22.19 (the plan names Node 20; 22 is the
current LTS and is used). Docker is **not installed** on this host, so `docker compose`
acceptance steps (M3-T7, M5-T7, M8-T4) cannot be executed here. The Docker files are still
written; their acceptance is recorded as not run in `docs/OPEN_ISSUES.md`, and the same
journeys are exercised against the non-Docker run (`make dev` / `make serve`).

## E-04 · M1-T2: "zero-pad to 20 bytes"

The plan does not say which side to pad. Left-padding gives the same integer as the current
code (so pseudo-identities would not change, contradicting the M1-T2 acceptance line
"pseudo-identity values change"). The implementation right-pads: each ID occupies the
leading bytes of a 160-bit field, matching RP9 §7.2's 160-bit identifier model. Recorded as
register entry IA-13.
