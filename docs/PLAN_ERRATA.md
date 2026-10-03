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

## E-05 · §4.6 MAKA-E v1: details the specification leaves open

Each point below is implemented as described and covered by tests in `tests/enhanced/`.

1. **Onboarding trigger (§4.6.5 step 4).** The sequence says the CM-BS AKE follows the CLUSTER_GRANT,
   but no message tells a member to start. After a grant, the CH sends each granted member without
   a CM-CH session a `CLUSTER_OPEN = V‖0x33‖LP(epoch, ID_CH)`. It is an unauthenticated hint: the
   CM reacts only by starting an authenticated CM-BS handshake through the sender, which the BS
   authorises from its registry. A forged hint costs at most one rate-limited handshake. The CM's
   designated CH is set only by the BS's sealed DESIGNATION.
2. **DATA_CM carries the CM-CH sid.** `DATA_CM = V‖0x40‖LP(sid_CM-CH, inner, hop_tag)` rather than
   `LP(inner, hop_tag)`, so the CH can select the hop key directly and report `UNKNOWN_SESSION`
   (V-ADV-07) or `SESSION_SUPERSEDED` precisely. The hop-MAC key is derived once per CM-CH session,
   which keeps the per-reading cost at one AEAD and one MAC (§6.6).
3. **Lost-session notice.** V-ADV-07 requires the initiator's stale session to be invalidated when the
   responder rejects data with `UNKNOWN_SESSION`, but §4.6.4 sends no replies on failure. The
   rejecting party sends `SESSION_UNKNOWN = V‖0x26‖LP(sid, ID_R, ID_I)`. It is unauthenticated, and
   the initiator acts on it only by starting a fresh handshake for that (peer, purpose). The fresh
   handshake supersedes the stale session; nothing is trusted or destroyed on the notice alone.
4. **Replayed HS1.** V-ADV-01 allows either `UNKNOWN_SESSION` on the HS3 path or a pending handshake
   that times out. The responder rejects any HS1 whose sid it has seen before (`REPLAY_REJECTED`).
   This check is cheap and runs before any public-key work. An HS1 replayed under a *new* sid takes
   the second listed path (UNKNOWN_SESSION at the initiator, then TIMEOUT at the responder), and both
   cases are tested.
5. **Timeouts in steps.** The scheduler delivers one frame per step network-wide, so a handshake's
   latency grows with the number of frames in flight. A fixed `T_HS = 20` would time out on `net`
   during onboarding. The effective timeout is `T_HS + 6 × (number of devices)` (38 steps for `paper`,
   98 for `net`). Original mode scales its timeouts the same way. The configured values are still
   shown in the UI next to the effective ones.
6. **Clusters are named by their first CH.** A cluster keeps its label (e.g. `CH-01`) when the operator
   designates a replacement CH (`CH-01-r1`). Grants check a member's registry cluster label against
   the claiming CH's.
