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

## E-06 · §3.7 J5 and V-E2E-05: the browser journey runs a smaller comparison

**Finding.** J5 names a `net`/`demo`/5-seed comparison. With three variants, one discarded warm-up
and five seeds each, that is 18 onboardings of `net` at `demo` parameters, several minutes of
pure-Python work. A Playwright test that waits on it would dominate the E2E run and time out on
slower hosts.

**Clarification.** The console accepts the full J5 configuration (and it is the form's default).
V-E2E-05 drives the same form with `paper`/`toy`/1 seed, which exercises the same job, storage,
charts, table view and threshold display. The full matrix, including `net`/`demo`/5 seeds, is
produced by `eval/bench/compare.py` and committed under `artifacts/eval/`. The Evaluation page shows
that artefact when no run has been made in the console.

## E-07 · M3-T7, M5-T7, M8-T4 and §7.2: Docker withdrawn by owner decision (2026-10-06)

**Decision.** The project owner dropped Docker. The following are withdrawn:

- M3-T7's acceptance (`docker compose up` on a clean machine, then `create-admin`);
- M5-T7's "against `docker compose`";
- the Docker parts of M8-T4 and §7.2 (the image, compose file and Docker deployment steps);
- §7.3's "Tagged release with Docker image build instructions".

**Accepted acceptance path.** The Playwright journeys run against `web/e2e/serve.sh`, which starts the
backend (`python -m maka_server serve`, fresh database, `MAKA_ENV=test`) serving the production
build of the UI on one port. They run locally before every push and in CI (`.github/workflows/ci.yml`,
job `web`). The supported ways to run the console are `make dev` and `make serve`
(`docs/OPERATIONS.md`).

**Removed.** `deploy/Dockerfile`, `deploy/docker-compose.yml` and `.dockerignore`. `deploy/.env.example`
moved to `.env.example` in the repository root. OI-01 is closed with this reason.

## E-08 · M7-T1..T3 and §6 V-FORMAL-01..03: the formal models as actually run (2026-10-06)

**Finding.** M7 committed the HLPSL files with a structural lint only. Run through the real AVISPA
tools (follow-up Part C; tool chain and attempts in `formal/avispa/TOOLING.md`), several of the
plan's assumptions turned out wrong, and the models were changed as follows. No goal, session or
intruder capability was weakened; every change is marked in the files.

1. **Tool chain.** No single SPAN build runs everything: the original `hlpsl2if` 2.0 rejects RP9's
   `hash_func` type, and the 64-bit package's OFMC (2012c) fails calibration. The chain used is the
   64-bit translator with the original back-ends (OFMC version of 2006/02/13, CL-AtSe 2.2-5) plus
   CL-AtSe 2.3-4, calibrated on SPAN's own test suite.
2. **`rp9_fixed.hlpsl` fixes only what a tool rejects.** The plan's "minimal syntax fixes" were
   M7's lint findings (D1–D6). The tools reject only D1 (CL-AtSe: `request` on the left of `=|>`)
   and D8 (the original translator: `hash_func`), so `rp9_fixed` now carries exactly FIX D1 and
   FIX D8. The fuller set moved to a new file, `rp9_executable.hlpsl` (D1–D6, D8, D9), because
   `rp9_fixed` runs but its authentication phase never executes (OB-11).
3. **New models.** `rp9_insider.hlpsl` (the intruder as a legitimate CM, Part C2.3),
   `maka_e_nopsk_control.hlpsl` (Part C2.5) and the AnB forward-secrecy pair
   `anb/maka_e_ake_fs.AnB` / `anb/maka_e_ake_fs_nodh_control.AnB` (Part C3.1).
4. **`maka_e.hlpsl` changes needed to make the model mean what it says.**
   - The PSK `psk(A,B)` as a function application gave a model where no transition could fire (OFMC: 0
     states). Replaced by one constant per pair, `kab`, `kib`, `kai`; the intruder knows its own
     (`kib`, `kai`), as before.
   - The HKDF labels (`kcr`, `kci`, `kir`, `kri`, `hs2`, `hs3`) are public constants in the
     intruder's knowledge. Without them, even the no-PSK control was SAFE.
   - The role parameters `I`, `R` were renamed `Ini`, `Rsp`: OFMC 2006 crashes on the name `I`
     ("ofmc: I").
5. **Executability probes** (`formal/avispa/probes.py`) are added for every model: a SAFE verdict
   on a model whose transitions cannot fire is not evidence. They are part of V-FORMAL now.
6. **Untyped runs** are recorded for the MAKA-E models in addition to AVISPA's default typed model.
   CL-AtSe's untyped attack on `n_r` is a field-boundary ambiguity that the implementation
   excludes; the exclusion is tested (`tests/enhanced/test_ake.py::test_untyped_boundary_shift_*`).

**Register.** OB-09 corrected, OB-10 reworded, OB-11 and OB-12 added. OI-02 updated.
## E-09 · §4.6.5–§4.6.7, §4.8 and §6.6: protocol fixes after review (follow-up Part D, 2026-10-06)

1. **D1 · `DATA_CM` carries a hop sequence number.** It becomes
   `DATA_CM = V‖0x40‖LP(sid_CM-CH, hop_seq, inner, hop_tag)` with
   `hop_tag = HMAC(HKDF(k_CM→CH, "hop-mac"), LP(sid_CM-CH, hop_seq, inner))`. This amends E-05 item 2.
   - `hop_seq` is a per-CM-CH-session counter starting at 1. The CH checks the tag, then rejects a
     `hop_seq` that is not strictly greater than the last accepted one (`REPLAY_REJECTED`), before
     batching.
   - Before this fix a replayed `DATA_CM` passed the CH (its tag was valid), took a batch slot and
     was rejected only at the BS.
   - Cost: +10 bytes per reading (8-byte counter, 2-byte length prefix).
2. **D6 · the sealed-message nonce is not transmitted.** Sealed messages (§4.6.6) use the nonce
   `0^32‖seq`, which the receiver already has from `seq`. `encode_secure` now carries only the
   ciphertext and tag, saving 12 bytes per sealed message.
   - With D1, the per-reading CM→CH overhead is **114 bytes** (116 before). §6.6's 120-byte
     threshold is unchanged.
   - The test vector `tests/vectors/maka_e_v1.json` was regenerated. Its AKE part is byte-identical
     (the AKE does not use sealed messages). It gains a `data` section (DATA_CM, the inner frame, the
     derived nonce, the hop tag) with its secrets, checked by `tests/enhanced/test_vectors.py`.
3. **D3 · the grant refresh is periodic.** §4.6.7's recovery trigger "on any `UNAUTHORISED_PEER`
   event from the BS" is withdrawn: no message carries such an event to the CH, and it was never
   implemented. Instead the CH re-sends `CLUSTER_CLAIM` over the sealed CH–BS session every
   `MAKA_GRANT_REFRESH_STEPS` steps (default 50), as well as after every CH–BS handshake.
   - The timer is a background timer: it fires when steps are taken but does not keep the network
     busy, so "run to quiescence" still ends.
   - A grant answering a periodic refresh opens (`CLUSTER_OPEN`) only members new to the grant, so
     that a refresh during onboarding does not restart members' handshakes.
4. **D4 · `Session.epoch`** is set at establishment, on both sides, to the registry epoch as that
   side knows it.
   - The BS uses its own epoch. A device uses the latest epoch the BS has sent it.
   - The BS's first epoch-bearing message on a session (`CLUSTER_GRANT` for CH–BS, `DESIGNATION`
     for CM–BS) confirms that session's epoch.
   - Before this fix it was always 0.
5. **D5 · sequence-number bound.** A sender never seals with `seq ≥ 2^32` (or sends `hop_seq ≥ 2^32`)
   under one key. At the bound it refuses (`SEQ_EXHAUSTED`) and the session is rekeyed:
   - an initiator starts a fresh handshake;
   - a responder sends `SESSION_UNKNOWN` for the session, on which the initiator re-handshakes.
     That message is unauthenticated and can only trigger a fresh authenticated handshake.
6. **D2 · revoking a CH.** The BS voids the cluster's designation (§4.6.7), but the members are not
   told directly.
   - Each member keeps its sessions and PSK with the revoked CH until the replacement CH relays a
     new `DESIGNATION` (sealed under the CM–BS session). The member then destroys every session
     and the cached PSK with the old CH.
   - Readings sent in between cannot reach the BS. The console shows these members as "CH revoked,
     awaiting re-designation" and counts their lost readings (`devices.designated`,
     `devices.undelivered`, migration 0003).
7. **D7 · the revoked device is not told.** This is the intended semantics, not an omission.
   - A revoked device is excluded by the BS registry and the CH grants (R-05).
   - A notice to it would bind nothing: a compromised device can ignore it, and an honest one has
     nothing left to protect.
   - Its sessions are destroyed at its peers, and every later handshake from it is refused
     (`UNAUTHORISED_PEER`).

## E-10 · §4.3, §4.4 and §4.6.5: two defects found by the new tests (follow-up Part E, 2026-10-06)

1. **The server read keystores.** §4.4 says nothing in `maka_server` reads a secret from a keystore.
   `services/networks.py::mirror_keystores` did: after provisioning it read every entry (including
   the BS's `k` and each device's `Pr`) with `Keystore.get` to hand it to the encrypted adapter.
   - Fixed: `Keystore.attach(adapter, replay=True)` makes the keystore push the entries it already
     holds through the adapter's `save` hook, the same path every later write takes.
   - `tests/server/test_keystore_guard.py` checks the rule statically (AST over `src/maka_server`)
     and at run time (no `Keystore.get`/`snapshot` called from a `maka_server` module during
     onboarding, readings, revocation, rekey and a Lab run). Each check has a positive control.
2. **A forged `CLUSTER_OPEN` could move a designated member's relay.** E-05 made `CLUSTER_OPEN` an
   unauthenticated hint whose worst effect is one extra handshake (R-13). But the member also
   stored the hint's sender as its relay CH, so all its later CM–BS handshakes (rekeys) went
   through the forger's CH and failed.
   - Fixed: once a member is designated, only a `DESIGNATION` (sealed under the CM–BS session)
     changes its relay. A hint's sender is used only for the one handshake it triggers.
   - Before any designation, the hint still tells a new member where to send its first handshake,
     as E-05 intended.
   - Test: `tests/enhanced/test_review_e3.py::test_forged_cluster_open_from_another_ch_changes_nothing`.

## E-11 · §3.7 and FR-12: console fixes after review (follow-up Part F, 2026-10-06)

1. **F1 · session epoch in the console.** Each side stamps a session with the registry epoch it
   knows at establishment (E-09 item 4). A member that rekeys both its sessions at once can
   complete the CM–CH handshake before the new `DESIGNATION` tells it the epoch, so the two sides
   can differ (CM 0, CH 1). The console's session row shows the larger of the two, which is the
   registry epoch the session was established in. The topology subtitle shows the network's
   registry epoch.
2. **F2 · revoked devices' sessions** read "closed by peer (device revoked)" when the peer's side
   is CLOSED and the device's own side is not, with an explanation (the device is not told, E-09
   item 7).
3. **F3 · job toasts** follow the job: a pending toast stays until the job ends and is then replaced
   by its outcome. This covers revoke, rekey, reprovision, sending readings, periodic readings,
   demo reset, network reset and designation.
4. **F5 · readings carry their CM–BS session id** (a public identifier). This needs migration
   0004, `readings.session_sid`. The Readings page shows its first 8 hex digits next to `seq` and
   marks with ↻ the first reading of each new session, since `seq` restarts at 1 after a rekey.
5. **F6 · Reset network, Delete network (admin only) and Designate CH** have buttons, each with a
   typed confirmation: the network's name to reset or delete it, the cluster label to designate.
   This withdraws USER_GUIDE's "no button in this release" for designation.
6. **F7 · configuration errors.** A missing or malformed `MAKA_KEK` (or any invalid `MAKA_*` value)
   ends the CLI with one line on stderr and exit status 2. Before this fix it printed a Python
   traceback from inside uvicorn's application factory.
7. **F8 · V-EVAL-05's human check is recorded.** The project owner checked RP9 Tables 5 and 6
   against the PDF on 2026-10-06: all 11 rows and all 99 cells match. The Evaluation page states
   this (`eval/comparison.py::TRANSCRIPTION_CHECK`), and a test ties the counts to the committed
   tables.
