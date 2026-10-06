# MAKA-E v1: security argument

This is a structured, **informal** argument for each security property MAKA-E v1 claims
(IMPLEMENTATION_PLAN.md §2.5 item 2). For each property it states the mechanism, the assumption it
rests on, the closest analysed analogue, and the evidence in this repository. It is not a proof.
The [last section](#what-is-not-established) lists what is not established.

The protocol is specified in IMPLEMENTATION_PLAN.md §4.6, with the clarifications in
`docs/PLAN_ERRATA.md` E-05. MAKA-E keeps RP9's identity-based key material and replaces the rest:

> **MAKA-E is RP9's key material with a standard authenticated key exchange.** Each device holds
> `Pr_i = k·H(ID_i)`. Two devices derive a pre-shared key non-interactively (the
> Sakai–Ohgishi–Kasahara construction) and run a PSK-authenticated ephemeral Diffie–Hellman
> exchange with the same structure as TLS 1.3 `psk_dhe_ke`. It is not a new cryptographic design,
> and its security story is borrowed from those two well-analysed constructions.

## Model and assumptions

- **Adversaries**: IMPLEMENTATION_PLAN.md §2.1, AT1–AT5. A Dolev–Yao network adversary, outsider
  devices, malicious insiders holding their own `Pr_i`, capture of one device, and flooding.
- **Trusted**: the BS and provisioning authority (it holds `k`), and the factory channel that loads
  `Pr_i`.
- **Cryptographic assumptions**:
  - **A1 BDH** in the pairing groups: given `P, aP, bP, cP`, computing `ê(P,P)^{abc}` is hard.
  - **A2 Gap-CDH** in `G = E(F_p)[r]`. CDH is hard even with a DDH oracle. The symmetric pairing
    *is* a DDH oracle in `G`, so plain DDH does not hold here, and the argument never needs it.
  - **A3** HKDF-SHA256 and HMAC-SHA256 are PRFs. Where a Diffie–Hellman value is fed into HKDF, HKDF
    is modelled as a random oracle (as in the standard analyses of SOK and TLS 1.3).
  - **A4** AES-256-GCM is a secure AEAD as long as a (key, nonce) pair is never reused.
  - **A5** `H` (hash-to-curve) is a random oracle onto `G`.
- **Parameter caveat**: embedding degree 2 puts discrete logarithms in `F_{p²}`. The `demo` set
  (512-bit `F_{p²}`) gives about 60-bit security and `secure` (1024-bit) about 80-bit. These are
  demonstration parameters; nothing here claims deployment-grade security.

## Properties

### P1. Only A, B (and the BS) can compute `PSK_AB`

- **Mechanism**: `S_AB = ê(Pr_A, H(ID_B)) = ê(H(ID_A), H(ID_B))^k`, and
  `PSK_AB = HKDF(S_AB, "MAKA-E/v1/psk", LP(lo, hi))`. The value depends only on the unordered pair,
  because ê is symmetric and bilinear.
- **Argument**: this is SOK non-interactive key distribution. Computing `S_AB` without `Pr_A`,
  `Pr_B` or `k` is a BDH instance in the random-oracle model (A1, A5). The same holds for an insider
  `C` that holds `Pr_C`: its key yields `S_CX` for its own pairs only. HKDF binds the result to the
  two identities (A3).
- **Analogue**: SOK non-interactive key distribution. Its security under BDH in the random-oracle
  model is shown by Dupont and Enge (2006) and by Paterson and Srinivasan (2009).
- **Evidence**: V-UNIT-10 (symmetry, distinctness, equality with the BS's computation from `k`);
  Lab L3 enhanced (an insider's best PSK guesses all fail, 0/100 in V-ADV-10).
- **Not modelled symbolically**: the AnB models take `psk(A,B)` as an uninterpreted function, and the
  HLPSL model as one secret constant per pair (`kab`; the intruder's own are `kib`, `kai`).

### P2. Mutual authentication and key confirmation (AKE)

- **Mechanism**: `tag_R = HMAC(kc_R, "HS2"‖th)` and `tag_I = HMAC(kc_I, "HS3"‖th)`. Here
  `th = SHA-256(HS1‖HS2-without-tag)` and the `kc_*` come from `HKDF(PSK‖Z, th, LP(label, purpose))`.
  A valid `tag_R` can only be produced with `PSK_IR`, and it covers the initiator's fresh `N_I` and
  `X` (both in `th`), so it authenticates R to I for this run. `tag_I` does the same in the other
  direction and also confirms the key (R learns that I derived the same keys).
- **Assumptions**: P1, A3.
- **Analogue**: TLS 1.3 `psk_dhe_ke`. Its PSK binder and Finished MACs play the role of
  `tag_R`/`tag_I`, and it has computational analyses (Dowling, Fischlin, Günther and Stebila) and
  symbolic ones (Cremers et al., Tamarin). MAKA-E has fewer options than TLS: no 0-RTT, no
  negotiation, and one PSK per pair.
- **Evidence**:
  - AVISPA on `formal/avispa/maka_e.hlpsl` (4 sessions: two honest in parallel, the intruder as
    initiator and as responder with its own PSKs): OFMC 2006 and CL-AtSe 2.2-5/2.3-4 report SAFE
    for `authentication_on n_i`, `n_r`, each goal also checked alone. Every transition of both
    roles can execute (probes), so the SAFE is not vacuous. The no-PSK control is UNSAFE under
    every back-end.
  - In AVISPA's untyped model CL-AtSe attacks `n_r` by shifting a field boundary (the intruder
    appends fields to `X`; the initiator reads them as part of `N_R`). The implementation's
    length-prefixed, fixed-width fields reject both shifted messages
    (`tests/enhanced/test_ake.py::test_untyped_boundary_shift_*`).
  - OFMC 2024 on the AnB model: no attack at 1–3 sessions; the no-PSK control is attacked
    (`formal/avispa/README.md`).
  - Tests V-ADV-03/04/05/11/14 and Lab L2/L3/L4.

### P3. Session-key secrecy and forward secrecy

- **Mechanism**: the session keys are `k_IR`/`k_RI` from `HKDF(PSK‖Z, th, …)`, where `Z = x·Y = y·X`
  for ephemerals drawn fresh in every run.
  - The initiator destroys `x` when HS2 is processed.
  - The responder destroys `y` (and never stores `Z`) immediately after deriving the keys, and
    destroys `kc_I` once HS3 has been checked.
  - A superseded session's keys are destroyed.
- **Argument**:
  - *Secrecy*: an adversary without the PSK cannot complete a run (P2). One holding `x` or `y` of
    its own runs learns nothing about other runs.
  - *Forward secrecy*: an adversary that later learns `Pr_A` and every PSK still needs `Z` for
    recorded runs, which is a Gap-CDH instance (A2), and HKDF hides everything else (A3).
- **Analogue**: forward secrecy of TLS 1.3 `psk_dhe_ke` against later compromise of the PSK.
- **Evidence**:
  - AVISPA (OFMC 2006, CL-AtSe) finds no attack on `secrecy_of k_ir, k_ri` in the 4-session HLPSL
    model; OFMC 2024 none in the AnB model at 1–3 sessions.
  - Forward secrecy, symbolically (`anb/maka_e_ake_fs.AnB`, the PSK published after the session):
    no attack at 1 session. At 2 sessions OFMC 2024 reports an attack, and the trace does not show
    a forward-secrecy failure: the leaked keys belong to a responder session that the intruder
    itself opened (with `X = g`) and completed *after* the PSK leaked, i.e. impersonation after
    compromise, which no PSK protocol prevents. AnB cannot restrict the leak to "after every
    session has completed", so this model does not establish forward secrecy at 2 sessions either
    way. The no-DH control is attacked at 1 and 2 sessions, so the model does detect loss of
    keys from completed sessions when DH is absent.
  - V-ADV-12: with the PSKs and `Pr` taken after the session ended, the adversary module's key
    derivations fail and no ephemeral remains in the keystore.
  - Lab L5 enhanced: recorded data from ended sessions stays confidential.
- **Caveat**: Python cannot reliably wipe integers. "Destroyed" means the keystore's byte buffer is
  zeroed and every reference dropped; copies made during computation may remain in process memory
  (residual R-08).

### P4. Replay and freshness

- **Mechanism**:
  - Both sides contribute fresh 256-bit nonces and ephemerals.
  - A responder rejects an HS1 whose `sid` it has seen before.
  - HS2 and HS3 must match a pending `sid`.
  - Session messages carry a per-direction counter `seq`, accepted only if strictly increasing. The
    counter also forms the AEAD nonce `0^32 ‖ seq`, so a (key, nonce) pair is never reused (A4). The
    nonce is not transmitted; the receiver rebuilds it from `seq` (E-09, D6).
  - A sender never uses `seq ≥ 2^32` under one key: it refuses to send and the session is rekeyed
    (the initiator starts a handshake; a responder asks it to with `SESSION_UNKNOWN`) (E-09, D5).
  - On the CM→CH hop, `DATA_CM` carries its own counter `hop_seq`, covered by the hop MAC. The CH
    rejects a non-increasing `hop_seq` with `REPLAY_REJECTED` before batching (E-09, D1).
- **Evidence**: V-ADV-01/02/08/09; Lab L1. OFMC's strong (injective) authentication goal holds for
  MAKA-E. For RP9, by contrast, OFMC 2024 finds a cross-session replay at 2 sessions: without a
  receiver-side nonce record, replay succeeds; RP9's replay protection rests entirely on that
  record, which RP9 does not specify.

### P5. Authorisation: membership, designation, revocation (C4)

- **Mechanism**:
  - The BS answers a CH's member claim against its own registry (`CLUSTER_GRANT`). A CH answers
    `CM-CH` handshakes only from granted members.
  - A CM accepts a CH only if the BS designated it (`DESIGNATION`, sealed under the CM-BS session).
  - Revocation removes the identity from the registry and grants, destroys sessions and PSKs, and
    sends `REVOKE_NOTICE`/`ACK` over authenticated sessions.
- **Argument**: every authorisation decision is either the BS's own or relayed under an
  authenticated session with the BS (P2). A malicious CH cannot add members (L6) and cannot become
  a CM's CH without designation (V-ADV-15).
- **Limits**:
  - Exclusion is by authorisation lists, not cryptography: a revoked `Pr` is still mathematically
    valid (R-05).
  - A CH that misses a notice keeps the revoked member until its next grant refresh: after every
    CH–BS handshake and every `MAKA_GRANT_REFRESH_STEPS` steps over the sealed CH–BS session
    (R-06; V-LIFE-03 shows the window closing without a rekey).
  - The revoked device itself is not told, by design: nothing it could be told would bind it. When
    a CH is revoked, its members are not told either. They keep their sessions and PSK with it until
    the replacement CH relays a new `DESIGNATION`, and then destroy them. Readings sent in between
    are lost, and the console shows them as lost (E-09, D2, D7).
- **Evidence**: V-ADV-13/15, V-LIFE-01..04; Lab L6, L8.

### P6. Data confidentiality, integrity and attribution on the CM→CH→BS path

- **Mechanism**:
  - Readings are sealed end to end under the CM→BS session key. AD carries type, `sid`, parties
    and `seq`.
  - The CM→CH hop is authenticated by `HMAC(HKDF(k_CM→CH, "hop-mac"), LP(sid_CM-CH, hop_seq, inner))`.
  - The CH batches inner frames under the CH→BS session.
  - The BS checks that each sender is a granted member of the delivering CH, then opens it with
    that member's session.
- **Argument**:
  - The CH never holds a CM→BS key (V-POS-04), so it can drop or delay readings but cannot read or
    forge them.
  - The hop MAC lets the CH discard unauthenticated traffic cheaply.
- **Not provided**: in-network aggregation. RP9's undefined `Aggregate` is replaced by
  authenticated batching, not implemented (AM-05).

### P7. Limited denial-of-service resistance

- **Mechanism**: responder checks 1–5 (decode, recipient, purpose, authorisation, pending limits)
  run before any pairing or scalar multiplication. PSKs are cached per peer; there is one pending
  handshake per initiator and at most `MAX_PENDING` overall.
- **Evidence**:
  - V-DOS-01: 1,000 HS1 frames from unknown IDs cost 0 pairings and 0 scalar multiplications.
  - V-DOS-02: the pending limits hold.
  - Lab L7: RP9 pays one IBE decryption per bogus message.
- **Limit**: an authorised but malicious peer can still force about 3 scalar multiplications per
  HS1, rate-limited (R-07).

### P8. Composition and domain separation (§2.5 item 3)

| Separation | How |
|---|---|
| Original vs enhanced messages | Version byte (`0x01`/`0x02`) and disjoint message types. Original-mode bytes into an enhanced device give `DECODE_ERROR` (V-ADV-14) |
| Handshake purposes | `purpose` is in HS1, hence in `th`, and in HKDF `info`. A CM-BS HS2 spliced into a CM-CH exchange gives `BAD_TAG` (V-ADV-14) |
| PSK vs session keys vs hop key | Distinct HKDF salts and infos (`MAKA-E/v1/psk`, `MAKA-E/v1/keys`, `hop-mac`) |
| Directions | Separate keys `k_IR`, `k_RI`; AD names the sending and receiving party |
| Message kinds on one session | The type byte is in the AEAD AD, so a GRANT cannot be replayed as a DESIGNATION |
| Unauthenticated hints | `CLUSTER_OPEN` and `SESSION_UNKNOWN` are never trusted: they can only trigger a fresh authenticated handshake |

## What is not established

1. **No computational proof of MAKA-E as composed.** The argument above reasons by analogy with
   SOK and TLS 1.3 `psk_dhe_ke` under standard assumptions. Composing the SOK-derived PSK with the
   key exchange, the membership layer and the data path has not been proven.
2. **Symbolic analysis is bounded and abstract.** AVISPA (OFMC, CL-AtSe) checked the key exchange
   with the 4 sessions of `maka_e.hlpsl`, and OFMC 2024 the AnB model with up to 3, with perfect
   cryptography, the PSK as an opaque secret and DH as the only algebra. The membership,
   revocation and data layers are not modelled. Forward secrecy is not established symbolically
   beyond 1 session (P3). The tools are 2006-era builds run on a modern host
   (`formal/avispa/TOOLING.md` records how they were calibrated).
3. **Key-compromise impersonation (KCI).** With a symmetric PSK, whoever holds `Pr_A` can
   impersonate any peer *to A*. This is accepted and demonstrated (V-CAP-02).
4. **BS compromise is total.** The BS holds `k` and can derive every key.
5. **Implementation security.** The pure-Python arithmetic is not constant-time (D-02), memory
   wiping is best-effort (R-08), and the parameters are demonstration-grade (D-01).
6. **Testing is not proof.** The adversarial tests and Lab scenarios exercise the modelled attacker
   capabilities (§2.1). Attacks outside that model are not excluded.
