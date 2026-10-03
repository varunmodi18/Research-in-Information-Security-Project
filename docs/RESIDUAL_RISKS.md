# Residual risks

These risks remain after the MAKA-E changes (IMPLEMENTATION_PLAN.md §2.3, §2.4, M7-T4). Each one
is accepted, documented and, where possible, demonstrated. "Evidence" points to the test or Lab
scenario that shows the behaviour.

| ID | Risk | Effect | Why it is accepted | Evidence |
|---|---|---|---|---|
| R-01 | **Key-compromise impersonation (KCI)** | Whoever holds a device's `Pr_A` (and so its PSKs) can impersonate *any* peer to that device | Inherent to a symmetric PSK. Removing it needs signatures or an asymmetric binding of each party's long-term key, which is out of scope | V-CAP-02; `docs/SECURITY_ARGUMENT.md` §"not established" 3 |
| R-02 | **No device anonymity (P-11)** | Identities appear in clear in HS1/HS2 and in frame metadata; traffic is linkable | Out of scope (§2.3). RP9's anonymity claim (Table 6 F5) is not supported even for RP9 | — |
| R-03 | **Demonstration-grade parameters (D-01)** | `demo` gives about 60-bit and `secure` about 80-bit security (embedding degree 2) | Pure-Python pairings at deployment sizes would be impractically slow; no deployment claim is made | Parameter label on every network page (V-DOC-02) |
| R-04 | **Non-constant-time arithmetic (D-02)** | Timing side channels on scalar multiplication and pairings | Side channels are out of scope (§2.1 assumption 5) | — |
| R-05 | **A revoked identity's key stays valid** | A revoked device's `Pr` still computes correct PSKs; exclusion relies on the BS registry and the CH grants | Cryptographic revocation would need epoch-bound identities `H(ID‖epoch)` and re-provisioning (a later enhancement, §3.5) | L8, V-LIFE-01 |
| R-06 | **Stale revocation window** | A CH that misses a `REVOKE_NOTICE` keeps accepting the revoked member until its next grant refresh (every CH–BS rekey) | The BS still rejects the member's end-to-end traffic; the window is bounded by the rekey policy | V-LIFE-03 (window shown closing) |
| R-07 | **DoS by an authorised insider** | An authorised device can force about 3 scalar multiplications per HS1 at a responder | Bounded by one pending handshake per peer and `MAX_PENDING`; unknown identities cost no public-key work | V-DOS-02, L7 |
| R-08 | **Best-effort memory wiping (I-09)** | Python `int` and `bytes` copies of secrets may stay in process memory after "destruction" | The language gives no reliable wipe; keystore buffers are zeroed and references dropped | `tests/runtime/test_runtime_core.py::test_keystore_destroy_zeroes_the_original_buffer` |
| R-09 | **BS / provisioning authority compromise** | Total: the BS holds `k` and can derive every key | The BS is trusted by assumption (§2.1 assumption 1) | — |
| R-10 | **Secrets at rest under one environment KEK (D-05)** | Whoever reads `.env` and the database can decrypt the long-term keys | Local demo deployment; session keys and ephemerals are never persisted | V-LEAK-04; `docs/OPERATIONS.md` (KEK handling) |
| R-11 | **Console exposure (D-04)** | The console has no TLS, is single-host, and binds to localhost by default | Internet-facing deployment is excluded (§3.5) | V-WEB-01..08 |
| R-12 | **The CH sees metadata and can drop data** | A cluster head learns which member sends when and how much, and can delay or drop readings (it cannot read or forge them) | Inherent to relaying; batching hides payloads, not traffic patterns | V-POS-04 |
| R-13 | **Unauthenticated hints** | Forged `CLUSTER_OPEN` / `SESSION_UNKNOWN` messages make a device start an extra handshake | Each costs at most one rate-limited, authenticated handshake; nothing is trusted from them (`docs/PLAN_ERRATA.md` E-05) | V-ADV-07 |
| R-14 | **Simulation only (D-03)** | No radio loss model, timing realism or energy measurement; one frame is delivered per scheduler step | The product demonstrates protocol behaviour, not field performance; IoT cost figures are labelled estimates | §6.7 limitations on the Evaluation page |
| R-15 | **Seeded mode repeats randomness across runs** | Lab and test networks with a seed reproduce keys and nonces across runs | Required for reproducibility (NFR-REL-02); product networks use OS randomness | OB-08; `docs/PLAN_ERRATA.md` E-01 |
