# Open issues

Findings, missed thresholds and acceptance steps that could not be completed, each with its
evidence (IMPLEMENTATION_PLAN.md §5 rules, §6.6, §7.3). Newest at the bottom of each section.

## Owner decisions (2026-10-06)

- **OI-01 (Docker): closed, out of scope by owner decision.** Docker is dropped from the project;
  E2E against `web/e2e/serve.sh` is the accepted acceptance path (`docs/PLAN_ERRATA.md` E-07).
- **OI-02 (formal): not accepted as it stood.** The owner required real AVISPA runs on the HLPSL
  files (OFMC and CL-AtSe back-ends) in addition to the OFMC 2024 runs on the AnB models. Done in
  follow-up Part C; OI-02 is closed below.

## Closed

### OI-02 · Formal analysis with the AVISPA tools (M7-T1..T3, V-FORMAL-01..03): closed 2026-10-06

- **What the plan asks:** OFMC and CL-AtSe results for the RP9 transcription, the fixed RP9 model and
  MAKA-E, all as HLPSL.
- **What happened in M7:** the AVISPA tools could not be obtained. The HLPSL files had only a lint,
  and the protocols were checked as AnB models with OFMC 2024.
- **Resolution (follow-up Part C):**
  - The AVISPA tools were obtained without root, from the SPAN 1.6 packages, and calibrated on
    SPAN's own test suite (`formal/avispa/TOOLING.md`).
  - Every HLPSL model was run through OFMC (version of 2006/02/13), CL-AtSe 2.2-5 and CL-AtSe
    2.3-4, with all goals together and one goal at a time, plus per-transition executability probes.
    MAKA-E was also run untyped. The raw outputs are in `formal/avispa/results/avispa/`.
  - Results and what they do and do not show: `formal/avispa/README.md`, the Evaluation page (two
    separate tables) and `docs/SECURITY_ARGUMENT.md`.
  - Register OB-09 (corrected) and OB-11/OB-12 (new); errata E-08.
- **Recorded, not hidden:**
  - Runs that hit the 30-minute limit are recorded as TIMEOUT, and CL-AtSe crashes as ERROR, with
    their raw output.
  - CL-AtSe's untyped attack on MAKA-E's `n_r` is a field-boundary ambiguity. The implementation
    excludes it, and a test shows this.
  - Forward secrecy (OFMC 2024, AnB): no attack at 1 session; the 2-session trace is impersonation after long-term key compromise, which the AnB language cannot exclude, so forward secrecy is not established symbolically beyond 1 session.

### OI-01 · Docker acceptance (M3-T7, M5-T7, M8-T4): closed by owner decision

- **What the plan asked:** `docker compose up` on a clean machine, then `create-admin`, reaches the
  dashboard; E2E journeys run against the Docker build.
- **What happened:** Docker was never installed on the development host, so the Docker files written
  in M3/M8 were never built.
- **Resolution (2026-10-06):** the owner dropped Docker from the project. `deploy/Dockerfile`,
  `deploy/docker-compose.yml` and `.dockerignore` were deleted; `.env.example` moved to the
  repository root. The supported way to run is `make dev` / `make serve`, and the accepted
  acceptance path is the Playwright suite against `web/e2e/serve.sh` (E-07).

## Acceptance steps not run

None open. OI-02 is closed below.

## M7 evaluation checkpoint (M7-T7)

All §6 metrics were produced on 2026-10-04 (`artifacts/eval/`). **No threshold was missed.**

| Check | Result | Threshold | Evidence |
|---|---|---|---|
| V-PERF-01 primitive timings vs M0-T4 baseline | no primitive more than 6.2 % slower (worst: `demo` Weil pairing, 1.062×) | report > 20 % | `primitives_2026-10-04.md` |
| V-PERF-02 NFR-PERF-01 enhanced onboarding `net`/`demo` | 9.25 s median of 5 | ≤ min(60, 1.5 × 17.49) = 26.2 s | `compare_2026-10-04.md` |
| V-PERF-03 pairings per CM during onboarding | 2 | ≤ 2 | same |
| V-PERF-03 per-reading CM public-key operations | 0 | 0 | same |
| V-PERF-03 per-reading CM AEAD + MAC | 2 | ≤ 2 | same |
| V-PERF-03 bytes per reading on the CM→CH hop, minus payload | 116 (114 after the follow-up's D1/D6, E-09) | ≤ 120 | same; `tests/enhanced/test_data.py::test_per_reading_cost_and_size` |
| V-PERF-04 API p95 with `net` (`demo`) loaded | 7.99 ms (200 requests) | ≤ 200 ms | `api_latency_2026-10-04.md` |
| Lab L1–L8 outcomes | all 16 as predicted in §3.6 | — | `compare_2026-10-04.md` |

Findings that are not threshold failures:

1. **MAKA-E costs the BS more than RP9 does.** Estimated BS onboarding cost is 94 ms per device for
   MAKA-E against 45–61 ms for RP9 (RP9 Table 5 constants), because the BS runs a handshake with
   every device and issues grants and designations.
   - Per CH, MAKA-E is below both RP9 variants: 49.9 ms against 55.9 and 65.8.
   - Per CM it lies between them: 49.9 ms against 46.0 for RP9 as priced in Table 2, and 52.1 for
     RP9 with encrypted pseudo-identities.
2. **RP9 as published does not price its own secure variant.** Encrypting pseudo-identities (the
   only reading under which §5.3 is confidential) adds 6–16 ms per device over RP9's Table 2 pricing
   (OB-07).
3. **Host wall time favours MAKA-E**: 9.25 s against 13.41–17.55 s for RP9 on `net`/`demo`, because
   RP9's IBE decryptions each cost a pairing. This is a host measurement of pure-Python code, not a
   sensor-node prediction.
