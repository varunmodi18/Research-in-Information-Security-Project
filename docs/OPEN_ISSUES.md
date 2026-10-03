# Open issues

Findings, missed thresholds and acceptance steps that could not be completed, each with its
evidence (IMPLEMENTATION_PLAN.md §5 rules, §6.6, §7.3). Newest at the bottom of each section.

## Awaiting project-owner approval (§7.3 item 1)

The definition of done accepts an unmet **M**-priority criterion only with a documented,
evidence-backed reason **approved by the project owner**. OI-01 (Docker) and OI-02 (HLPSL/CL-AtSe)
below are documented with evidence. They have **not yet been approved**: approval is the owner's
decision, not the implementer's.

## Acceptance steps not run

### OI-01 · Docker acceptance (M3-T7, M5-T7, M8-T4) not executed on this host

- **What the plan asks:** `docker compose up` on a clean machine, then `create-admin`, reaches the
  dashboard; E2E journeys run against the Docker build.
- **What happened:** Docker is not installed on the development host (`which docker` finds
  nothing; see `docs/PLAN_ERRATA.md` E-03). `deploy/Dockerfile`, `deploy/docker-compose.yml`
  and `deploy/.env.example` are written but have not been built.
- **What was run instead:** the same image layout without Docker. `web/e2e/serve.sh` starts
  the backend (`python -m maka_server serve`) serving the production build of the UI
  (`web/dist`) on one port, exactly as the container does, and the Playwright journeys run
  against it (`make e2e`).
- **To close:** on a machine with Docker 24+, run the commands in `docs/OPERATIONS.md`
  ("First start with Docker") and `cd web && E2E_BASE=... npx playwright test` against the container.
- **Also unverified for the same reason:** the change that installs the package in place
  (`pip install -e`) and copies `artifacts/eval` and `docs/baseline` into the image, so that the
  Evaluation page finds the committed comparison and the RP9 reference data inside the container.

### OI-02 · Formal analysis: HLPSL models and CL-AtSe results not obtained (M7-T1..T3)

- **What the plan asks:** OFMC and CL-AtSe results for the RP9 transcription, the fixed RP9 model and
  MAKA-E, all as HLPSL (V-FORMAL-01..03).
- **What happened:** the AVISPA `hlpsl2if` translator and CL-AtSe could not be obtained for this host
  (`formal/avispa/NOT_RUN.md` lists the attempts). OFMC 2024 runs, but only on AnB models.
- **What was run instead:** the HLPSL files are committed and pass a structural lint
  (`formal/avispa/syntax_check.py`). The protocols were re-modelled in AnB and checked with OFMC:
  - MAKA-E: no attack at 1–3 sessions; the no-PSK negative control is attacked.
  - RP9: attacked, by an insider at 1 session, and by a cross-session replay with outsiders only at
    2 sessions.

  Results are in `formal/avispa/results/` and on the Evaluation page. Everywhere else the HLPSL and
  CL-AtSe results are marked "not obtained".
- **To close:** on a machine with the AVISPA package, run `formal/avispa/run_all.sh`. It runs the
  HLPSL models when `hlpsl2if` is on `PATH`.

## M7 evaluation checkpoint (M7-T7)

All §6 metrics were produced on 2026-10-04 (`artifacts/eval/`). **No threshold was missed.**

| Check | Result | Threshold | Evidence |
|---|---|---|---|
| V-PERF-01 primitive timings vs M0-T4 baseline | no primitive more than 6.2 % slower (worst: `demo` Weil pairing, 1.062×) | report > 20 % | `primitives_2026-10-04.md` |
| V-PERF-02 NFR-PERF-01 enhanced onboarding `net`/`demo` | 9.25 s median of 5 | ≤ min(60, 1.5 × 17.49) = 26.2 s | `compare_2026-10-04.md` |
| V-PERF-03 pairings per CM during onboarding | 2 | ≤ 2 | same |
| V-PERF-03 per-reading CM public-key operations | 0 | 0 | same |
| V-PERF-03 per-reading CM AEAD + MAC | 2 | ≤ 2 | same |
| V-PERF-03 bytes per reading on the CM→CH hop, minus payload | 116 | ≤ 120 | same |
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
