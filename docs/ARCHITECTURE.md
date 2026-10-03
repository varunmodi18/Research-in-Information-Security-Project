# Architecture

This repository holds two systems that share one cryptographic core:

1. **The RP9 reproduction** (`src/maka`, `src/icmds`, `attacks/`, `security/`, `formal/`, `eval/`).
   It is driven by `python -m maka.cli`, and every claim and table in RP9 (Harbi et al., 2019) can be
   traced through it. See `README.md` and `docs/REGISTER.md`.
2. **The MAKA console** (`src/maka/runtime`, `src/maka/original_rt`, `src/maka/enhanced`,
   `src/maka/lab`, `src/maka_server`, `web/`). It is a web application that runs simulated sensor
   networks under **MAKA-E**, the enhanced protocol, and offers a Lab where MAKA-E is compared with RP9
   as published.

```
            browser (React + TypeScript)
                │  HTTP + SSE  (/api, cookie session, CSRF header)
┌───────────────▼───────────────────────────────────────────────┐
│ maka_server  (FastAPI)                                         │
│  routers ─ services ─ JobManager (one worker thread / network) │
│  RuntimeRegistry ─ EncryptedKeystoreAdapter ─ SSE Broker       │
│  SQLAlchemy 2 + Alembic ─ SQLite (WAL)                         │
└───────────────┬───────────────────────────────────────────────┘
                │  in-process
┌───────────────▼───────────────────────────────────────────────┐
│ maka.runtime: Scheduler ─ Bus(interceptors) ─ Device ─ Keystore │
│   ├─ maka.original_rt  RP9 §5 as state machines (lab only)      │
│   ├─ maka.enhanced     MAKA-E v1 (product and lab)              │
│   └─ maka.lab          adversary + scenarios L1–L8 (lab only)   │
│ maka core: field, curve, pairing, hashing, ibe, aead, kdf,      │
│            codec, ledger, trace, rng                            │
└────────────────────────────────────────────────────────────────┘
```

## Cryptographic core (`src/maka`)

| Module | Role |
|---|---|
| `field`, `curve`, `pairing`, `params` | Type-1 supersingular curve, with the Weil pairing through a distortion map. Parameter sets `toy` (insecure), `demo` (~60-bit) and `secure` (~80-bit) (IA-02, IA-07) |
| `hashing` | `H` (hash-to-point) and the hash-to-scalar constructions (IA-09) |
| `ibe` | Boneh–Franklin IBE hybrid, standing in for RP9's abstract Enc/Dec (IA-03). Used by original mode only |
| `aead` | AES-256-GCM with explicit associated data and counter nonces |
| `kdf` | HKDF-SHA256 / HMAC-SHA256 with labelled, length-prefixed inputs (MAKA-E) |
| `codec` | Versioned, length-prefixed wire encoding. Every decoded point is validated, and the subgroup check is counted as `T_SM_val` (IA-12) |
| `ledger` | Counts operations per entity and phase (`T_HG`, `T_SM`, `T_P`, `T_E/D`, `T_HKDF`, `T_MAC`, ...). These counts feed RP9 Tables 2–5 and the comparison |
| `trace` | Annotated transcripts. Secret values are recorded only as `«secret:name»` |
| `rng` | Context-local randomness: seeded for reproducible lab runs, OS randomness for product networks |

## Device runtime (`src/maka/runtime`)

Protocols run as message-driven state machines over **bytes**. No Python objects cross between
devices.

- **`Frame`**: frozen `(src, dst, label, payload bytes, injected flag)`.
- **`Bus`**: delivers frames through an ordered interceptor chain (record, drop, inject, modify). The
  product bus refuses adversary interceptors (`ModeNotAllowed`).
- **`Scheduler`**: delivers one frame per step and fires timers. Step hooks let the server publish
  progress and persist state. Because the scheduler is deterministic, the same seed and inputs give
  the same frame log (NFR-REL-02).
- **`Device`**: decodes, runs its checks, and emits events and check results. The checks are what the
  Timeline shows.
- **`Keystore`**: named byte buffers that are zeroed on destruction. Python cannot guarantee wiping
  (R-08).

Rng, ledger and tracer are context-local (`using(...)` context managers). Several networks can
therefore run in different server threads without sharing randomness or counters.

### Original mode (`src/maka/original_rt`)

RP9 §5.1–§5.5 re-expressed as state machines on the runtime, with the M1 defect fixes (decode,
then verify). It is reachable only on lab networks (V-WEB-06).

### MAKA-E v1 (`src/maka/enhanced`)

Specified in IMPLEMENTATION_PLAN.md §4.6, with the clarifications in `docs/PLAN_ERRATA.md` E-05, and
argued in `docs/SECURITY_ARGUMENT.md`.

| Module | Contents |
|---|---|
| `provisioning` | The BS (only it holds `k`) issues `Pr_i = k·H(ID_i)`. Devices never receive `k` (C1) |
| `ake` | SOK pre-shared key `PSK_AB = HKDF(ê(Pr_A, H(ID_B)))` (C2), and a 3-message PSK + ephemeral-DH handshake HS1/HS2/HS3 with `tag_R`/`tag_I` over the transcript hash, giving direction-separated session keys (C3) |
| `membership` | `CLUSTER_CLAIM`/`CLUSTER_GRANT`, `CLUSTER_OPEN`, CM–BS handshakes relayed by the CH, `DESIGNATION`, and CM–CH handshakes (C4) |
| `data` | Readings sealed end to end under the CM→BS key, a hop MAC on CM→CH, and CH batching to the BS |
| `lifecycle` | Rekey and supersession, `REVOKE_NOTICE`/`ACK`, reprovisioning, CH designation |
| `network` | `build`/`restore` and the tunables |

### Lab (`src/maka/lab`)

`attacker.py` is the adversary: interceptors plus capabilities such as capturing a keystore and
forging with known material. `scenarios.py` defines L1–L8. Each runs on a fresh network per mode and
judges the outcome only from what actually happened (frames, events, keystore contents), never from a
prediction. Evidence is persisted under a run tag.

## Server (`src/maka_server`)

| Component | Responsibility |
|---|---|
| `main.create_app` | App factory: migrations, middleware, routers, SPA mount |
| `settings` | `MAKA_*` environment configuration (`docs/OPERATIONS.md`) |
| `security`, `deps` | Argon2id passwords; server-side hashed session tokens in an `HttpOnly` cookie; CSRF header; login lockout; role dependencies `viewer < operator < admin` |
| `errors` | RFC 9457 problem details with a stable `code` |
| middleware | Security headers (CSP `default-src 'self'`, no framing) and an audit record of every state-changing request |
| `jobs.JobManager` | Asynchronous jobs: one worker thread and queue per network, idempotency keys, cancellation between steps, the periodic-reading ticker, and `aborted` on restart |
| `services/runtime.RuntimeRegistry` | Live `NetworkRuntime`s. Each one flushes frames, events, readings, sessions, device status and keystores to the DB every N steps and at the end of each job |
| `keystore_store.EncryptedKeystoreAdapter` | Long-term device keys at rest, encrypted with AES-GCM under `MAKA_KEK`, with AD = `LP(network, device, name)`. Ephemerals, handshake state and session keys are never persisted |
| `sse.Broker` | Per-network event stream with a replay buffer for `Last-Event-ID` |
| `services/*` | Job handlers: onboard, step, readings, lifecycle, lab scenarios, evaluation, demo reset |
| `services/jobrules` | Which job types are allowed on which network kind |
| `migrations/` | Alembic: `0001` initial schema, `0002` adds `run_tag` |

**Data model**:

| Table | Holds |
|---|---|
| `users`, `auth_sessions` | Console accounts and their sessions |
| `networks` → `devices` → `keystore_entries` | Topology and encrypted long-term keys |
| `sessions` | Protocol session *metadata*: peer, purpose, state, public session id, counters |
| `frames`, `security_events`, `readings` | The protocol record (payloads only for lab networks) |
| `jobs`, `evaluation_runs` | Job state and evaluation results |
| `audit_log` | Every state-changing request |

**Recovery (§4.8).** Live protocol state is never persisted. After a crash or a failed job, the
network is rebuilt from the database and the keystores: devices return with their long-term keys,
sessions are re-established by onboarding again, and jobs found running are marked `aborted`.

**Secrets boundary (§4.4).** No SECRET-class value leaves the keystore or the runtime through the
API, UI, SSE, logs, database plaintext or exports. The leakage tests (V-LEAK-01..04) scan all of
these.

## Web UI (`web/`)

Vite + React 18 + TypeScript + Tailwind, with TanStack Query for server state and React Router.

- **Types**: API types are generated from `docs/openapi.json` (`openapi-typescript`).
- **Pages**: Dashboard, New network, Topology (`@xyflow/react`), Device, Timeline, Frames, Readings,
  Security events, Lab, Evaluation (Recharts) and Admin.
- **Live updates**: pages subscribe to `/api/networks/{id}/stream`.
- **Serving**: the production build is served by the backend from `web/dist`.
- **Tests**: Playwright E2E runs against `web/e2e/serve.sh` (a fresh backend serving the build).
  Journeys J1–J5 and the demo script are in `web/e2e/`.

## Evaluation and formal tooling

- `eval/bench/compare.py` builds fresh runtimes for RP9 (two variants) and MAKA-E and measures them,
  then renders `artifacts/eval/`.
- `eval/bench/primitives.py`, `api_latency.py`: V-PERF-01 and V-PERF-04.
- `formal/avispa/`: the HLPSL transcriptions (lint only) and the AnB models checked with OFMC
  (`results/SUMMARY.json`). The Evaluation page reads both, through `services/evaluation.reference()`.

## Testing layers

| Layer | Location |
|---|---|
| Unit and vector tests | `tests/`, `tests/vectors/maka_e_v1.json` |
| Runtime and protocol | `tests/runtime`, `tests/enhanced` |
| Adversarial and Lab | `tests/lab`, and the V-ADV-* cases in `tests/enhanced` |
| Server and API | `tests/server` |
| Benchmarks | `tests/bench` |
| Documentation honesty | `tests/test_docs.py` |
| Register entries | `tests/register` |
| E2E | `web/e2e` |

`make ci` runs ruff, `mypy --strict` on the typed packages, and the fast tests. `make ci-slow` and
`make e2e` run at checkpoints.
