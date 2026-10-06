# Operations

How to install, configure, run, back up and reset the MAKA console. It is a single-host demonstration
system: it binds to loopback by default, has no TLS, and is not meant for internet-facing deployment
(IMPLEMENTATION_PLAN.md §3.5; `docs/RESIDUAL_RISKS.md` R-11).

## Requirements

- **Python 3.12** and **Node 22** (Node 20 also works).
- Docker is not supported: it was dropped by owner decision (`docs/PLAN_ERRATA.md` E-07).
- 4 GB RAM.
- No network access at runtime. The UI loads nothing from the internet (CSP `default-src 'self'`).

## First start

```
python3 -m venv .venv && .venv/bin/pip install -e ".[dev,server]"    # or: make setup
make web web-build                                                    # npm ci, then build web/dist
cp .env.example .env                                                  # then set MAKA_KEK in .env:
python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
PYTHONPATH=src .venv/bin/python -m maka_server create-admin --username admin
PYTHONPATH=src .venv/bin/python -m maka_server seed-demo             # optional demo state
make serve                                                            # http://127.0.0.1:8000
```

The database is `var/maka.db` (`MAKA_DB_URL`). For development, `make dev` runs the backend with
auto-reload on :8000 and Vite on :5173. The E2E suite starts its own throwaway backend with
`web/e2e/serve.sh` (fresh database, `MAKA_ENV=test`) serving the built UI.

## Configuration

All settings are environment variables prefixed `MAKA_`. They can also be set in `.env` in the working
directory (`src/maka_server/settings.py`).

| Variable | Default | Meaning |
|---|---|---|
| `MAKA_ENV` | `dev` | `dev`: seeded product networks allowed. `test`: ephemeral KEK allowed. `demo`: strict, no secret disclosure, no seeded product networks |
| `MAKA_KEK` | — (required unless `test`) | Key-encryption key for keystores at rest: 32 random bytes, base64 |
| `MAKA_DB_URL` | `sqlite:///./var/maka.db` | SQLite database (WAL mode) |
| `MAKA_BIND` | `127.0.0.1:8000` | Listen address |
| `MAKA_STATIC_DIR` | `web/dist` | Built UI |
| `MAKA_PARAMS_DEFAULT` | `demo` | Default parameter set for new networks |
| `MAKA_T_HS`, `MAKA_T_RETRY`, `MAKA_MAX_PENDING`, `MAKA_BATCH_STEPS`, `MAKA_BATCH_MAX` | 20, 5, 16, 5, 8 | MAKA-E tunables (in scheduler steps; see `docs/PLAN_ERRATA.md` E-05 item 5 for the effective handshake timeout) |
| `MAKA_GRANT_REFRESH_STEPS` | 50 | How often (in steps) a CH re-requests its `CLUSTER_GRANT` over the sealed CH–BS session. Bounds how long a CH that missed a `REVOKE_NOTICE` keeps a revoked member (`docs/PLAN_ERRATA.md` E-09). The timer runs only while the network is stepped |
| `MAKA_SESSION_IDLE_HOURS` | 8 | Console session idle expiry |
| `MAKA_LOGIN_MAX_FAILURES`, `MAKA_LOGIN_WINDOW_S`, `MAKA_LOGIN_LOCK_S` | 5, 900, 900 | Login lockout |
| `MAKA_PERSIST_EVERY_STEPS` | 10 | How often a running network is flushed to the database |
| `MAKA_DEMO_PASSWORDS_FILE` | — | For `seed-demo`: lines `admin=…`, `operator=…`, `viewer=…` |
| `MAKA_COOKIE_SECURE` | auto | `Secure` cookie flag; off only when bound to loopback |

## The key-encryption key (KEK)

- Device long-term keys (`Pr_i`, PSK caches) are stored AES-256-GCM-encrypted under `MAKA_KEK`. The
  associated data binds each entry to its network, device and name.
- Session keys, ephemerals and handshake state are **never** persisted. After a restart, devices
  re-establish sessions.
- Generate the KEK with the command above and keep it outside the repository. `.env` is git-ignored.
- Without a valid KEK (unless `MAKA_ENV=test`), `python -m maka_server serve` stops at once with one
  line on stderr and exit status 2. The line is either
  `maka_server: MAKA_KEK is required (32 random bytes, base64) unless MAKA_ENV=test` or
  `maka_server: invalid configuration: MAKA_KEK: …`.
- Whoever has both `.env` and the database can decrypt the stored keys (residual risk R-10).
- **Losing or changing the KEK** makes existing keystores unreadable. The affected networks cannot be
  rebuilt; recover with `python -m maka_server reset-demo` (demo state), or delete and recreate the
  networks.

## Users

```
python -m maka_server create-admin --username admin                     # password prompted (min 12 characters)
python -m maka_server create-user --username alice --role operator      # admin, operator or viewer
echo "$PW" | python -m maka_server create-user --username bob --role viewer --password-stdin
```

Admins can also add users, change roles and disable accounts in the console (**Admin**).
Passwords are stored as Argon2id hashes, and no default users exist.

## Demo state, backup and reset

| Task | Command |
|---|---|
| Create the demo users and networks | `python -m maka_server seed-demo` (or `make demo-seed`) |
| Restore the demo networks | Admin → **Reset demo…**, or `python -m maka_server reset-demo` (`make demo-reset`) |
| Back up | Stop the console, then copy `var/maka.db` (with `-wal`/`-shm` if present) **and** `.env` |
| Restore | Stop the console, put both files back, start it |

- **What a reset does**:
  - *Removes*: every network, device, keystore, session, frame, security event, reading, network job
    and evaluation run.
  - *Recreates*: "Vineyard" (`net`, MAKA-E, `demo`) and "Lab-Paper" (`paper`, `toy`, seed 20260927).
  - *Keeps*: users and the audit log.
- **Jobs running**: a reset refuses with `NETWORK_BUSY`; wait or cancel the job first.
- **Console running**: if you use the command-line reset while the console is running, restart the
  console afterwards so it drops its in-memory runtimes. The Admin page reset does not need this.

## Logs and monitoring

| Log | Where | Contents |
|---|---|---|
| Server log | uvicorn on stdout/stderr | Requests and errors. Never secrets |
| Audit log | `audit_log` table; **Admin → Audit** | Every state-changing request: user, action, target, outcome |
| Security events | `security_events` table; **Security events** page; `GET /api/events/export` | Protocol events (`HANDSHAKE_OK`, `BAD_TAG`, `REPLAY_REJECTED`, ...) |
| Health | `GET /api/health` | For monitoring scripts |

## Recovery after a crash or restart

At startup, any job still marked `running` is marked `aborted`. Its network is then rebuilt from the
database and the keystores (§4.8): devices are restored with their long-term keys, while sessions,
which were never persisted, are gone. Run **Onboard** again to re-establish them (V-REC-01).

## Upgrades

`python -m maka_server migrate` (also run automatically at startup) applies Alembic migrations. Back up
first.
