# Open issues

Findings, missed thresholds and acceptance steps that could not be completed, each with its
evidence (IMPLEMENTATION_PLAN.md §5 rules, §6.6, §7.3). Newest at the bottom of each section.

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
  ("Docker") and `cd web && E2E_BASE=... npx playwright test` against the container.
