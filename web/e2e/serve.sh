#!/usr/bin/env bash
# Starts a throwaway backend (fresh DB, MAKA_ENV=test) serving the built UI for Playwright.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
WORK="$(mktemp -d)"
export MAKA_ENV=test MAKA_DB_URL="sqlite:///$WORK/e2e.db" MAKA_BIND="127.0.0.1:${E2E_PORT:-8765}"
export MAKA_STATIC_DIR="$ROOT/web/dist" PYTHONPATH="$ROOT/src"
for u in admin operator viewer; do
  echo "e2e-${u}-password" | "$PY" -m maka_server create-user --username "e2e-$u" --role "$u" --password-stdin
done
exec "$PY" -m maka_server serve
