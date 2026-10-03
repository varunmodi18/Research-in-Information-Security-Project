"""Writes docs/openapi.json from the FastAPI app (input to `npm run gen:api:file` and docs/API.md)."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from maka_server.main import create_app
from maka_server.settings import Settings


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(Settings(env="test", db_url=f"sqlite:///{tmp}/openapi.db"))
        spec = app.openapi()
    out = REPO_ROOT / "docs" / "openapi.json"
    out.write_text(json.dumps(spec, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    sys.stdout.write(f"wrote {out} ({len(spec['paths'])} paths)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
