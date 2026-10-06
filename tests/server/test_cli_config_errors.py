"""F7 (follow-up): a missing or malformed MAKA_KEK ends `python -m maka_server serve` with one clear
line on stderr and a non-zero exit, not a traceback."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"


def _serve(tmp_path: Path, kek: str | None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("MAKA_")}
    env.update(MAKA_ENV="dev", MAKA_DB_URL=f"sqlite:///{tmp_path / 'cli.db'}", MAKA_BIND="127.0.0.1:0",
               PYTHONPATH=str(SRC))
    if kek is not None:
        env["MAKA_KEK"] = kek
    return subprocess.run([sys.executable, "-m", "maka_server", "serve"], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=60, check=False)


@pytest.mark.parametrize(("kek", "expected"), [
    (None, "maka_server: MAKA_KEK is required (32 random bytes, base64) unless MAKA_ENV=test"),
    ("bm90LWJhc2U2NCE=", "maka_server: invalid configuration: MAKA_KEK: Value error, MAKA_KEK must decode to 32 bytes"),
    ("not base64 at all", "maka_server: invalid configuration: MAKA_KEK: Value error, MAKA_KEK must be base64"),
])
def test_f7_bad_kek_gives_one_line_and_nonzero_exit(tmp_path: Path, kek: str | None, expected: str) -> None:
    r = _serve(tmp_path, kek)
    assert r.returncode == 2
    assert r.stderr.splitlines() == [expected]
    assert "Traceback" not in r.stderr and r.stdout == ""
