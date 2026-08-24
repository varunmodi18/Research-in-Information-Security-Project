"""P0.5: every subcommand's --help must parse without error."""

from __future__ import annotations

import pytest

from maka.cli import build_parser

SUBCOMMANDS = ["primitives", "run", "icmds", "security", "formal", "eval", "all"]


@pytest.mark.parametrize("command", SUBCOMMANDS)
def test_subcommand_help(command: str, capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert command in out or "usage" in out
