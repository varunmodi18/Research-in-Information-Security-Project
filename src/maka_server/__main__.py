"""python -m maka_server <command> (IMPLEMENTATION_PLAN.md §4.9, §7.2).

    migrate                      upgrade the database to the latest schema
    create-admin --username U    create the initial Admin (password prompted, min 12 chars)
    create-user --username U --role R [--password-stdin]
                                 create a console user; --password-stdin reads one line (scripts, E2E)
    seed-demo                    create users admin/operator/viewer (passwords prompted, or read
                                 from MAKA_DEMO_PASSWORDS_FILE: one `username=password` per line)
                                 and reset the demo networks "Vineyard" and "Lab-Paper"
    reset-demo                   restore the demo networks only (users and audit log are kept)
    serve                        run the API + built UI with uvicorn on MAKA_BIND
"""

from __future__ import annotations

import argparse
import getpass
import re
import sys
from pathlib import Path


def _create_user(username: str, role: str, password_stdin: bool) -> int:
    from maka_server.context import build_context
    from maka_server.errors import ApiError
    from maka_server.migrate import upgrade
    from maka_server.services.users import create_user
    from maka_server.settings import get_settings

    settings = get_settings()
    upgrade(settings.db_url)
    if password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass(f"Password for {username} (min 12 characters): ")
        if password != getpass.getpass("Repeat password: "):
            sys.stderr.write("passwords do not match\n")
            return 2
    try:
        create_user(build_context(settings), username, password, role)
    except ApiError as exc:
        sys.stderr.write(f"{exc.title}: {exc.detail}\n")
        return 2
    sys.stdout.write(f"{role} user {username!r} created\n")
    return 0


def _demo_passwords(path: Path | None, missing: list[str]) -> dict[str, str]:
    """From MAKA_DEMO_PASSWORDS_FILE (`username=password` or `username:password` per line, split at
    the first separator, surrounding spaces ignored), else prompted."""
    if path is not None:
        found = (re.match(r"\s*([A-Za-z0-9_.-]+)\s*[=:](.*)$", line) for line in path.read_text().splitlines())
        return {m.group(1): m.group(2).strip() for m in found if m}
    out = {}
    for name in missing:
        pw = getpass.getpass(f"Password for demo user {name} (min 12 characters): ")
        if pw != getpass.getpass("Repeat password: "):
            raise ValueError("passwords do not match")
        out[name] = pw
    return out


def _demo(reset_only: bool) -> int:
    from sqlalchemy import select

    from maka_server import models
    from maka_server.context import build_context
    from maka_server.errors import ApiError
    from maka_server.migrate import upgrade
    from maka_server.services import demo
    from maka_server.services.networks import register_builders
    from maka_server.settings import get_settings

    settings = get_settings()
    upgrade(settings.db_url)
    ctx = build_context(settings)
    register_builders(ctx)
    try:
        if reset_only:
            result: dict[str, object] = {"networks": demo.reset_networks(ctx)}
        else:
            with ctx.db.session() as db:
                have = set(db.scalars(select(models.User.username)))
            missing = [u for u in demo.DEMO_USERS if u not in have]
            passwords = _demo_passwords(settings.demo_passwords_file, missing)
            absent = [u for u in missing if u not in passwords]
            if absent:
                sys.stderr.write(f"no password given for: {', '.join(absent)}\n")
                return 2
            result = demo.seed(ctx, passwords)
    except (ApiError, ValueError) as exc:
        sys.stderr.write(f"{getattr(exc, 'title', 'Error')}: {getattr(exc, 'detail', exc)}\n")
        return 2
    finally:
        ctx.jobs.shutdown()
    sys.stdout.write(f"demo ready: {result}\n")
    sys.stdout.write("If the console is running, restart it (or use Admin → Reset demo) so it drops old runtimes.\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m maka_server")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    ca = sub.add_parser("create-admin")
    ca.add_argument("--username", required=True)
    ca.add_argument("--password-stdin", action="store_true")
    cu = sub.add_parser("create-user")
    cu.add_argument("--username", required=True)
    cu.add_argument("--role", choices=["admin", "operator", "viewer"], required=True)
    cu.add_argument("--password-stdin", action="store_true")
    sub.add_parser("seed-demo")
    sub.add_parser("reset-demo")
    sub.add_parser("serve")
    args = ap.parse_args(argv)

    if args.cmd == "migrate":
        from maka_server.migrate import upgrade
        from maka_server.settings import get_settings

        upgrade(get_settings().db_url)
        return 0
    if args.cmd == "create-admin":
        return _create_user(args.username, "admin", args.password_stdin)
    if args.cmd == "create-user":
        return _create_user(args.username, args.role, args.password_stdin)
    if args.cmd in ("seed-demo", "reset-demo"):
        return _demo(reset_only=args.cmd == "reset-demo")
    if args.cmd == "serve":
        import uvicorn

        from maka_server.settings import get_settings

        host, _, port = get_settings().bind.rpartition(":")
        uvicorn.run("maka_server.main:create_app", factory=True, host=host, port=int(port))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
