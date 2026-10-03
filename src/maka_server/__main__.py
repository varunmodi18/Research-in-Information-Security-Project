"""python -m maka_server <command> (IMPLEMENTATION_PLAN.md §4.9, §7.2).

    migrate                      upgrade the database to the latest schema
    create-admin --username U    create the initial Admin (password prompted, min 12 chars)
    serve                        run the API + built UI with uvicorn on MAKA_BIND
"""

from __future__ import annotations

import argparse
import getpass
import sys


def _create_admin(username: str) -> int:
    from maka_server.context import build_context
    from maka_server.migrate import upgrade
    from maka_server.services.users import create_user
    from maka_server.settings import get_settings

    settings = get_settings()
    upgrade(settings.db_url)
    password = getpass.getpass(f"Password for {username} (min 12 characters): ")
    if password != getpass.getpass("Repeat password: "):
        sys.stderr.write("passwords do not match\n")
        return 2
    create_user(build_context(settings), username, password, "admin")
    sys.stdout.write(f"admin user {username!r} created\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m maka_server")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    ca = sub.add_parser("create-admin")
    ca.add_argument("--username", required=True)
    sub.add_parser("serve")
    args = ap.parse_args(argv)

    if args.cmd == "migrate":
        from maka_server.migrate import upgrade
        from maka_server.settings import get_settings

        upgrade(get_settings().db_url)
        return 0
    if args.cmd == "create-admin":
        return _create_admin(args.username)
    if args.cmd == "serve":
        import uvicorn

        from maka_server.settings import get_settings

        host, _, port = get_settings().bind.rpartition(":")
        uvicorn.run("maka_server.main:create_app", factory=True, host=host, port=int(port))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
