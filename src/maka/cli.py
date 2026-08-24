"""Command-line entry point.

Realises: P0.4. Subcommands are stubs until the phases that implement them land;
each stub still parses its flags and prints a run-id header so `--help` and a dry
run are meaningful from P0 onward.
"""

from __future__ import annotations

import argparse
import sys

from maka import rng, trace


def _common_flags(sub_parser: argparse.ArgumentParser) -> None:
    sub_parser.add_argument("--params", choices=["toy", "demo", "secure"], default="demo")
    sub_parser.add_argument("--fixture", choices=["paper", "net"], default="paper")
    sub_parser.add_argument("--sizing", choices=["paper", "actual"], default="paper")
    sub_parser.add_argument("--seed", type=int, default=0)
    sub_parser.add_argument("-v", dest="verbosity", action="count", default=1)
    sub_parser.add_argument("--no-color", action="store_true")
    sub_parser.add_argument("--out", default="artifacts/transcripts")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="maka", description="MAKA (Harbi et al., 2019) reference implementation")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("primitives", "run", "icmds", "security", "formal", "eval", "all"):
        sub_parser = sub.add_parser(name)
        _common_flags(sub_parser)
        if name == "icmds":
            sub_parser.add_argument("--attacks", choices=["all"], default="all")
        if name == "security":
            sub_parser.add_argument("--all", action="store_true")
        if name == "formal":
            sub_parser.add_argument("--ban", action="store_true")
            sub_parser.add_argument("--avispa", action="store_true")
        if name == "eval":
            sub_parser.add_argument("--all", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    r = rng.seed(args.seed)
    rid = rng.run_id(args.seed, args.params, args.fixture)
    tracer = trace.init(run_id=rid, out_dir=args.out, color=not args.no_color, verbosity=args.verbosity)
    tracer.banner(f"run-id: {rid}",
                  f"command: {args.command}  params={args.params}  fixture={args.fixture}  seed={args.seed}")

    dispatch = {
        "primitives": _run_primitives,
        "run": _run_protocol,
        "icmds": _run_icmds,
        "security": _run_security,
        "formal": _run_formal,
        "eval": _run_eval,
        "all": _run_all,
    }
    return dispatch[args.command](args, r)


def _run_primitives(args: argparse.Namespace, r: rng.Rng) -> int:
    from demos import d1_primitives

    d1_primitives.run(params_name=args.params, verbosity=args.verbosity)
    return 0


def _run_protocol(args: argparse.Namespace, r: rng.Rng) -> int:
    from demos import d2_maka_full

    d2_maka_full.run(params_name=args.params, fixture=args.fixture, verbosity=args.verbosity)
    return 0


def _run_icmds(args: argparse.Namespace, r: rng.Rng) -> int:
    from demos import d3_icmds_and_attacks

    d3_icmds_and_attacks.run(params_name=args.params, verbosity=args.verbosity)
    return 0


def _run_security(args: argparse.Namespace, r: rng.Rng) -> int:
    from demos import d4_maka_security

    d4_maka_security.run(params_name=args.params, fixture=args.fixture, verbosity=args.verbosity)
    return 0


def _run_formal(args: argparse.Namespace, r: rng.Rng) -> int:
    from demos import d5_formal

    d5_formal.run(ban=getattr(args, "ban", True), avispa=getattr(args, "avispa", True))
    return 0


def _run_eval(args: argparse.Namespace, r: rng.Rng) -> int:
    from demos import d6_evaluation

    d6_evaluation.run(params_name=args.params, fixture=args.fixture, sizing=args.sizing)
    return 0


def _run_all(args: argparse.Namespace, r: rng.Rng) -> int:
    for fn in (_run_primitives, _run_icmds, _run_protocol, _run_security, _run_formal, _run_eval):
        rc = fn(args, r)
        if rc != 0:
            return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
