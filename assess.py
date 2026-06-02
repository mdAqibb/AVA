#!/usr/bin/env python3
"""AVA — Authorized Vulnerability Assessor (CLI entrypoint).

AUTHORIZED USE ONLY. See DISCLAIMER.md. The tool refuses to run without an
explicit --i-have-authorization assertion and a valid scope.yaml.

Usage:
    python assess.py --target https://example.com --i-have-authorization

The CLI stays thin: it parses arguments, builds a Config, and hands off to the
Orchestrator. All policy (authorization, scope, rate limits) lives in modules.
"""

from __future__ import annotations

import argparse
import sys

from ava.intake.authorization import AuthorizationError
from ava.intake.config import Config
from ava.orchestrator import Orchestrator


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assess.py",
        description="Authorized web vulnerability assessment pipeline.",
        epilog="AUTHORIZED USE ONLY — see DISCLAIMER.md.",
    )
    p.add_argument("--target", help="Target base URL, e.g. https://example.com")
    p.add_argument("--scope-file", dest="scope_file", default="scope.yaml",
                   help="Path to scope.yaml (default: ./scope.yaml)")
    p.add_argument("--config", help="Optional YAML config file with defaults.")
    p.add_argument("--output-dir", dest="output_dir", default="output",
                   help="Where to write run artifacts (default: ./output)")
    p.add_argument("--operator", default="",
                   help="Operator identity recorded in the audit trail.")

    # The authorization gate — required to run.
    p.add_argument("--i-have-authorization", dest="authorized", action="store_true",
                   help="Assert you are explicitly authorized to test the target.")

    # Posture
    p.add_argument("--rate-preset", choices=["gentle", "moderate", "fast"],
                   help="Convenience preset for rate + concurrency.")
    p.add_argument("--rate", type=float, help="Requests per second.")
    p.add_argument("--concurrency", type=int, help="Max concurrent requests.")
    p.add_argument("--global-cap", dest="global_cap", type=int,
                   help="Hard ceiling on total requests for the run.")
    p.add_argument("--max-depth", dest="max_depth", type=int, help="Max crawl depth.")
    p.add_argument("--timeout", type=float, help="Per-request timeout (s).")
    p.add_argument("--retries", type=int,
                   help="Retries on transient transport errors (default 2).")

    # Resume an interrupted run for the same target.
    p.add_argument("--resume", action="store_true", default=None,
                   help="Resume the latest incomplete run for this target.")
    p.add_argument("--resume-run-id", dest="resume_run_id", default=None,
                   help="Resume a specific run id under the output dir.")

    # Check toggles (opt-out of defaults)
    p.add_argument("--no-active", dest="active", action="store_false", default=None,
                   help="Disable active checks (passive only).")
    p.add_argument("--no-heavy-fuzzing", dest="heavy_fuzzing", action="store_false",
                   default=None, help="Disable bounded heavy fuzzing.")
    p.add_argument("--no-dom-crawl", dest="dom_crawl", action="store_false",
                   default=None, help="Disable the headless-browser DOM crawl.")

    # Deliberately verbose, deliberately discouraged.
    p.add_argument("--allow-destructive-i-accept-risk", dest="allow_destructive",
                   action="store_true", default=None,
                   help="DISCOURAGED: permit destructive PoC payloads for this "
                        "run. Requires a human decision; not for unattended runs.")
    p.add_argument("--verbose", action="store_true", default=None)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = Config.load(args)
    # Carry the explicit assertion separately from posture config.
    config._authorized = bool(args.authorized)

    if not args.target:
        print("error: --target is required.\n", file=sys.stderr)
        build_parser().print_help(sys.stderr)
        return 2

    try:
        Orchestrator(config).run()
    except AuthorizationError as e:
        # Fail closed, loudly, with a clear reason and a non-zero exit code.
        print(f"\n[AUTHORIZATION REFUSED] {e}\n", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\nInterrupted. Partial state was saved; rerun to resume.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
