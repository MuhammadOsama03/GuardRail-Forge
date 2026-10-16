import argparse
import json

from guardrail_forge.benchmarks import BUILTIN_SUITES
from guardrail_forge.evaluations import render_markdown, run_suite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run GuardRail Forge security evaluations")
    parser.add_argument("--suite", default="core-security", choices=sorted(BUILTIN_SUITES))
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--minimum-pass-rate", type=float, default=1.0)
    args = parser.parse_args(argv)
    if not 0 <= args.minimum_pass_rate <= 1:
        parser.error("--minimum-pass-rate must be between 0 and 1")
    report = run_suite(BUILTIN_SUITES[args.suite])
    print(render_markdown(report) if args.format == "markdown" else report.model_dump_json(indent=2))
    return 0 if report.pass_rate >= args.minimum_pass_rate else 1


def cli() -> None:
    raise SystemExit(main())

