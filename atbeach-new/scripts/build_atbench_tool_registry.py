from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.benchmark_adapters.atbench import (  # noqa: E402
    ATBENCH_HF_REVISION,
    ATBENCH_SOURCE_SHA256,
    load_atbench_cases,
)
from agentsentry.tool_registry import build_tool_registry  # noqa: E402

DEFAULT_INPUT = ROOT / "third_party" / "benchmarks" / "ATBench-Dataset" / "ATBench" / "test.json"
DEFAULT_OUTPUT = ROOT / "evaluation" / "static_trajectory" / "atbench_tool_registry_v1.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a frozen ATBench simulated-tool security registry from observed "
            "tool names, descriptions, JSON schemas and source metadata only."
        )
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--source-revision", default=ATBENCH_HF_REVISION)
    parser.add_argument(
        "--max-cases",
        type=int,
        default=0,
        help="0 scans the full release; use a positive value only for smoke registries.",
    )
    parser.add_argument(
        "--allow-unverified-source",
        action="store_true",
        help="Accept an input whose SHA-256 differs from the frozen ATBench release.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_cases < 0:
        parser.error("--max-cases must be zero or greater")
    if not args.input.is_file():
        parser.error(f"ATBench input not found: {args.input}")

    cases = load_atbench_cases(
        args.input,
        max_cases=args.max_cases,
        source_revision=args.source_revision,
        expected_sha256=None if args.allow_unverified_source else ATBENCH_SOURCE_SHA256,
    )
    registry = build_tool_registry(case.tool_catalog for case in cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(registry, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(f"tools: {len(registry['tools'])}")
    print(f"registry_sha256: {registry['registry_sha256']}")
    print(f"output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
