#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.dataset_pipeline.collector import (  # noqa: E402
    FAILED_STATUSES,
    CollectionError,
    collect_benchmarks,
)


DEFAULT_ROOT = ROOT / "third_party" / "benchmarks"
DEFAULT_MANIFEST = ROOT / "dataset" / "raw_manifest.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Shallow-clone or safely audit AgentSentry's supported raw benchmarks."
    )
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--source",
        action="append",
        dest="sources",
        help="Source key or dataset name; repeat to select multiple (defaults to all six).",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Fetch and fast-forward existing clean repositories; dirty raw data is refused.",
    )
    parser.add_argument("--git", default="git", help="Git executable (default: git).")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = collect_benchmarks(
            root=args.root,
            manifest_path=args.manifest,
            update=args.update,
            sources=args.sources,
            git_executable=args.git,
        )
    except (CollectionError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    statuses: dict[str, int] = {}
    failed = False
    for entry in manifest["sources"]:
        status = entry["status"]
        statuses[status] = statuses.get(status, 0) + 1
        failed = failed or status in FAILED_STATUSES
    print(
        json.dumps(
            {"manifest": str(args.manifest), "sources": len(manifest["sources"]), "statuses": statuses},
            ensure_ascii=False,
        )
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
