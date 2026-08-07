from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.dataset_pipeline.builder import build_normalized_dataset  # noqa: E402
from agentsentry.dataset_pipeline.io import write_json, write_jsonl  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the lossless AgentSentry research dataset without running AgentSentry.")
    default_output = ROOT / "dataset" / "normalized" / "all.jsonl"
    default_report = ROOT / "dataset" / "build_report.json"
    parser.add_argument("--benchmark-root", type=Path, default=ROOT / "third_party" / "benchmarks")
    parser.add_argument("--manifest", type=Path, default=ROOT / "dataset" / "raw_manifest.json")
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument("--report", type=Path, default=default_report)
    parser.add_argument("--source", action="append", default=[], help="Source key or dataset name; repeat to select sources.")
    parser.add_argument("--require-records", action="store_true")
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args()

    if args.source or args.allow_partial:
        if args.output.resolve() == default_output.resolve() or args.report.resolve() == default_report.resolve():
            parser.error("--source/--allow-partial requires separate --output and --report paths")

    records, report = build_normalized_dataset(
        args.benchmark_root,
        manifest_path=args.manifest if args.manifest.exists() else None,
        selected=tuple(args.source),
        allow_partial=args.allow_partial,
    )
    write_jsonl(args.output, records)
    write_json(args.report, report)
    print(json.dumps({"records": len(records), "output": str(args.output), "report": str(args.report)}, ensure_ascii=False))
    if args.require_records and not records:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
