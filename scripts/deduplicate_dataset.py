from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.dataset_pipeline.dedup import deduplicate_records  # noqa: E402
from agentsentry.dataset_pipeline.io import iter_jsonl, write_json, write_jsonl  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Remove exact duplicates and group, but retain, near duplicates.")
    parser.add_argument("--input", type=Path, default=ROOT / "dataset" / "normalized" / "all.validated.jsonl")
    parser.add_argument("--output", type=Path, default=ROOT / "dataset" / "cleaned" / "all.cleaned.jsonl")
    parser.add_argument("--audit-output", type=Path, default=ROOT / "dataset" / "cleaned" / "all.annotated.jsonl")
    parser.add_argument("--report", type=Path, default=ROOT / "dataset" / "cleaned" / "dedup_report.json")
    parser.add_argument("--near-distance", type=int, default=6)
    args = parser.parse_args()

    annotated, cleaned, report = deduplicate_records(list(iter_jsonl(args.input)), near_distance=args.near_distance)
    write_jsonl(args.audit_output, annotated)
    write_jsonl(args.output, cleaned)
    write_json(args.report, report)
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
