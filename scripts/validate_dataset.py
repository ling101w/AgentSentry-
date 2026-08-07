from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.dataset_pipeline.io import iter_jsonl, write_json, write_jsonl  # noqa: E402
from agentsentry.dataset_pipeline.validation import validate_records  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate research records and mark invalid rows without deleting them.")
    parser.add_argument("--input", type=Path, default=ROOT / "dataset" / "normalized" / "all.jsonl")
    parser.add_argument("--output", type=Path, default=ROOT / "dataset" / "normalized" / "all.validated.jsonl")
    parser.add_argument("--report", type=Path, default=ROOT / "dataset" / "quality_report.json")
    parser.add_argument("--fail-on-invalid", action="store_true")
    args = parser.parse_args()

    records, report = validate_records(list(iter_jsonl(args.input)))
    write_jsonl(args.output, records)
    write_json(args.report, report)
    print(json.dumps(report, ensure_ascii=False))
    return 2 if args.fail_on_invalid and report["invalid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
