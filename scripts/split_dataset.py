from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.dataset_pipeline.io import iter_jsonl, write_json, write_jsonl  # noqa: E402
from agentsentry.dataset_pipeline.split import split_records  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Create leakage-resistant grouped and cross-dataset splits.")
    parser.add_argument("--input", type=Path, default=ROOT / "dataset" / "cleaned" / "all.cleaned.jsonl")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dataset" / "splits")
    parser.add_argument("--train-ratio", type=float, default=0.70)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--seed", default="agentsentry-v1")
    parser.add_argument("--holdout-source", default="InjecAgent")
    args = parser.parse_args()

    splits, cross, report = split_records(
        list(iter_jsonl(args.input)),
        train_ratio=args.train_ratio,
        val_ratio=args.val_ratio,
        seed=args.seed,
        holdout_source=args.holdout_source,
    )
    for name, rows in splits.items():
        write_jsonl(args.output_dir / f"{name}.jsonl", rows)
    write_jsonl(args.output_dir / "cross_dataset_train.jsonl", cross["train"])
    write_jsonl(args.output_dir / "cross_dataset_test.jsonl", cross["test"])
    write_json(args.output_dir / "split_report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
