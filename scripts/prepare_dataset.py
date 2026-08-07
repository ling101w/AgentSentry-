from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.dataset_pipeline.pipeline import prepare_dataset  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build, validate, deduplicate, split, and export the complete dataset.")
    default_dataset_root = ROOT / "dataset"
    parser.add_argument("--benchmark-root", type=Path, default=ROOT / "third_party" / "benchmarks")
    parser.add_argument("--dataset-root", type=Path, default=default_dataset_root)
    parser.add_argument("--manifest", type=Path, default=ROOT / "dataset" / "raw_manifest.json")
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--near-distance", type=int, default=6)
    parser.add_argument("--split-seed", default="agentsentry-v1")
    parser.add_argument("--holdout-source", default="InjecAgent")
    parser.add_argument("--max-attack-ratio", type=float, default=0.80)
    parser.add_argument("--require-records", action="store_true")
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args()

    if (args.source or args.allow_partial) and args.dataset_root.resolve() == default_dataset_root.resolve():
        parser.error("--source/--allow-partial requires a separate --dataset-root to protect the full dataset")

    summary = prepare_dataset(
        benchmark_root=args.benchmark_root,
        dataset_root=args.dataset_root,
        manifest_path=args.manifest if args.manifest.exists() else None,
        selected=tuple(args.source),
        near_distance=args.near_distance,
        split_seed=args.split_seed,
        holdout_source=args.holdout_source,
        max_attack_ratio=args.max_attack_ratio,
        allow_partial=args.allow_partial,
    )
    print(json.dumps(summary, ensure_ascii=False))
    if args.require_records and not summary["normalized_records"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
