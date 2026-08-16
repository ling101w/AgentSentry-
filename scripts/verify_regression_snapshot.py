from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.dataset_pipeline.regression import (  # noqa: E402
    RegressionSnapshotError,
    verify_regression_snapshot,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the immutable AgentSentry regression benchmark snapshot.")
    parser.add_argument("--dataset-root", type=Path, default=ROOT / "dataset")
    parser.add_argument("--manifest", type=Path, default=ROOT / "dataset" / "regression_snapshot.json")
    args = parser.parse_args()
    try:
        report = verify_regression_snapshot(args.dataset_root, args.manifest)
    except RegressionSnapshotError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
