#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.dataset_pipeline.io import write_jsonl  # noqa: E402
from agentsentry.dataset_pipeline.registry import (  # noqa: E402
    RegistryImportError,
    import_registry_xlsx,
)


DEFAULT_OUTPUT = ROOT / "dataset" / "manifest" / "source_registry.jsonl"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Import the four-column Excel dataset registry as traceable JSONL."
    )
    parser.add_argument("xlsx", type=Path, help="Workbook with 数据集/威胁/分类依据/边界说明 headers.")
    parser.add_argument("--sheet", help="Worksheet name (defaults to the active worksheet).")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        rows = import_registry_xlsx(args.xlsx, sheet=args.sheet)
        count = write_jsonl(args.output, rows)
    except (RegistryImportError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"input": str(args.xlsx), "output": str(args.output), "rows": count},
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
