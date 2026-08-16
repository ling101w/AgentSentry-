#!/usr/bin/env python3
"""Validate audit JSONL completeness and produce replay-oriented evidence."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

REQUIRED = ("created_at", "run_id", "session_key", "agent_id", "tool_name", "params", "decision", "disposition", "execution_status")


def validate(path: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    malformed = 0
    if path.is_file():
        for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(value, dict):
                rows.append(value)
            else:
                malformed += 1
    missing_by_field: Counter[str] = Counter()
    incomplete_ids: list[str] = []
    timestamp_errors = 0
    for row in rows:
        missing = [field for field in REQUIRED if field not in row or row[field] is None or row[field] == ""]
        missing_by_field.update(missing)
        if missing:
            incomplete_ids.append(str(row.get("id") or f"row-{len(incomplete_ids) + 1}"))
        try:
            datetime.fromisoformat(str(row.get("created_at", "")).replace("Z", "+00:00"))
        except ValueError:
            timestamp_errors += 1
    tool_rows = [row for row in rows if str(row.get("type", "")).startswith(("tool_", "approval_"))]
    tool_missing = sum(bool([field for field in REQUIRED if field not in row or row[field] in (None, "")]) for row in tool_rows)
    return {
        "schema_version": "agentsentry.audit-completeness.v1",
        "path": str(path),
        "records": len(rows),
        "malformed_lines": malformed,
        "timestamp_errors": timestamp_errors,
        "complete_records": len(rows) - len(incomplete_ids),
        "completeness_rate": round((len(rows) - len(incomplete_ids)) / len(rows), 6) if rows else 0.0,
        "missing_by_field": dict(sorted(missing_by_field.items())),
        "incomplete_record_ids": incomplete_ids[:100],
        "tool_or_approval_records": len(tool_rows),
        "tool_or_approval_incomplete": tool_missing,
        "replay_fields": list(REQUIRED),
        "status": "pass" if rows and not malformed and not timestamp_errors and not incomplete_ids else "fail",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate(args.path)
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
