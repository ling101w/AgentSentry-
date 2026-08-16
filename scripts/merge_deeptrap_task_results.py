#!/usr/bin/env python3
"""Merge valid DeepTrap task retries into a complete benchmark result."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEEPTRAP_ROOT = ROOT / "third_party" / "benchmarks" / "DeepTrap"
if str(DEEPTRAP_ROOT) not in sys.path:
    sys.path.insert(0, str(DEEPTRAP_ROOT))

import benchmark  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path)
    parser.add_argument("--replacement", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.resolve().read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("tasks"), list):
        raise ValueError(f"{path}: invalid DeepTrap result")
    return payload


def _task_is_valid(task: dict[str, Any]) -> bool:
    validity = task.get("evaluation_valid") or []
    return bool(validity) and all(bool(value) for value in validity)


def main() -> None:
    args = _parse_args()
    base = _load(args.base)
    tasks = {
        str(task.get("task_id")): copy.deepcopy(task)
        for task in base["tasks"]
        if isinstance(task, dict) and task.get("task_id")
    }
    if len(tasks) != len(base["tasks"]):
        raise ValueError("base result contains missing or duplicate task IDs")

    sources: dict[str, str] = {}
    for replacement_path in args.replacement:
        replacement = _load(replacement_path)
        for field in ("model", "judge_model"):
            if replacement.get(field) != base.get(field):
                raise ValueError(
                    f"{replacement_path}: {field} differs from base result "
                    f"({replacement.get(field)!r} != {base.get(field)!r})"
                )
        for task in replacement["tasks"]:
            if not isinstance(task, dict):
                continue
            task_id = str(task.get("task_id") or "")
            if task_id not in tasks:
                raise ValueError(f"{replacement_path}: unknown task ID {task_id!r}")
            if not _task_is_valid(task):
                continue
            tasks[task_id] = copy.deepcopy(task)
            sources[task_id] = str(replacement_path.resolve())

    ordered_tasks = [tasks[str(task["task_id"])] for task in base["tasks"]]
    unresolved = [task["task_id"] for task in ordered_tasks if not _task_is_valid(task)]

    merged = copy.deepcopy(base)
    merged["tasks"] = ordered_tasks
    merged["summary"] = benchmark._summarize_results(ordered_tasks)
    merged["merge"] = {
        "base": str(args.base.resolve()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "replacement_sources": sources,
        "unresolved_task_ids": unresolved,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
    print(args.output.resolve())
    if unresolved:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
