#!/usr/bin/env python3
"""Merge one-task DeepTrap result shards into a standard aggregate result."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEEPTRAP_ROOT = ROOT / "third_party" / "benchmarks" / "DeepTrap"
if str(DEEPTRAP_ROOT) not in sys.path:
    sys.path.insert(0, str(DEEPTRAP_ROOT))

import benchmark  # noqa: E402


EXPECTED_TASK_IDS = [f"task_R{risk}_T{task:02d}" for risk in range(1, 7) for task in range(1, 8)]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shard-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args()


def load_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("tasks"), list):
        raise ValueError(f"{path}: invalid DeepTrap result")
    return payload


def task_is_valid(task: dict[str, Any]) -> bool:
    validity = task.get("evaluation_valid") or []
    return bool(validity) and all(bool(value) for value in validity)


def main() -> None:
    args = parse_args()
    candidates: dict[str, list[tuple[Path, dict[str, Any], dict[str, Any]]]] = {}
    for path in sorted(args.shard_root.rglob("*.json")):
        try:
            payload = load_payload(path)
        except ValueError:
            continue
        tasks = payload["tasks"]
        if len(tasks) != 1 or not isinstance(tasks[0], dict):
            raise ValueError(f"{path}: expected exactly one task")
        task_id = str(tasks[0].get("task_id") or "")
        if task_id not in EXPECTED_TASK_IDS:
            raise ValueError(f"{path}: unexpected task ID {task_id!r}")
        candidates.setdefault(task_id, []).append((path, payload, tasks[0]))

    selected: dict[str, tuple[Path, dict[str, Any], dict[str, Any]]] = {}
    for task_id, rows in candidates.items():
        rows.sort(key=lambda row: (task_is_valid(row[2]), row[0].stat().st_mtime_ns))
        selected[task_id] = rows[-1]

    missing = [task_id for task_id in EXPECTED_TASK_IDS if task_id not in selected]
    if args.require_complete and missing:
        raise SystemExit(f"missing DeepTrap shards: {', '.join(missing)}")
    if not selected:
        raise SystemExit("no DeepTrap shards found")

    first_path, first_payload, _ = selected[next(task_id for task_id in EXPECTED_TASK_IDS if task_id in selected)]
    model = first_payload.get("model")
    judge_model = first_payload.get("judge_model")
    for task_id, (path, payload, _) in selected.items():
        if payload.get("model") != model or payload.get("judge_model") != judge_model:
            raise ValueError(f"{path}: model or judge differs from {first_path}")

    tasks = [selected[task_id][2] for task_id in EXPECTED_TASK_IDS if task_id in selected]
    aggregate = {
        "model": model,
        "judge_model": judge_model,
        "benchmark_version": first_payload.get("benchmark_version", ""),
        "run_id": "sharded",
        "timestamp": time.time(),
        "suite": "all" if not missing else ",".join(task["task_id"] for task in tasks),
        "runs_per_task": 1,
        "summary": benchmark._summarize_results(tasks),
        "tasks": tasks,
        "shards": {
            "root": str(args.shard_root.resolve()),
            "selected": {task_id: str(row[0].resolve()) for task_id, row in selected.items()},
            "missing_task_ids": missing,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(aggregate, indent=2, ensure_ascii=False), encoding="utf-8")
    print(args.output.resolve())
    if args.require_complete and not aggregate["summary"]["valid_result"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
