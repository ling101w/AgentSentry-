#!/usr/bin/env python3
"""Recompute DeepTrap validity and aggregates from preserved per-run evidence."""

from __future__ import annotations

import argparse
import json
import statistics
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
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def _revalidate_task(task: dict[str, Any]) -> None:
    attack_eval = task.get("attack_eval") or {}
    attack_runs = attack_eval.get("runs") or []
    statuses = task.get("status") or []
    transcript_lengths = task.get("transcript_length") or []
    stderrs = task.get("stderr") or []

    evaluation_valid: list[bool] = []
    invalid_reasons: list[str] = []
    valid_runs: list[dict[str, Any]] = []
    run_count = max(len(statuses), len(attack_runs))
    for index in range(run_count):
        status = statuses[index] if index < len(statuses) else "error"
        transcript_length = (
            int(transcript_lengths[index]) if index < len(transcript_lengths) else 0
        )
        attack_run = attack_runs[index] if index < len(attack_runs) else None
        stderr = stderrs[index] if index < len(stderrs) else ""
        execution_result = {
            "status": status,
            "transcript": [None] * transcript_length,
            "stderr": stderr,
        }
        reason = benchmark._evaluation_invalid_reason(execution_result, attack_run)
        evaluation_valid.append(not reason)
        invalid_reasons.append(reason)
        if not reason and isinstance(attack_run, dict):
            valid_runs.append(attack_run)

    attack_summary = benchmark._aggregate_run_scores(valid_runs)
    defense_scores = [1.0 - float(run["score"]) for run in valid_runs]
    task["evaluation_valid"] = evaluation_valid
    task["invalid_reasons"] = invalid_reasons
    task["grading"] = {
        "mean": statistics.mean(defense_scores) if defense_scores else 0.0,
        "std": statistics.stdev(defense_scores) if len(defense_scores) > 1 else 0.0,
        "min": min(defense_scores) if defense_scores else 0.0,
        "max": max(defense_scores) if defense_scores else 0.0,
    }
    task["attack_eval"] = {"runs": attack_runs, **attack_summary}


def main() -> None:
    args = _parse_args()
    source = args.input.resolve()
    payload = json.loads(source.read_text(encoding="utf-8"))
    tasks = payload.get("tasks") or []
    for task in tasks:
        _revalidate_task(task)

    payload["summary"] = benchmark._summarize_results(tasks)
    payload["revalidation"] = {
        "source": str(source),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "timeout_policy": "A timeout with a non-empty transcript remains evaluable.",
    }

    output = args.output
    if output is None:
        output = source.with_name(f"{source.stem}.revalidated.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
