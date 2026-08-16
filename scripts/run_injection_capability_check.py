#!/usr/bin/env python3
"""Run AgentDojo injection tasks as plain user tasks (official capability check).

AgentDojo's official ``benchmark_suite_with_injections`` runs every injection
task once as a normal user task before scoring attacks and reports
``injection_tasks_utility_results``. Without this step, an attack that fails
only because the model is incapable of executing the malicious goal is
indistinguishable from an attack stopped by the defense.

This runner reproduces that step with the same pipeline construction as
``run_agentdojo_native.py`` (plain runtime, no defense) so the capability
baseline is comparable to the defended benchmark runs.

Usage:
    python scripts/run_injection_capability_check.py \
        --selection evaluation/native/native_workspace_full_v1_selection.json \
        --model openai-compatible --model-id "$model" \
        --openai-compatible-system-role system
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import run_agentdojo_native as native  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--model", default="openai-compatible")
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--openai-compatible-system-role", default="system", choices=["system", "developer"])
    parser.add_argument("--provider-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--provider-max-retries", type=int, default=2)
    parser.add_argument("--output", type=Path, default=None, help="defaults to runtime/capability/<suite>-capability.json")
    args = parser.parse_args(argv)

    selection = native.load_selection(args.selection.resolve())
    api = native.load_agentdojo_api(native.source_for_selection(selection))
    suite = api.get_suite(selection["benchmark"]["benchmark_version"], selection["benchmark"]["suite"])
    native.validate_selection_against_suite(selection, suite)

    from agentdojo.benchmark import run_task_without_injection_tasks
    from agentdojo.logging import OutputLogger

    model = native.create_pipeline_llm(
        api,
        args.model,
        args.model_id,
        timeout_seconds=args.provider_timeout_seconds,
        max_retries=args.provider_max_retries,
        system_role=args.openai_compatible_system_role,
    )
    pipeline = api.AgentPipeline.from_config(
        api.PipelineConfig(
            llm=model,
            model_id=args.model_id,
            defense=None,
            tool_delimiter="tool",
            system_message_name=None,
            system_message=None,
            tool_output_format=None,
        )
    )

    benchmark_version = selection["benchmark"]["benchmark_version"]
    output = args.output or (
        ROOT / "runtime" / "capability" / f"{suite.name}-injection-capability-{args.model_id.replace('/', '_')}.json"
    )
    # run_task_without_injection_tasks dereferences logger.logdir even when no
    # caching is intended, so a real log directory is required.
    logdir = output.parent / "logs" / suite.name
    logdir.mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {}
    injection_ids = sorted(suite.injection_tasks)
    # TraceLogger reads the global Logger context (Logger.get().logdir); the
    # official benchmark wraps runs in OutputLogger, so do the same.
    with OutputLogger(str(logdir)):
        for index, injection_id in enumerate(injection_ids, start=1):
            task = suite.injection_tasks[injection_id]
            started = datetime.now(UTC)
            try:
                utility, _ = run_task_without_injection_tasks(
                    suite, pipeline, task, logdir, True, benchmark_version
                )
                results[injection_id] = {
                    "utility": bool(utility),
                    "goal": str(getattr(task, "GOAL", "")),
                    "error": None,
                }
                status = "solved" if utility else "unsolved"
            except Exception as exc:  # noqa: BLE001 - record and continue
                results[injection_id] = {
                    "utility": None,
                    "goal": str(getattr(task, "GOAL", "")),
                    "error": f"{type(exc).__name__}: {exc}",
                }
                status = f"error={results[injection_id]['error']}"
            elapsed = (datetime.now(UTC) - started).total_seconds()
            print(f"[{index:02d}/{len(injection_ids):02d}] {injection_id} {status} ({elapsed:.1f}s)", flush=True)

    solvable = sum(1 for row in results.values() if row["utility"] is True)
    report = {
        "created_at": datetime.now(UTC).isoformat(),
        "purpose": "AgentDojo official injection-goal capability check (injection tasks run as user tasks)",
        "benchmark": selection["benchmark"],
        "model": {"kind": args.model, "model_id": args.model_id},
        "injection_tasks_solvable": solvable,
        "injection_tasks_total": len(results),
        "note": (
            "Injection tasks the model cannot solve as plain user tasks cannot "
            "produce meaningful attack-success evidence; treat their security "
            "outcomes as capability-confounded, not defense-attributable."
        ),
        "results": results,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"solvable {solvable}/{len(results)}; report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
