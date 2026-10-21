"""Replay frozen benign workflows and optionally execute native reference contracts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsentry.benign_reuse import summarize_replay  # noqa: E402


def source_snapshot() -> str:
    hasher = hashlib.sha256()
    paths = [ROOT / "openclaw-plugin/config.ts", ROOT / "openclaw-plugin/index.ts"]
    paths += list((ROOT / "openclaw-plugin/core").rglob("*.ts"))
    paths += list((ROOT / "openclaw-plugin/manifests").glob("*.json"))
    for path in sorted(paths):
        hasher.update(path.relative_to(ROOT).as_posix().encode())
        hasher.update(path.read_bytes())
    return hasher.hexdigest()


def native_reference(node: str, profile: str) -> dict:
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    from agentsentry.agentdojo_adapter import JsonlNodeBridgeClient, make_guarded_runtime_class

    os.environ.update({"AGENTSENTRY_NATIVE_PROFILE": profile, "AGENTSENTRY_NATIVE_ENFORCEMENT": "block", "AGENTSENTRY_NATIVE_DISABLE_JUDGE": "1"})
    suite = get_suite("v1.2.2", "workspace")
    bridge = JsonlNodeBridgeClient([node, str(ROOT / "openclaw-plugin/scripts/agentdojo-policy-bridge.mjs")], timeout=15)
    rows = []
    try:
        for task_id, task in suite.user_tasks.items():
            records, instances, call_errors = [], [], []
            baseline, guarded, error = None, None, ""
            try:
                baseline, _ = suite.run_task_with_pipeline(GroundTruthPipeline(task), task, injection_task=None, injections={})
                parent = make_guarded_runtime_class(FunctionsRuntime, bridge, user_message=task.PROMPT,
                    record_sink=lambda record: records.append({"tool": record["tool_name"], "decision": record["decision"], "executed": record["executed"],
                        "reason": record["reason"], "normalized_tool": (record.get("detector_result") or {}).get("normalized_tool"),
                        "bridge_error": record.get("bridge_error"), "protocol_error": record.get("protocol_error"), "after_feedback_error": record.get("after_feedback_error")}))

                class ReferenceRuntime(parent):
                    def __init__(self, *args, **kwargs):
                        super().__init__(*args, **kwargs)
                        instances.append(self)

                    def run_function(self, env, function, kwargs, raise_on_error=False):
                        # Continue the known reference path so the official utility
                        # evaluator is reached. Denied tools still never execute.
                        result, failure = super().run_function(env, function, kwargs, raise_on_error=False)
                        if failure:
                            call_errors.append({"tool": function, "error": str(failure)[:400]})
                        return result, failure

                guarded, _ = suite.run_task_with_pipeline(GroundTruthPipeline(task), task, injection_task=None, injections={}, runtime_class=ReferenceRuntime)
            except Exception as failure:
                error = f"{type(failure).__name__}: {failure}"[:500]
            finally:
                for instance in instances:
                    instance.end()
            interventions = [record for record in records if record["decision"] != "allow"]
            transport_error = next((record.get(key) for record in records for key in ("bridge_error", "protocol_error", "after_feedback_error") if record.get(key)), "")
            error = error or transport_error
            rows.append({"task_id": task_id, "reference_baseline_utility": baseline, "guarded_reference_utility": guarded,
                         "all_reference_tools_executed": bool(records) and all(record["executed"] for record in records), "reference_call_errors": call_errors,
                         "ask": any(record["decision"] == "ask" for record in records), "deny": any(record["decision"] == "deny" for record in records),
                         "first_intervention": interventions[0] if interventions else None, "records": records, "harness_error": error})
            print(json.dumps({"native_task": task_id, "baseline": baseline, "reference_utility": guarded, "intervened": bool(interventions), "error": bool(error)}), flush=True)
    finally:
        bridge.close()
    return {"evidence_level": "official_ground_truth_reference_contract", "profile": profile, "suite": "workspace", "agentdojo": "0.1.35", "benchmark_version": "v1.2.2",
            "trials": len(rows), "baseline_utility_passed": sum(row["reference_baseline_utility"] is True for row in rows),
            "reference_utility_passed": sum(row["guarded_reference_utility"] is True for row in rows),
            "reference_workflows_completed": sum(row["guarded_reference_utility"] is True and row["all_reference_tools_executed"] and not row["reference_call_errors"] and not row["harness_error"] for row in rows),
            "denied_workflows": sum(row["deny"] for row in rows), "asked_workflows": sum(row["ask"] for row in rows),
            "intervened_workflows": sum(row["ask"] or row["deny"] for row in rows), "harness_errors": sum(bool(row["harness_error"]) for row in rows),
            "models_called": False, "tools_execute_only_inside_official_memory_environment": True,
            "interpretation": "GroundTruthPipeline supplies reference actions AND answers. Official utility on this path is not autonomous agent Utility; all_reference_tools_executed is reported separately. This is not a model-backed benchmark.", "rows": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", default="node")
    parser.add_argument("--cases", type=Path, default=ROOT / "evaluation/benign/reused_business_workflows.jsonl")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profiles", default="balanced,competition")
    parser.add_argument("--native-reference", action="store_true")
    parser.add_argument("--native-profile", default="competition", choices=["balanced", "competition"])
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    before = source_snapshot()
    started = time.perf_counter()
    if args.native_reference:
        report = native_reference(args.node, args.native_profile)
    else:
        subprocess.run([args.node, str(ROOT / "openclaw-plugin/scripts/benign-workflow-replay.mjs"), "--cases", str(args.cases), "--output", str(args.output), "--profiles", args.profiles], check=True, cwd=ROOT)
        report = json.loads(args.output.read_text(encoding="utf-8"))
        report["summaries"] = {profile: summarize_replay([row for row in report["rows"] if row["profile"] == profile]) for profile in args.profiles.split(",")}
    report.update({"base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "working_tree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()),
                   "reportable": False, "detector_source_sha256_before": before, "detector_source_sha256_after": source_snapshot(), "elapsed_seconds": round(time.perf_counter() - started, 2)})
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key not in ["rows", "summaries"]}))
    harness_errors = report.get("harness_errors", sum(bool(row.get("harness_error")) for row in report["rows"]))
    return int(report["detector_source_sha256_after"] != before or harness_errors > 0)


if __name__ == "__main__":
    raise SystemExit(main())
