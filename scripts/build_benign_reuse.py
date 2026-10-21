"""Freeze reusable, source-labelled development workflows without model calls."""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsentry.benign_reuse import deduplicate_workflows  # noqa: E402


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_controls(node: str) -> list[dict]:
    relative = "reports/plugin_comparison/custom_realistic_100/xuanjian_custom_realistic_100_cases.csv"
    path = ROOT / relative
    with path.open(encoding="utf-8-sig") as handle:
        selected = [entry for entry in csv.DictReader(handle) if entry["attack"] == "True"]
    rows = [{"case_id": "custom-control:" + entry["case_id"], "command": entry["command"], "actions": json.loads(entry["actions"]),
             "label": {"expected": entry["expectation"], "is_attack": True, "basis": "historical_review_or_security_control"},
             "provenance": [{"source": "Custom-Realistic-100-controls", "case_id": entry["case_id"], "path": relative, "sha256": digest(path), "level": "development_controls"}]} for entry in selected]
    materialized = subprocess.run([node, str(ROOT / "openclaw-plugin/scripts/benign-workflow-replay.mjs"), "--materialize"], input=json.dumps(rows, ensure_ascii=False), capture_output=True, encoding="utf-8", check=True)
    cases, conflicts = deduplicate_workflows(json.loads(materialized.stdout))
    if conflicts:
        raise ValueError("Control expectations conflict")
    return cases


def build(node: str) -> dict:
    rows, inventory = [], []
    for relative in [
        "reports/benchmark_risk_tiered/benchmark_eval_results.risk_tiered.json",
        "reports/benchmark_risk_tiered/tool_attack_benchmark_results.risk_tiered.json",
    ]:
        path = ROOT / relative
        selected = [result["case"] for result in json.loads(path.read_text(encoding="utf-8"))["results"] if result["case"].get("attack") is False]
        inventory.append({"path": relative, "sha256": digest(path), "source_labeled_normal": len(selected)})
        for entry in selected:
            rows.append({"case_id": entry["case_id"], "command": entry["command"], "tool": entry["tool"], "target": entry.get("target", ""), "params": entry.get("params"),
                         "label": {"expected": entry["expectation"], "is_attack": False, "basis": "historical_source_label"},
                         "provenance": [{"source": entry["source"], "case_id": entry["case_id"], "path": relative, "sha256": digest(path), "level": "mapped_development", "original_ref": entry.get("source_ref")} ]})
    relative = "reports/plugin_comparison/custom_realistic_100/xuanjian_custom_realistic_100_cases.csv"
    path = ROOT / relative
    selected = [entry for entry in csv.DictReader(path.open(encoding="utf-8-sig")) if entry["attack"] == "False"]
    inventory.append({"path": relative, "sha256": digest(path), "source_labeled_normal": len(selected), "expectations": dict(Counter(entry["expectation"] for entry in selected))})
    for entry in selected:
        rows.append({"case_id": "custom-realistic:" + entry["case_id"], "command": entry["command"], "actions": json.loads(entry["actions"]),
                     "label": {"expected": entry["expectation"], "is_attack": False, "basis": "historical_source_label"},
                     "provenance": [{"source": "Custom-Realistic-100", "case_id": entry["case_id"], "path": relative, "sha256": digest(path), "level": "curated_development", "note": entry["notes"]}]})
    materialized = subprocess.run([node, str(ROOT / "openclaw-plugin/scripts/benign-workflow-replay.mjs"), "--materialize"], input=json.dumps(rows, ensure_ascii=False), capture_output=True, encoding="utf-8", check=True)
    rows = json.loads(materialized.stdout)

    from agentdojo.task_suite.load_suites import get_suite

    version = importlib.metadata.version("agentdojo")
    if version != "0.1.35":
        raise ValueError("Reuse manifest is pinned to AgentDojo 0.1.35")
    official = []
    for name in ["workspace", "banking", "slack", "travel"]:
        suite = get_suite("v1.2.2", name)
        official.append({"suite": name, "version": version, "benchmark_version": "v1.2.2", "benign_tasks": len(suite.user_tasks), "tools": len(suite.tools), "native_adapter_available": name == "workspace"})
        if name != "workspace":
            continue
        for task_id, task in suite.user_tasks.items():
            environment = suite.load_and_inject_default_environment({})
            calls = task.ground_truth(environment)
            steps = [{"user_message": task.PROMPT, "tool_name": call.function, "tool_args": call.args, "tool_result": None, "session_history": []} for call in calls]
            rows.append({"case_id": f"agentdojo-reference:{name}:{task_id}", "adapter": "agentdojo-workspace", "steps": steps,
                         "label": {"expected": "allow", "is_attack": False, "basis": "official_benign_reference_path"},
                         "provenance": [{"source": "AgentDojo-workspace-reference", "case_id": task_id, "path": "agentdojo==0.1.35:workspace:v1.2.2", "level": "reference_actions", "prompt_sha256": hashlib.sha256(task.PROMPT.encode()).hexdigest()}]})
    usable = [row for row in rows if row["steps"]]
    cases, conflicts = deduplicate_workflows(usable)
    return {"sources": inventory, "official_suites": official, "source_workflows": len(rows), "empty_workflows": [row["case_id"] for row in rows if not row["steps"]],
            "exact_duplicates_removed": len(usable) - len(cases) - sum(len(group["case_ids"]) for group in conflicts), "conflicts": conflicts,
            "unique_workflows": len(cases), "expected_counts": dict(Counter(row["label"]["expected"] for row in cases)), "cases": cases}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", default="node")
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation/benign/reused_business_workflows.jsonl")
    parser.add_argument("--inventory", type=Path, default=ROOT / "evaluation/benign/reuse_inventory.json")
    parser.add_argument("--controls-only", action="store_true")
    parser.add_argument("--controls-output", type=Path, default=ROOT / "evaluation/regression/reused_business_controls.jsonl")
    args = parser.parse_args()
    if args.controls_only:
        cases = build_controls(args.node)
        args.controls_output.parent.mkdir(parents=True, exist_ok=True)
        args.controls_output.write_text("".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in cases), encoding="utf-8")
        print(json.dumps({"controls": len(cases), "sha256": digest(args.controls_output)}))
        return 0
    result = build(args.node)
    cases = result.pop("cases")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in cases), encoding="utf-8")
    result.update({"evidence_level": "reused_development_fixtures", "cases_sha256": digest(args.output), "deduplication": "Exact five-field workflow input hash; source-labelled variants are not statistically independent.",
                   "label_isolation": "case ids, provenance and labels remain evaluator-owned; only five-field step payloads reach policy", "transformations": ["Reconstruct legacy manual Lab action parameters using existing labActionsFromCommand", "Remove evaluator-authored benchmark/benign-baseline reason hints from tool args", "Preserve business prompt text and source expectations; ask-labelled cases remain review controls"]})
    args.inventory.parent.mkdir(parents=True, exist_ok=True)
    args.inventory.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ["source_workflows", "unique_workflows", "expected_counts", "exact_duplicates_removed", "empty_workflows", "official_suites"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
