"""Publish numeric evidence from the historical local runs behind the README figures.

This exports recorded results; it never runs a model or recreates missing scores.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from statistics import mean

ARMS = ("no_defense", "risk_based", "evidence_gated", "agentward")
NATIVE = (
    "reports/native_agentdojo/native_deepseek_v4_pro_no_defense_expanded_v1_140.public.json",
    "reports/native_agentdojo/native_deepseek_v4_pro_agentsentry_expanded_v1_140.public.json",
    "outputs/native_deepseek_v4_pro_evidence_gated_expanded_v1_140.public.json",
    "runtime/agentward-agentdojo-deepseek-v4-pro-expanded-v1-a6/agentdojo-native-20260818T002106Z-3080364c/result.public.json",
)
DEEPTRAP = (
    "outputs/deeptrap-deepseek-v4-flash-no-defense-final/0011_qwen-deepseek-v4-flash.json",
    "outputs/deeptrap-deepseek-v4-flash-agentsentry-competition-final/0007_qwen-deepseek-v4-flash.json",
    "outputs/deeptrap-deepseek-v4-flash-agentsentry-evidence-gated/0025_qwen-deepseek-v4-flash.revalidated.json",
    "outputs/deeptrap-deepseek-v4-flash-agentward-env1-full1/deeptrap_agentward.full.revalidated.json",
)
EXPECTED_NATIVE = ((0.61, 0, 0.875), (0.01, 0.25, 0.675), (0, 0, 0.925), (0.02, 0.025, 0.975))
EXPECTED_DEEPTRAP = ((0.3361, 0.4119), (0.1428, 0.1119), (0.2371, 0.2167), (0.2909, 0.1548))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def deeptrap_public(source: dict) -> dict:
    """Keep per-task score evidence; omit workspaces, stderr and free-text notes."""
    rows = []
    for task in source["tasks"]:
        evaluation = task["attack_eval"]
        rows.append({
            **{key: task[key] for key in ("task_id", "category", "status", "timed_out", "evaluation_valid")},
            "grading_mean": task["grading"]["mean"],
            "attack_score_mean": evaluation["mean"],
            "attack_success_mean": evaluation["attack_success_mean"],
            "utility_mean": evaluation["utility_mean"],
            "runs": [{key: run[key] for key in ("score", "attack_success", "stealth", "utility", "is_success")} for run in evaluation["runs"]],
        })
    if len(rows) != 42 or len({row["task_id"] for row in rows}) != 42:
        raise ValueError("expected 42 unique DeepTrap tasks")
    computed = {
        "AGS": round(mean(row["attack_success_mean"] for row in rows), 4),
        "UGS": round(mean(row["utility_mean"] for row in rows), 4),
        "defense_score": round(1 - mean(row["attack_score_mean"] for row in rows), 4),
        "attack_successes": sum(row["runs"][0]["is_success"] for row in rows),
        "task_count": len(rows),
        "valid_task_count": sum(all(row["evaluation_valid"]) if isinstance(row["evaluation_valid"], list) else bool(row["evaluation_valid"]) for row in rows),
    }
    for metric in ("AGS", "UGS", "defense_score", "task_count", "valid_task_count"):
        if computed[metric] != source["summary"][metric]:
            raise ValueError(f"DeepTrap score mismatch: {metric}")
    return {
        "schema_version": "agentsentry.historical-deeptrap-scores.v1",
        "visibility": "public_numeric_task_scores",
        **{key: source[key] for key in ("model", "judge_model", "benchmark_version", "run_id", "timestamp", "suite", "runs_per_task", "summary")},
        "recomputed": computed,
        "tasks": rows,
        "projection": "Numeric scores and original execution statuses retained; free-text grading notes, stderr, workspace paths, configurations and transcripts excluded.",
    }


def export(source: Path, output: Path) -> None:
    files = []
    native_rows, deeptrap_rows = [], []
    selection = load(source / "evaluation/native/native_expanded_v1_selection.json")
    selection_hash = hashlib.sha256(json.dumps(selection, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    for index, arm in enumerate(ARMS):
        native_path = source / NATIVE[index]
        native = load(native_path)
        if native["benchmark"]["selection_sha256"] != selection_hash:
            raise ValueError("native selection hash mismatch")
        if native["coverage"]["completed_trials"] != 140 or native["coverage"]["error_trials"] != 0:
            raise ValueError("native run is not 140 completed trials")
        metrics = native["metrics"]
        values = (metrics["security"]["asr"]["value"], metrics["decisions"]["fpr"]["value"], metrics["utility"]["benign"]["task_completion_rate"]["value"])
        if values != EXPECTED_NATIVE[index]:
            raise ValueError(f"native figure mismatch: {arm}: {values}")
        native_rows.append({"arm": arm, "ASR": values[0], "FPR": values[1], "benign_utility": values[2], "attack_trials": 100, "benign_trials": 40, "reportable": native["coverage"]["reportable"], "run_id": native["run"]["run_id"]})
        target = output / "agentdojo" / f"{arm}.public.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(native_path.read_bytes())
        files.append({"source_relative": NATIVE[index], "source_sha256": digest(native_path), "published": target.relative_to(output).as_posix(), "published_sha256": digest(target), "projection": "original public aggregate, unchanged"})
        deeptrap_path = source / DEEPTRAP[index]
        public = deeptrap_public(load(deeptrap_path))
        if (public["recomputed"]["AGS"], public["recomputed"]["UGS"]) != EXPECTED_DEEPTRAP[index]:
            raise ValueError(f"DeepTrap figure mismatch: {arm}")
        target = output / "deeptrap" / f"{arm}.scores.json"
        write(target, public)
        files.append({"source_relative": DEEPTRAP[index], "source_sha256": digest(deeptrap_path), "published": target.relative_to(output).as_posix(), "published_sha256": digest(target), "projection": public["projection"]})
        deeptrap_rows.append({"arm": arm, **public["recomputed"], "model": public["model"]})
    extras = {
        "evaluation/native/native_expanded_v1_selection.json": "agentdojo/selection.json",
        "outputs/native_deepseek_v4_pro_evidence_gated_expanded_v1_140_provenance.json": "agentdojo/evidence_gated.provenance.json",
        "outputs/native_deepseek_v4_pro_evidence_gated_expanded_v1_140_three_layer.public.json": "agentdojo/evidence_gated.audit.public.json",
        "reports/native_agentdojo/native_deepseek_v4_pro_expanded_v1_three_layer_audit.public.json": "agentdojo/risk_based.audit.public.json",
        "reports/native_agentdojo/native_agentward_deepseek_v4_pro_expanded_v1_a6_three_layer.public.json": "agentdojo/agentward.audit.public.json",
    }
    for relative, published in extras.items():
        original, target = source / relative, output / published
        target.write_bytes(original.read_bytes())
        files.append({"source_relative": relative, "source_sha256": digest(original), "published": published, "published_sha256": digest(target), "projection": "original public evidence, unchanged"})
    for name, rows in (("agentdojo", native_rows), ("deeptrap", deeptrap_rows)):
        with (output / name / "summary.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    write(output / "comparison.json", {"agentdojo": native_rows, "deeptrap": deeptrap_rows})
    write(output / "manifest.json", {"schema_version": "agentsentry.local-benchmark-publication.v1", "publication_date": "2026-10-13", "historical_runs": True, "rerun_on_security_branch": False, "selection_sha256": selection_hash, "files": files})
    print(f"Verified 4 native aggregates and 168 DeepTrap task scores; exported to {output}")


def verify(output: Path) -> None:
    manifest = load(output / "manifest.json")
    for entry in manifest["files"]:
        if digest(output / entry["published"]) != entry["published_sha256"]:
            raise ValueError(f"published hash mismatch: {entry['published']}")
    comparison = load(output / "comparison.json")
    for index, arm in enumerate(ARMS):
        native = load(output / "agentdojo" / f"{arm}.public.json")
        metrics = native["metrics"]
        values = (metrics["security"]["asr"]["value"], metrics["decisions"]["fpr"]["value"], metrics["utility"]["benign"]["task_completion_rate"]["value"])
        if values != EXPECTED_NATIVE[index]:
            raise ValueError(f"native mismatch: {arm}")
        aggregate = comparison["agentdojo"][index]
        if (aggregate["ASR"], aggregate["FPR"], aggregate["benign_utility"]) != values:
            raise ValueError(f"native comparison mismatch: {arm}")
        public = load(output / "deeptrap" / f"{arm}.scores.json")
        rows = public["tasks"]
        values = (round(mean(row["attack_success_mean"] for row in rows), 4), round(mean(row["utility_mean"] for row in rows), 4))
        if len(rows) != 42 or values != EXPECTED_DEEPTRAP[index]:
            raise ValueError(f"DeepTrap mismatch: {arm}")
        if len({row["task_id"] for row in rows}) != 42:
            raise ValueError(f"duplicate DeepTrap tasks: {arm}")
        if (comparison["deeptrap"][index]["AGS"], comparison["deeptrap"][index]["UGS"]) != values:
            raise ValueError(f"comparison mismatch: {arm}")
    print("Published evidence verified: file hashes, 4 native arms, 168 DeepTrap task scores and figure metrics.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--verify", type=Path, help="Verify the public package without access to the private/local archive.")
    parser.add_argument("--output", type=Path, default=Path("reports/local-benchmarks-202608"))
    args = parser.parse_args()
    if args.verify:
        verify(args.verify)
    elif args.source_root:
        export(args.source_root, args.output)
    else:
        parser.error("specify --source-root or --verify")
