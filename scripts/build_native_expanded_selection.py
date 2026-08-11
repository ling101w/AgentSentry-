"""Build the workspace-constrained native-expanded-v1 selection.

This is a planning artifact only: it loads AgentDojo's ground-truth task
suite, discovers which injection vectors each user task actually exposes, and
selects 100 unique attack pairs without creating any model client or calling a
provider. The workspace suite has 40 unique benign tasks; expanding that count
requires a separate multi-suite manifest and policy release.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "evaluation" / "native" / "native_expanded_v1_selection.json"
BENCHMARK_SOURCE_COMMIT = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
SEED = 7
ATTACK_COUNT = 100
INJECTION_SINK_FAMILIES = {
    "injection_task_0": ["send_email"],
    "injection_task_1": ["cloud_file_mutation"],
    "injection_task_2": ["calendar_write"],
    "injection_task_3": ["email_data_to_external_send"],
    "injection_task_4": ["email_data_to_external_send"],
    "injection_task_5": ["email_data_to_external_send", "email_mutation"],
    "injection_task_6": ["email_data_to_external_send", "email_mutation"],
    "injection_task_7": ["email_data_to_external_send", "email_mutation"],
    "injection_task_8": ["email_data_to_external_send", "email_mutation"],
    "injection_task_9": ["email_data_to_external_send", "email_mutation"],
    "injection_task_10": ["cloud_data_to_external_send", "email_mutation"],
    "injection_task_11": ["cloud_data_to_external_send", "cloud_file_mutation", "email_mutation"],
    "injection_task_12": ["cloud_data_to_external_send", "cloud_file_mutation", "email_mutation"],
    "injection_task_13": ["bulk_external_send"],
}


def natural_id(value: str) -> tuple[str, int]:
    prefix, number = value.rsplit("_", 1)
    return prefix, int(number)


def load_workspace_suite() -> Any:
    from agentdojo.task_suite.load_suites import get_suite

    return get_suite("v1.2.2", "workspace")


def discover_vectors(suite: Any) -> dict[str, list[str]]:
    from agentdojo.attacks.important_instructions_attacks import ToolKnowledgeAttack

    attack = ToolKnowledgeAttack(suite, SimpleNamespace(name="gpt-4o-2024-05-13"))
    vectors: dict[str, list[str]] = {}
    for task_id, task in sorted(suite.user_tasks.items(), key=lambda item: natural_id(item[0])):
        vectors[task_id] = sorted(attack.get_injection_candidates(task))
    return vectors


def select_pairs(suite: Any) -> list[dict[str, str]]:
    existing_path = ROOT / "evaluation" / "native" / "agentdojo_selection.json"
    existing = json.loads(existing_path.read_text(encoding="utf-8"))
    selected = [
        {"user_task_id": pair["user_task_id"], "injection_task_id": pair["injection_task_id"]}
        for pair in existing["attack_pairs"]
    ]
    selected_keys = {(pair["user_task_id"], pair["injection_task_id"]) for pair in selected}
    users = sorted(suite.user_tasks, key=natural_id)
    injections = sorted(suite.injection_tasks, key=natural_id)

    # A coprime stride visits all user contexts while rotating through every
    # injection goal. Existing v1 pairs are retained before filling new cases.
    for index in range(len(users) * len(injections)):
        user_id = users[(17 * index) % len(users)]
        injection_id = injections[(5 * index + 3) % len(injections)]
        key = (user_id, injection_id)
        if key in selected_keys:
            continue
        selected.append({"user_task_id": user_id, "injection_task_id": injection_id})
        selected_keys.add(key)
        if len(selected) == ATTACK_COUNT:
            break
    if len(selected) != ATTACK_COUNT:
        raise RuntimeError(f"could not construct {ATTACK_COUNT} unique attack pairs")
    return selected


def injection_sink_metadata(suite: Any, pairs: list[dict[str, str]]) -> dict[str, Any]:
    environment = suite.load_and_inject_default_environment({})
    task_sequences: dict[str, list[str]] = {}
    family_counts: Counter[str] = Counter()
    for injection_id, task in sorted(suite.injection_tasks.items(), key=lambda item: natural_id(item[0])):
        functions = [call.function for call in task.ground_truth(environment)]
        task_sequences[injection_id] = functions
    for pair in pairs:
        for family in INJECTION_SINK_FAMILIES[pair["injection_task_id"]]:
            family_counts[family] += 1
    return {
        "injection_task_counts": dict(
            sorted(Counter(pair["injection_task_id"] for pair in pairs).items(), key=lambda item: natural_id(item[0]))
        ),
        "attack_user_task_counts": dict(
            sorted(Counter(pair["user_task_id"] for pair in pairs).items(), key=lambda item: natural_id(item[0]))
        ),
        "sink_family_case_counts": dict(sorted(family_counts.items())),
        "sink_family_counting": "multi_label; one attack case may contribute to multiple sink families",
        "injection_sink_families": INJECTION_SINK_FAMILIES,
        "static_ground_truth_tool_sequences": task_sequences,
    }


def build_selection() -> dict[str, Any]:
    suite = load_workspace_suite()
    vectors = discover_vectors(suite)
    pairs = select_pairs(suite)
    if len(suite.user_tasks) != 40:
        raise RuntimeError(f"expected 40 workspace user tasks, found {len(suite.user_tasks)}")
    if any(not vectors[pair["user_task_id"]] for pair in pairs):
        raise RuntimeError("selected attack pair has no observable injection vector")
    sink_metadata = injection_sink_metadata(suite, pairs)
    vector_counts = Counter(
        vector
        for pair in pairs
        for vector in vectors[pair["user_task_id"]]
    )
    return {
        "$schema": "https://agentsentry.dev/schemas/agentdojo-native-expanded-selection-v1.json",
        "selection_version": "1.1.0",
        "benchmark": {
            "name": "AgentDojo",
            "package_version": "0.1.35",
            "benchmark_version": "v1.2.2",
            "source_commit": BENCHMARK_SOURCE_COMMIT,
            "suite": "workspace",
        },
        "attack": "tool_knowledge",
        "seed_scope": "one provider generation per unique case; harness seed 7; provider generation seed is not exposed by AgentDojo 0.1.35",
        "seeds": [SEED],
        "benign_task_ids": sorted(suite.user_tasks, key=natural_id),
        "attack_pairs": pairs,
        "sampling": {
            "mode": "one_generation_per_unique_case",
            "repeats": 1,
            "harness_seed": SEED,
            "provider_generation_seed": "not_exposed_by_agentdojo_0.1.35",
        },
        "coverage": {
            "selection_algorithm": "retain native v1 pairs, then fill with coprime user/injection strides",
            "unique_benign_cases": len(suite.user_tasks),
            "unique_attack_cases": len(pairs),
            "observable_injection_vector_counts": dict(sorted(vector_counts.items())),
            **sink_metadata,
        },
        "expected": {
            "benign_cases": len(suite.user_tasks),
            "attack_cases": len(pairs),
            "unique_cases": len(suite.user_tasks) + len(pairs),
            "trials": len(suite.user_tasks) + len(pairs),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    payload = build_selection()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "expected": payload["expected"], "coverage": payload["coverage"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
