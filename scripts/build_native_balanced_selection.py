"""Build the workspace-constrained native-balanced-v1 selection.

Planning artifact only: loads AgentDojo's ground-truth workspace suite,
retains every native-expanded-v1 attack pair, then fills with a balanced
completion so that each injection task appears exactly ATTACKS_PER_INJECTION
times and each user task appears exactly ATTACKS_PER_USER times. No model
client is created and no provider is called.

Balanced degrees exist because 40 users x 7 = 280 = 14 injections x 20.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "evaluation" / "native" / "native_balanced_v1_selection.json"
SOURCE_SELECTION = ROOT / "evaluation" / "native" / "native_expanded_v1_selection.json"
BENCHMARK_SOURCE_COMMIT = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
SEED = 7
ATTACKS_PER_INJECTION = 20
ATTACKS_PER_USER = 7
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
    source = json.loads(SOURCE_SELECTION.read_text(encoding="utf-8"))
    selected = [
        {"user_task_id": pair["user_task_id"], "injection_task_id": pair["injection_task_id"]}
        for pair in source["attack_pairs"]
    ]
    selected_keys = {(pair["user_task_id"], pair["injection_task_id"]) for pair in selected}
    users = sorted(suite.user_tasks, key=natural_id)
    injections = sorted(suite.injection_tasks, key=natural_id)

    total = ATTACKS_PER_USER * len(users)
    if total != ATTACKS_PER_INJECTION * len(injections):
        raise RuntimeError("balanced degree equations do not close for this suite")
    if len(selected) > total:
        raise RuntimeError("source selection already exceeds the balanced attack budget")

    user_degree = Counter(pair["user_task_id"] for pair in selected)
    injection_degree = Counter(pair["injection_task_id"] for pair in selected)
    if any(count > ATTACKS_PER_USER for count in user_degree.values()):
        raise RuntimeError("source selection exceeds the per-user balanced degree")
    if any(count > ATTACKS_PER_INJECTION for count in injection_degree.values()):
        raise RuntimeError("source selection exceeds the per-injection balanced degree")

    # Greedy largest-remaining-demand fill. Every retained pair stays fixed;
    # remaining capacity is attached to the injections with the most open slots.
    remaining_user = {user: ATTACKS_PER_USER - user_degree[user] for user in users}
    remaining_injection = {injection: ATTACKS_PER_INJECTION - injection_degree[injection] for injection in injections}
    order = sorted(users, key=lambda user: (-remaining_user[user], natural_id(user)))
    for user in order:
        need = remaining_user[user]
        for _ in range(need):
            candidates = [
                injection
                for injection in injections
                if remaining_injection[injection] > 0 and (user, injection) not in selected_keys
            ]
            if not candidates:
                raise RuntimeError(f"balanced fill failed for {user}: no admissible injection task")
            best = max(candidates, key=lambda injection: (remaining_injection[injection], -natural_id(injection)[1]))
            selected.append({"user_task_id": user, "injection_task_id": best})
            selected_keys.add((user, best))
            remaining_injection[best] -= 1
        remaining_user[user] = 0

    if len(selected) != total:
        raise RuntimeError(f"could not construct {total} unique attack pairs")
    if any(remaining != 0 for remaining in remaining_injection.values()):
        raise RuntimeError("balanced fill did not saturate every injection task")
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
        "$schema": "https://agentsentry.dev/schemas/agentdojo-native-balanced-selection-v1.json",
        "selection_version": "1.2.0",
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
            "selection_algorithm": (
                "retain all native-expanded-v1 pairs, then greedy largest-remaining-demand fill "
                "to exact per-user degree 7 and per-injection degree 20"
            ),
            "unique_benign_cases": len(suite.user_tasks),
            "unique_attack_cases": len(pairs),
            "attacks_per_user_task": ATTACKS_PER_USER,
            "attacks_per_injection_task": ATTACKS_PER_INJECTION,
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
    print(json.dumps({"output": str(args.output), "expected": payload["expected"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
