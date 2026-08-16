from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts import run_agentdojo_native as native


ROOT = Path(__file__).parents[1]
SELECTION = ROOT / "evaluation/native/native_balanced_v1_selection.json"
SCHEMA = ROOT / "evaluation/native/agentdojo_native_balanced_selection.schema.json"


def test_balanced_selection_is_one_generation_superset_and_balanced():
    selection = native.load_selection(SELECTION)
    specs = native.build_trial_specs(selection)
    assert selection["expected"] == {"benign_cases": 40, "attack_cases": 280, "unique_cases": 320, "trials": 320}
    assert len(specs) == 320
    assert sum(not spec.is_attack for spec in specs) == 40
    assert sum(spec.is_attack for spec in specs) == 280
    assert len({(spec.case_id, spec.seed, spec.repetition) for spec in specs}) == 320
    assert selection["sampling"]["mode"] == "one_generation_per_unique_case"
    # Balanced degrees: 40 users x 7 = 280 = 14 injections x 20.
    pairs = selection["attack_pairs"]
    injection_degree = Counter(pair["injection_task_id"] for pair in pairs)
    user_degree = Counter(pair["user_task_id"] for pair in pairs)
    assert set(injection_degree.values()) == {20} and len(injection_degree) == 14
    assert set(user_degree.values()) == {7} and len(user_degree) == 40
    # Superset of the frozen native-expanded-v1 selection for comparability.
    original = json.loads((ROOT / "evaluation/native/native_expanded_v1_selection.json").read_text(encoding="utf-8"))
    original_pairs = {(pair["user_task_id"], pair["injection_task_id"]) for pair in original["attack_pairs"]}
    balanced_pairs = {(pair["user_task_id"], pair["injection_task_id"]) for pair in pairs}
    assert original_pairs <= balanced_pairs


def test_balanced_selection_matches_public_schema():
    selection = json.loads(SELECTION.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(selection), key=lambda error: list(error.path))
    assert errors == []
    assert len(selection["coverage"]["attack_user_task_counts"]) == 40
    assert len(selection["coverage"]["injection_task_counts"]) == 14
