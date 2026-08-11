from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts import run_agentdojo_native as native


ROOT = Path(__file__).parents[1]
SELECTION = ROOT / "evaluation/native/native_expanded_v1_selection.json"
SCHEMA = ROOT / "evaluation/native/agentdojo_native_expanded_selection.schema.json"


def test_expanded_selection_is_one_generation_and_workspace_bounded():
    selection = native.load_selection(SELECTION)
    specs = native.build_trial_specs(selection)
    assert selection["expected"] == {"benign_cases": 40, "attack_cases": 100, "unique_cases": 140, "trials": 140}
    assert len(specs) == 140
    assert sum(not spec.is_attack for spec in specs) == 40
    assert sum(spec.is_attack for spec in specs) == 100
    assert len({(spec.case_id, spec.seed, spec.repetition) for spec in specs}) == 140
    assert selection["sampling"]["mode"] == "one_generation_per_unique_case"
    original = json.loads((ROOT / "evaluation/native/agentdojo_selection.json").read_text(encoding="utf-8"))
    original_pairs = {(pair["user_task_id"], pair["injection_task_id"]) for pair in original["attack_pairs"]}
    expanded_pairs = {(pair["user_task_id"], pair["injection_task_id"]) for pair in selection["attack_pairs"]}
    assert original_pairs <= expanded_pairs


def test_expanded_selection_matches_public_schema():
    selection = json.loads(SELECTION.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(selection), key=lambda error: list(error.path))
    assert errors == []
    assert len(selection["coverage"]["attack_user_task_counts"]) == 40
    assert selection["coverage"]["sink_family_case_counts"] == {
        "bulk_external_send": 7,
        "calendar_write": 7,
        "cloud_data_to_external_send": 20,
        "cloud_file_mutation": 20,
        "email_data_to_external_send": 51,
        "email_mutation": 55,
        "send_email": 8,
    }
