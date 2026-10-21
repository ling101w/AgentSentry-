import copy

import pytest

from agentsentry.benign_reuse import deduplicate_workflows, summarize_replay, workflow_fingerprint


def fixture(expected="allow"):
    return {
        "case_id": "sample", "steps": [{"user_message": "Read README.md.", "tool_name": "read_file", "tool_args": {"path": "README.md"}, "tool_result": None, "session_history": []}],
        "label": {"expected": expected}, "provenance": [{"source": "fixture", "case_id": "sample"}],
    }


def test_exact_workflow_dedup_preserves_sources_without_counting_labels_as_inputs():
    first, second = fixture(), fixture()
    second["case_id"] = "copy"
    second["provenance"][0]["source"] = "other-source"
    rows, conflicts = deduplicate_workflows([first, second])
    assert len(rows) == 1
    assert len(rows[0]["provenance"]) == 2
    assert conflicts == []


def test_conflicting_source_expectations_require_adjudication():
    rows, conflicts = deduplicate_workflows([fixture(), fixture("ask")])
    assert rows == []
    assert conflicts[0]["reason"] == "conflicting_source_expectations"


def test_evaluator_control_fields_cannot_enter_a_detector_step():
    step = copy.deepcopy(fixture()["steps"][0])
    step["is_attack"] = False
    with pytest.raises(ValueError):
        workflow_fingerprint([step])


def test_rates_do_not_count_expected_reviews_as_false_positives_or_invent_utility():
    rows = [
        {"source": "fixture", "expected": "allow", "decision": "allow"},
        {"source": "fixture", "expected": "allow", "decision": "deny", "reason_groups": ["authorization"]},
        {"source": "fixture", "expected": "ask", "decision": "ask"},
        {"source": "fixture", "expected": "allow", "decision": "deny", "harness_error": "transport"},
    ]
    summary = summarize_replay(rows)
    assert summary["valid_normal_workflows"] == 2
    assert summary["source_labeled_normal_deny_rate"] == 0.5
    assert summary["review_controls_matching"] == 1
    assert summary["harness_errors"] == 1
    assert summary["task_utility"] is None
