from __future__ import annotations

from scripts.run_blind_evaluation import judge_called_for_decisions, most_severe_decision, opaque_client_id


def test_blind_runner_handles_compact_and_legacy_finding_shapes():
    assert judge_called_for_decisions([{"findings": 3, "semantic_judge_called": False}]) is False
    assert judge_called_for_decisions([{"findings": 2, "finding_types": ["deterministic", "semantic"]}]) is True
    assert judge_called_for_decisions([{"findings": [{"finding_type": "semantic"}]}]) is True


def test_blind_runner_uses_the_most_severe_decision():
    assert most_severe_decision([{"decision": "allow"}, {"decision": "ask"}]) == "ask"
    assert most_severe_decision([{"decision": "ask"}, {"decision": "deny"}]) == "deny"
    assert most_severe_decision([{"decision": "allow"}]) == "allow"
    assert most_severe_decision([{"unexpected": True}]) == "ask"


def test_blind_runner_does_not_put_semantic_case_ids_in_detector_routing():
    first = opaque_client_id(b"fixture-secret", "attack-indirect-prompt-injection", 0)
    second = opaque_client_id(b"fixture-secret", "attack-indirect-prompt-injection", 1)
    assert first.startswith("blind-trial-")
    assert "attack" not in first
    assert "injection" not in first
    assert first != second
