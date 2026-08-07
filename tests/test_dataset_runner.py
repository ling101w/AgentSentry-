from __future__ import annotations

from scripts.run_benchmark_eval import BenchmarkCase, classify_case_decisions, summarize


def _case(*, attack: bool = True, scenario: str = "external_email_hidden", tool: str = "") -> BenchmarkCase:
    return BenchmarkCase(
        case_id="fixture",
        source="Fixture",
        source_ref="fixture.json#/0",
        category="fixture",
        scenario=scenario,
        command="fixture",
        attack=attack,
        expectation="protected" if attack else "allow",
        tool=tool,
    )


def test_attack_scoring_uses_risk_sinks_instead_of_any_block() -> None:
    result = classify_case_decisions(
        _case(),
        [
            {"toolName": "read_email", "normalized_tool": "read_webpage", "decision": "deny"},
            {"toolName": "read_file", "decision": "allow"},
            {"toolName": "send_email", "decision": "deny"},
        ],
    )

    assert result["protected"] is False
    assert result["unsafe_release"] is True
    assert result["partial_block"] is True
    assert result["source_overblock"] is True


def test_attack_scoring_accepts_allowed_source_when_all_sinks_are_blocked() -> None:
    result = classify_case_decisions(
        _case(),
        [
            {"toolName": "read_email", "normalized_tool": "read_webpage", "decision": "allow"},
            {"toolName": "read_file", "decision": "deny"},
            {"toolName": "send_email", "decision": "ask"},
        ],
    )

    assert result["protected"] is True
    assert result["unsafe_release"] is False
    assert result["harness_error"] == ""


def test_unknown_attack_scenario_without_explicit_sink_is_unscorable() -> None:
    result = classify_case_decisions(
        _case(scenario="unknown"),
        [{"toolName": "call_api", "decision": "deny"}],
    )

    assert result["protected"] is False
    assert result["unsafe_release"] is False
    assert "no risk-sink oracle" in result["harness_error"]


def test_explicit_tool_precedes_scenario_and_matches_raw_alias() -> None:
    result = classify_case_decisions(
        _case(scenario="external_email_hidden", tool="read_email"),
        [
            {"toolName": "read_email", "normalized_tool": "read_webpage", "decision": "allow"},
            {"toolName": "read_file", "decision": "deny"},
        ],
    )

    assert result["unsafe_release"] is True
    assert [item["toolName"] for item in result["sink_decisions"]] == ["read_email"]


def test_benign_scoring_still_requires_every_action_to_be_allowed() -> None:
    result = classify_case_decisions(
        _case(attack=False, scenario="manual"),
        [{"toolName": "read_file", "decision": "deny"}],
    )

    assert result["false_positive"] is True
    assert result["allowed_all"] is False


def test_summary_excludes_harness_errors_from_security_denominators() -> None:
    case = _case()
    valid = {
        "case": case.__dict__,
        "protected": True,
        "unsafe_release": False,
        "harness_error": "",
        "decision_sequence": ["deny"],
    }
    failed = {
        "case": case.__dict__,
        "protected": False,
        "unsafe_release": False,
        "harness_error": "connection refused",
        "decision_sequence": [],
    }

    overall = summarize([valid, failed])["overall"]

    assert overall["cases"] == 2
    assert overall["evaluated_cases"] == 1
    assert overall["attempted_attack_cases"] == 2
    assert overall["attack_cases"] == 1
    assert overall["protection_rate"] == 1.0
    assert overall["harness_errors"] == 1
