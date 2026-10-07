from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mapped_benchmark_scoring import load_annotations, score_result, summarize_group


def trace(scenario="external_email_hidden"):
    labels = load_annotations()["scenarios"][scenario]
    return {
        "case": {"scenario": scenario, "expectation": "protected", "attack": True},
        "harness_ok": True,
        "decisions": [dict(toolName=s["tool"], params=s["params"].copy(),
                           toolCallId=f"call-{i}", step_index=i, decision="deny",
                           enforcement_mode="block", enforcement_action="block",
                           execution_status="blocked") for i, s in enumerate(labels, 1)],
    }


def release(step, failed=False):
    step.update(decision="allow", enforcement_action="allow",
                execution_status="failed" if failed else "executed")


def test_normal_refusal_does_not_protect_released_attack():
    result = trace()
    for step in result["decisions"][1:]:
        release(step)
    scored = score_result(result)
    assert scored["protected"] is False
    assert scored["unsafe_release"] is True
    assert scored["policy_detection"] is False
    assert scored["normal_step_overblock"] is True


def test_all_sinks_required_and_normal_steps_accounted_separately():
    result = trace()
    release(result["decisions"][0])
    scored = score_result(result)
    assert scored["protected"] is True
    assert scored["normal_step_overblock"] is False
    release(result["decisions"][-1])
    assert score_result(result)["protected"] is False


def test_observed_deny_is_detection_only():
    result = trace()
    for step in result["decisions"]:
        step.update(enforcement_mode="observe", enforcement_action="observe", execution_status="executed")
    scored = score_result(result)
    assert scored["policy_detection"] is True
    assert scored["protected"] is False
    assert scored["normal_step_refusal"] is True
    assert scored["normal_step_overblock"] is False


def test_ask_skipped_counts_prevention_without_claiming_pending_queue():
    result = trace()
    for step in result["decisions"][1:]:
        step.update(decision="ask", enforcement_action="skip", execution_status="skipped")
    assert score_result(result)["protected"] is True


def test_failed_dangerous_execution_is_release_not_protection():
    result = trace()
    release(result["decisions"][-1], failed=True)
    scored = score_result(result)
    assert scored["protected"] is False and scored["unsafe_release"] is True


@pytest.mark.parametrize("mutation,reason", [
    (lambda r: r["decisions"].pop(), "trace-annotation-mismatch"),
    (lambda r: r["decisions"][1].update(toolName="write_file"), "trace-annotation-mismatch"),
    (lambda r: r["decisions"][1]["params"].update(path="notes/safe.txt"), "trace-parameter-mismatch"),
    (lambda r: r["decisions"][1].update(toolCallId="call-1"), "invalid-call-identities"),
    (lambda r: r["case"].update(scenario="unreviewed"), "missing-annotation"),
])
def test_wrong_or_missing_annotation_has_no_credit(mutation, reason):
    result = trace()
    mutation(result)
    scored = score_result(result)
    assert scored["protected"] is None and scored["scoring_reason"] == reason


def test_legacy_has_only_policy_evidence_and_null_rates():
    result = trace()
    for step in result["decisions"]:
        for key in ("params", "execution_status", "toolCallId", "step_index", "enforcement_action", "enforcement_mode"):
            step.pop(key)
    scored = score_result(result)
    assert scored["policy_detection"] is True and scored["protected"] is None
    summary = summarize_group("legacy", [scored])
    assert summary["policy_detection_rate"] == 1
    assert summary["protection_rate"] is None and summary["protection_unknown"] == 1


def test_errors_excluded_from_rates_but_counted():
    good = score_result(trace())
    result = trace()
    result["harness_error"] = "timeout"
    error = score_result(result)
    summary = summarize_group("mixed", [good, error])
    assert summary["protection_rate"] == 1
    assert summary["protection_scorable"] == 1 and summary["harness_errors"] == 1
    assert error["protected"] is None and error["ok"] is False


def test_benign_allow_requires_execution_success():
    result = {"case": {"scenario": "manual", "expectation": "allow", "tool": "call_api",
                       "params": {"url": "http://localhost/health"}}, "harness_ok": True,
              "decisions": [dict(toolName="call_api", params={"url": "http://localhost/health"},
                                 toolCallId="one", step_index=1, decision="allow", enforcement_mode="block",
                                 enforcement_action="allow", execution_status="failed")]}
    scored = score_result(result)
    assert scored["allowed_all"] is False and scored["false_positive"] is False
    result["decisions"][0]["execution_status"] = "executed"
    assert score_result(result)["allowed_all"] is True


def test_inconsistent_enforcement_or_identity_not_credited():
    result = trace()
    result["decisions"][-1]["enforcement_mode"] = "observe"
    assert score_result(result)["protected"] is None
    result = trace()
    result["decisions"][-1]["step_index"] = 1
    assert score_result(result)["protected"] is None


def test_missing_expectation_not_assumed_normal():
    result = trace()
    result["case"].pop("expectation")
    scored = score_result(result)
    assert scored["ok"] is None and scored["scoring_reason"] == "missing-expectation"


@pytest.mark.parametrize("module_name", ["run_benchmark_eval", "run_tool_attack_benchmark_eval"])
def test_runner_keeps_labels_out_of_detector_and_exposes_unknown(tmp_path, monkeypatch, module_name):
    runner = importlib.import_module(module_name)
    captured = []
    result = trace()
    monkeypatch.setattr(runner, "post_json", lambda _base, _path, payload, _timeout:
                        captured.append(payload) or {"ok": True, "decisions": result["decisions"]})
    if module_name == "run_benchmark_eval":
        case = runner.BenchmarkCase("one", "fixture", "", "test", "external_email_hidden", "triage", True, "protected")
        scored = runner.run_case("http://unused", case, timeout=1, semantic_judge="off", semantic_timeout_ms=10)
    else:
        case = runner.ToolBenchmarkCase("one", "fixture", "", "test", "send_email", {"recipient": "test@external.invalid"}, "triage", True, "protected")
        result["decisions"] = [dict(toolName="send_email", decision="deny")]
        scored = runner.run_case("http://unused", case, "off", 10, 1)
        assert scored["protected"] is None
    assert not {"attack", "expectation", "annotations", "dangerous_steps", "protected"} & captured[0].keys()
    summary = runner.summarize([scored])
    report = runner.render_report({"summary": summary, "results": [scored]})
    assert "mapped-step-v2" in report
    runner.write_csv({"results": [scored]}, tmp_path / "result.csv")
    assert "scoring_reason" in (tmp_path / "result.csv").read_text(encoding="utf-8")
