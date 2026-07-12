from __future__ import annotations

import copy
import json
import math
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from agentsentry.native_protocol import (
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    SCHEMA_URI,
    NativeProtocolError,
    canonical_json_bytes,
    canonical_sha256,
    compute_native_metrics,
    opaque_trial_id,
    validate_native_metrics,
    validate_native_trial,
    validate_public_native_result,
)


SECRET = b"independent-evaluator-secret"
RESULT_SCHEMA_PATH = Path(__file__).parents[1] / "evaluation" / "native" / "agentdojo_native_result.schema.json"
PUBLIC_RESULT_PATH = Path(__file__).parents[1] / "evaluation" / "native" / "agentdojo_results.json"


def public_result_schema_validator() -> Draft202012Validator:
    schema = json.loads(RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def detector_input() -> dict:
    return {
        "user_message": "Create an incident ticket.",
        "tool_name": "create_ticket",
        "tool_args": {
            "category": "security",
            "label": "urgent",
            "nested": {"expected": "business-field-not-evaluator-label"},
        },
        "tool_result": None,
        "session_history": [{"role": "user", "content": "Use category and label fields."}],
    }


def make_trial(
    case_id: str,
    *,
    seed: int = 7,
    repetition: int = 0,
    is_attack: bool = True,
    security: bool | None = False,
    utility: float | None = 1.0,
    task_completed: bool | None = True,
    decision: str = "deny",
    latency_ms: float = 10,
    cost_usd: float | None = 0.001,
    error: bool = False,
) -> dict:
    request = detector_input()
    detector = None if error else {
        "decision": decision,
        "blocked_scope": "none" if decision == "allow" else "action",
        "action_executed": decision == "allow",
        "llm_judge_called": decision != "allow",
    }
    outcome = {
        "is_attack": is_attack,
        "security": None if error or not is_attack else security,
        "utility": None if error else utility,
        "task_completed": None if error else task_completed,
    }
    trial = {
        "trial_id": opaque_trial_id(SECRET, case_id, seed, repetition),
        "case_id": case_id,
        "seed": seed,
        "repetition": repetition,
        "status": "error" if error else "ok",
        "detector_input": request,
        "detector": detector,
        "outcome": outcome,
        "latency_ms": {
            "end_to_end": latency_ms,
            "agent": None if error else latency_ms * 0.6,
            "detector": None if error else latency_ms * 0.3,
            "judge": None if error else latency_ms * 0.1,
        },
        "usage": {
            "input_tokens": 100,
            "output_tokens": 20,
            "judge_input_tokens": 30 if not error else None,
            "judge_output_tokens": 5 if not error else None,
        },
        "cost": {
            "usd": cost_usd,
            "currency": "USD",
            "estimated": True,
            "pricing_snapshot": "2026-07-12",
        },
        "error": {
            "stage": "agent",
            "kind": "timeout",
            "code": "AGENT_TIMEOUT",
            "message_redacted": "agent timed out",
            "retryable": True,
        } if error else None,
        "commitments": {
            "detector_input_sha256": canonical_sha256(request),
            "detector_output_sha256": canonical_sha256(detector) if detector is not None else None,
        },
    }
    return trial


def public_result(*, status: str = "not_run", trials: list[dict] | None = None) -> dict:
    rows = trials or []
    has_run = status != "not_run"
    completed = sum(row["status"] == "ok" for row in rows)
    errors = len(rows) - completed
    transcript_hash = "b" * 64 if has_run else None
    return {
        "$schema": SCHEMA_URI,
        "protocol": {"name": PROTOCOL_NAME, "version": PROTOCOL_VERSION},
        "visibility": "public_aggregate",
        "status": status,
        "run": {
            "run_id": "run-native-fixture",
            "release_commit": "a" * 40 if has_run else None,
            "working_tree_dirty": False,
            "started_at": "2026-07-12T10:00:00+00:00" if has_run else None,
            "finished_at": "2026-07-12T10:05:00+00:00" if has_run else None,
        },
        "benchmark": {
            "name": "AgentDojo",
            "version": "1.0.0",
            "commit": "c" * 40,
            "suite": "workspace",
            "adapter_version": "1.0.0",
            "selection_sha256": "d" * 64,
            "seeds": [7, 11, 19],
        },
        "system_under_test": {
            "plugin_version": "0.2.0",
            "profile": "competition",
            "model": "fixture-model",
            "config_sha256": "e" * 64,
        },
        "label_isolation": {
            "architecture": "separate_evaluator_and_detector_processes",
            "label_store_mounted_in_detector": False,
            "opaque_trial_ids": True,
            "detector_event_schema_sha256": "f" * 64,
            "detector_transcript_sha256": transcript_hash,
            "detector_event_count": len(rows) if has_run else 0,
            "private_labels_sha256": "1" * 64 if has_run else None,
            "post_join_sha256": "2" * 64 if has_run else None,
            "violations": [],
        },
        "coverage": {
            "expected_trials": len(rows) if has_run else 120,
            "observed_trials": len(rows),
            "completed_trials": completed,
            "error_trials": errors,
            "reportable": has_run and bool(rows) and errors == 0,
        },
        "metrics": compute_native_metrics(rows) if rows else None,
        "artifacts": {
            "private_trials_sha256": "3" * 64 if has_run else None,
            "detector_transcript_sha256": transcript_hash,
        },
    }


def test_canonical_json_and_hash_are_deterministic_and_unicode_safe():
    first = {"z": 1, "message": "玄鉴", "nested": {"b": 2, "a": 1}}
    second = {"nested": {"a": 1, "b": 2}, "message": "玄鉴", "z": 1}
    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert canonical_json_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert canonical_sha256(first) == canonical_sha256(second)
    assert re.fullmatch(r"[0-9a-f]{64}", canonical_sha256(first))

    with pytest.raises(NativeProtocolError, match="canonical JSON"):
        canonical_json_bytes({"value": math.nan})
    with pytest.raises(NativeProtocolError, match="canonical JSON"):
        canonical_json_bytes({"not-json"})
    with pytest.raises(NativeProtocolError, match="non-string object key"):
        canonical_json_bytes({1: "coerced-key"})
    with pytest.raises(NativeProtocolError, match="unsupported tuple"):
        canonical_json_bytes(("not", "a", "json-array"))


def test_opaque_trial_id_is_stable_and_uses_the_full_private_identity():
    first = opaque_trial_id(SECRET, "attack-indirect-001", 7, 0)
    assert first == opaque_trial_id(SECRET, "attack-indirect-001", 7, 0)
    assert first != opaque_trial_id(SECRET, "attack-indirect-001", 8, 0)
    assert first != opaque_trial_id(SECRET, "attack-indirect-002", 7, 0)
    assert re.fullmatch(r"trial_[0-9a-f]{24}", first)
    assert "attack" not in first
    with pytest.raises(NativeProtocolError):
        opaque_trial_id(b"", "case", 0, 0)


def test_trial_validation_allows_legitimate_category_and_label_tool_arguments():
    trial = make_trial("benign-business-fields", is_attack=False, security=None, decision="allow")
    validate_native_trial(trial)
    assert trial["detector_input"]["tool_args"]["category"] == "security"
    assert trial["detector_input"]["tool_args"]["label"] == "urgent"


def test_trial_validation_rejects_tampering_and_unknown_fields():
    trial = make_trial("attack-tamper")
    trial["detector_input"]["tool_args"]["category"] = "changed-after-commitment"
    with pytest.raises(NativeProtocolError, match="input commitment"):
        validate_native_trial(trial)

    trial = make_trial("attack-output-tamper")
    trial["detector"]["decision"] = "allow"
    trial["detector"]["blocked_scope"] = "none"
    trial["detector"]["action_executed"] = True
    with pytest.raises(NativeProtocolError, match="output commitment"):
        validate_native_trial(trial)

    trial = make_trial("attack-extra")
    trial["unexpected"] = True
    with pytest.raises(NativeProtocolError, match="fields mismatch"):
        validate_native_trial(trial)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda row: row["outcome"].update(security=None), "security"),
        (lambda row: row["outcome"].update(utility=1.1), "between 0 and 1"),
        (lambda row: row["outcome"].update(utility=math.inf), "finite"),
        (lambda row: row["latency_ms"].update(end_to_end=-1), "non-negative"),
        (lambda row: row["usage"].update(input_tokens=-1), "non-negative integer"),
        (lambda row: row["cost"].update(usd=math.nan), "finite"),
    ],
)
def test_trial_validation_rejects_invalid_outcome_and_numeric_boundaries(mutate, message):
    trial = make_trial("attack-invalid-boundary")
    mutate(trial)
    with pytest.raises(NativeProtocolError, match=message):
        validate_native_trial(trial)


def test_trial_validation_enforces_attack_benign_and_error_semantics():
    benign = make_trial("benign-security", is_attack=False, security=None, decision="allow")
    benign["outcome"]["security"] = False
    with pytest.raises(NativeProtocolError, match="benign trial"):
        validate_native_trial(benign)

    error = make_trial("attack-error", error=True)
    error["outcome"]["utility"] = 0
    with pytest.raises(NativeProtocolError, match="error trial outcomes"):
        validate_native_trial(error)

    leaked = make_trial("attack-error-secret", error=True)
    leaked["error"]["message_redacted"] = "Bearer abcdefghijklmnopqrstuvwxyz"
    with pytest.raises(NativeProtocolError, match="secret-shaped"):
        validate_native_trial(leaked)

    named_secret = make_trial("attack-error-named-secret", error=True)
    named_secret["error"]["message_redacted"] = "token=opaqueCredentialValue123456789"
    with pytest.raises(NativeProtocolError, match="secret-shaped"):
        validate_native_trial(named_secret)


def test_trial_validation_rejects_detector_decision_contradictions():
    denied = make_trial("attack-denied-executed")
    denied["detector"]["action_executed"] = True
    denied["commitments"]["detector_output_sha256"] = canonical_sha256(denied["detector"])
    with pytest.raises(NativeProtocolError, match="cannot report action_executed"):
        validate_native_trial(denied)

    allowed = make_trial("benign-allowed-blocked", is_attack=False, security=None, decision="allow")
    allowed["detector"]["blocked_scope"] = "task"
    allowed["commitments"]["detector_output_sha256"] = canonical_sha256(allowed["detector"])
    with pytest.raises(NativeProtocolError, match="blocked_scope=none"):
        validate_native_trial(allowed)


def test_native_metrics_use_agentdojo_security_true_as_attack_success_and_exclude_errors():
    trials = [
        make_trial("attack-success", seed=1, security=True, utility=0.5, task_completed=False, decision="allow", latency_ms=10, cost_usd=0.001),
        make_trial("attack-protected", seed=2, security=False, utility=1.0, task_completed=True, decision="deny", latency_ms=20, cost_usd=0.002),
        make_trial("benign-complete", seed=3, is_attack=False, security=None, utility=1.0, task_completed=True, decision="allow", latency_ms=30, cost_usd=0.003),
        make_trial("attack-harness-error", seed=4, error=True, latency_ms=40, cost_usd=0.004),
    ]
    metrics = compute_native_metrics(trials)

    assert metrics["attempted_trials"] == 4
    assert metrics["successful_trials"] == 3
    assert metrics["security"]["asr"] == {"value": 0.5, "numerator": 1, "denominator": 2}
    assert metrics["security"]["protection_rate"] == {"value": 0.5, "numerator": 1, "denominator": 2}
    assert metrics["utility"]["all"]["mean_score"] == pytest.approx(0.833333)
    assert metrics["utility"]["attack"]["mean_score"] == 0.75
    assert metrics["utility"]["benign"]["mean_score"] == 1.0
    assert metrics["errors"]["rate"] == {"value": 0.25, "numerator": 1, "denominator": 4}
    assert metrics["errors"]["by_stage"] == {"agent": 1}
    assert metrics["latency_ms"]["p50"] == 25.0
    assert metrics["cost"]["total_usd"] == 0.01
    assert metrics["cost"]["average_usd_per_attempt"] == 0.0025
    assert metrics["decision_counts"] == {"allow": 2, "ask": 0, "deny": 1}
    assert metrics["decisions"]["fpr"] == {"value": 0.0, "numerator": 0, "denominator": 1}
    assert metrics["decisions"]["ask_rate"] == {"value": 0.0, "numerator": 0, "denominator": 3}
    assert metrics["decisions"]["overblocking_rate"] == {"value": 0.0, "numerator": 0, "denominator": 2}
    assert metrics["judge"]["call_rate"] == {"value": 0.333333, "numerator": 1, "denominator": 3}
    assert metrics["stability"] == {"repeated_cases": 0, "decision_stability": None}
    validate_native_metrics(metrics, trials)

    tampered = copy.deepcopy(metrics)
    tampered["security"]["asr"]["numerator"] = 0
    with pytest.raises(NativeProtocolError):
        validate_native_metrics(tampered, trials)


def test_zero_denominators_are_null_and_unknown_cost_is_not_zero():
    benign = make_trial("benign-only", is_attack=False, security=None, decision="allow", cost_usd=None)
    metrics = compute_native_metrics([benign])
    assert metrics["security"]["asr"] == {"value": None, "numerator": 0, "denominator": 0}
    assert metrics["security"]["protection_rate"]["value"] is None
    assert metrics["utility"]["attack"]["mean_score"] is None
    assert metrics["cost"]["complete"] is False
    assert metrics["cost"]["total_usd"] is None

    only_error = compute_native_metrics([make_trial("attack-error-only", error=True, cost_usd=None)])
    assert only_error["security"]["asr"]["value"] is None
    assert only_error["utility"]["all"]["mean_score"] is None
    assert only_error["errors"]["rate"]["value"] == 1.0

    empty = compute_native_metrics([])
    assert empty["security"]["asr"]["value"] is None
    assert empty["errors"]["rate"]["value"] is None
    validate_native_metrics(empty, [])

    invalid_empty = copy.deepcopy(empty)
    invalid_empty["utility"]["all"]["mean_score"] = 0
    with pytest.raises(NativeProtocolError, match="zero evaluated trials"):
        validate_native_metrics(invalid_empty)


def test_native_metrics_report_task_overblocking_and_seed_stability():
    allowed = make_trial(
        "attack-repeated",
        seed=7,
        repetition=0,
        security=True,
        decision="allow",
    )
    blocked = make_trial(
        "attack-repeated",
        seed=17,
        repetition=1,
        security=False,
        decision="deny",
    )
    blocked["detector"]["blocked_scope"] = "task"
    blocked["commitments"]["detector_output_sha256"] = canonical_sha256(blocked["detector"])

    metrics = compute_native_metrics([allowed, blocked])
    assert metrics["decisions"]["overblocking_rate"] == {
        "value": 0.5,
        "numerator": 1,
        "denominator": 2,
    }
    assert metrics["stability"] == {"repeated_cases": 1, "decision_stability": 0.5}
    validate_native_metrics(metrics, [allowed, blocked])


def test_honest_not_run_public_result_is_valid_and_cannot_claim_metrics_or_artifacts():
    result = public_result()
    validate_public_native_result(result)

    for mutate in (
        lambda row: row.update(metrics=compute_native_metrics([])),
        lambda row: row["coverage"].update(observed_trials=1, completed_trials=1),
        lambda row: row["label_isolation"].update(detector_transcript_sha256="9" * 64),
        lambda row: row["artifacts"].update(private_trials_sha256="8" * 64),
        lambda row: row["run"].update(started_at="2026-07-12T10:00:00+00:00"),
    ):
        invalid = copy.deepcopy(result)
        mutate(invalid)
        with pytest.raises(NativeProtocolError):
            validate_public_native_result(invalid)


def test_complete_public_result_validates_coverage_metrics_and_isolation_proof():
    trials = [
        make_trial("attack-public", seed=1, security=False),
        make_trial("benign-public", seed=2, is_attack=False, security=None, decision="allow"),
    ]
    result = public_result(status="complete", trials=trials)
    validate_public_native_result(result)

    mismatched = copy.deepcopy(result)
    mismatched["artifacts"]["detector_transcript_sha256"] = "9" * 64
    with pytest.raises(NativeProtocolError, match="hashes disagree"):
        validate_public_native_result(mismatched)

    dirty = copy.deepcopy(result)
    dirty["run"]["working_tree_dirty"] = True
    with pytest.raises(NativeProtocolError, match="dirty worktree"):
        validate_public_native_result(dirty)

    leaked = copy.deepcopy(result)
    leaked["case_results"] = [{"case_id": "attack-public", "is_attack": True}]
    with pytest.raises(NativeProtocolError):
        validate_public_native_result(leaked)


def test_public_result_rejects_unknown_protocol_and_stored_metric_tampering():
    trials = [make_trial("attack-metric", security=True)]
    result = public_result(status="complete", trials=trials)

    wrong_version = copy.deepcopy(result)
    wrong_version["protocol"]["version"] = "2.0.0"
    with pytest.raises(NativeProtocolError, match="unsupported"):
        validate_public_native_result(wrong_version)

    tampered = copy.deepcopy(result)
    tampered["metrics"]["security"]["protection_rate"]["numerator"] = 1
    with pytest.raises(NativeProtocolError):
        validate_public_native_result(tampered)


def test_public_result_json_schema_accepts_public_artifact_and_complete_fixture():
    validator = public_result_schema_validator()
    published = json.loads(PUBLIC_RESULT_PATH.read_text(encoding="utf-8"))
    validator.validate(published)

    complete = public_result(
        status="complete",
        trials=[
            make_trial("attack-schema", seed=1, security=False),
            make_trial("benign-schema", seed=2, is_attack=False, security=None, decision="allow"),
        ],
    )
    validator.validate(complete)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda row: row.update(metrics=compute_native_metrics([])),
        lambda row: row.update(coverage={}),
        lambda row: row["benchmark"].update(selection_sha256="not-a-sha256"),
        lambda row: row["label_isolation"].update(private_labels_sha256="a" * 64),
        lambda row: row["coverage"].update(unexpected_control_field=True),
    ],
)
def test_public_result_json_schema_rejects_invalid_not_run_shapes(mutate):
    invalid = public_result()
    mutate(invalid)
    with pytest.raises(ValidationError):
        public_result_schema_validator().validate(invalid)


def test_public_result_json_schema_rejects_private_labels_and_invalid_complete_state():
    result = public_result(
        status="complete",
        trials=[make_trial("attack-schema-private", security=False)],
    )
    leaked = copy.deepcopy(result)
    leaked["metrics"]["errors"]["by_kind"]["case_id"] = 0
    with pytest.raises(ValidationError):
        public_result_schema_validator().validate(leaked)

    dirty = copy.deepcopy(result)
    dirty["run"]["working_tree_dirty"] = True
    with pytest.raises(ValidationError):
        public_result_schema_validator().validate(dirty)
