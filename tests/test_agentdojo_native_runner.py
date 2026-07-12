from __future__ import annotations

from pathlib import Path

import pytest

from scripts import run_agentdojo_native as native


class FakeBridge:
    def __init__(self):
        self.messages = []

    def request(self, message):
        self.messages.append(message)
        return {"decision": "allow", "summary": "fixture"}


def test_frozen_selection_is_exactly_40_cases_by_three_seeds():
    selection = native.load_selection(Path("evaluation/native/agentdojo_selection.json"))
    specs = native.build_trial_specs(selection)

    assert len(specs) == 120
    assert sum(not spec.is_attack for spec in specs) == 60
    assert sum(spec.is_attack for spec in specs) == 60
    assert len({(spec.case_id, spec.seed) for spec in specs}) == 120
    assert {spec.seed for spec in specs} == {7, 17, 29}


def test_recording_bridge_keeps_routing_outside_the_five_field_detector_input():
    inner = FakeBridge()
    events = []
    bridge = native.RecordingBridge(inner, events)
    payload = {
        "user_message": "Create a ticket with the requested category.",
        "tool_name": "create_ticket",
        "tool_args": {"category": "security", "label": "urgent"},
        "tool_result": None,
        "session_history": [],
    }

    result = bridge.request(
        {
            "op": "before_tool",
            "session_id": "trial_0123456789abcdef01234567",
            "call_id": "call_00000001",
            "payload": payload,
        }
    )

    assert result["decision"] == "allow"
    assert set(events[0]["detector_input"]) == set(native.DETECTOR_PAYLOAD_FIELDS)
    assert events[0]["detector_input"]["tool_args"]["category"] == "security"
    assert events[0]["routing"]["opaque_session_id"].startswith("trial_")
    assert "case_id" not in str(events[0])
    assert "is_attack" not in str(events[0])


def test_recording_bridge_rejects_extra_evaluator_envelope_fields():
    bridge = native.RecordingBridge(FakeBridge(), [])
    with pytest.raises(native.NativeSetupError, match="invalid payload"):
        bridge.request(
            {
                "op": "before_tool",
                "session_id": "trial_0123456789abcdef01234567",
                "call_id": "call_00000001",
                "payload": {
                    "user_message": "task",
                    "tool_name": "tool",
                    "tool_args": {},
                    "tool_result": None,
                    "session_history": [],
                    "is_attack": True,
                },
            }
        )


def test_detector_summary_distinguishes_precise_intervention_from_task_block():
    allowed_then_denied = native.summarize_detector(
        [
            {"decision": "allow", "executed": True, "detector_result": {}},
            {"decision": "deny", "executed": False, "detector_result": {}},
        ],
        status="ok",
    )
    denied_first = native.summarize_detector(
        [{"decision": "ask", "executed": False, "detector_result": {}}],
        status="ok",
    )

    assert allowed_then_denied == {
        "decision": "deny",
        "blocked_scope": "action",
        "action_executed": False,
        "llm_judge_called": False,
    }
    assert denied_first["blocked_scope"] == "task"
    assert native.summarize_detector([], status="error") is None


def test_model_credential_preflight_is_explicit(monkeypatch):
    for name in ("OPENAI_API_KEY", "OPENAI_COMPATIBLE_BASE_URL", "OPENAI_COMPATIBLE_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(native.NativeSetupError, match="OPENAI_API_KEY"):
        native.ensure_model_credentials("gpt-4o-mini-2024-07-18", None)
    with pytest.raises(native.NativeSetupError, match="model-id"):
        native.ensure_model_credentials("openai-compatible", None)

    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("OPENAI_COMPATIBLE_API_KEY", "fixture")
    native.ensure_model_credentials("openai-compatible", "fixture-model")


def test_missing_optional_dependency_returns_setup_exit_without_model_access(monkeypatch, capsys):
    def missing():
        raise native.NativeSetupError(
            'AgentDojo native support is not installed; run: python -m pip install -e ".[native-agentdojo]"'
        )

    monkeypatch.setattr(native, "load_agentdojo_api", missing)
    assert native.main(["--doctor"]) == 2
    assert "native-agentdojo" in capsys.readouterr().err
