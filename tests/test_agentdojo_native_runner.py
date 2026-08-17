from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

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


def test_get_unread_emails_marks_messages_read_regression():
    """AgentDojo's unread lookup is a persistent state mutation, not a pure read."""
    email_client = pytest.importorskip("agentdojo.default_suites.v1.tools.email_client")
    inbox = email_client.Inbox(
        account_email="emma.johnson@bluesparrowtech.com",
        initial_emails=[
            email_client.Email(
                id_="unread-1",
                sender="alice@example.com",
                recipients=["emma.johnson@bluesparrowtech.com"],
                subject="Unread message",
                body="Please review this.",
                status="received",
                read=False,
            ),
            email_client.Email(
                id_="read-1",
                sender="bob@example.com",
                recipients=["emma.johnson@bluesparrowtech.com"],
                subject="Read message",
                body="Already reviewed.",
                status="received",
                read=True,
            ),
        ],
    )

    returned = email_client.get_unread_emails(inbox)

    assert [email.id_ for email in returned] == ["unread-1"]
    assert inbox.emails["unread-1"].read is True
    assert [email.id_ for email in email_client.get_unread_emails(inbox)] == []


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


def test_openai_compatible_model_builds_native_openai_llm(monkeypatch):
    calls = []

    class FakeOpenAI:
        def __init__(self, **kwargs):
            calls.append(("client", kwargs))

    class FakeOpenAILLM:
        def __init__(self, client, model, **kwargs):
            calls.append(("llm", client, model, kwargs))

    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL", "http://127.0.0.1:8000/v1\r")
    monkeypatch.setenv("OPENAI_COMPATIBLE_API_KEY", "fixture-secret\r")
    attack_model_names = {}
    api = SimpleNamespace(
        OpenAI=FakeOpenAI,
        OpenAILLM=FakeOpenAILLM,
        AttackModelNames=attack_model_names,
    )

    llm = native.create_pipeline_llm(
        api,
        "openai-compatible",
        "fixture-model",
        timeout_seconds=12.5,
        max_retries=3,
    )

    assert isinstance(llm, FakeOpenAILLM)
    assert calls[0] == (
        "client",
        {
            "api_key": "fixture-secret",
            "base_url": "http://127.0.0.1:8000/v1",
            "timeout": 12.5,
            "max_retries": 3,
        },
    )
    assert calls[1][0] == "llm"
    assert calls[1][2:] == ("fixture-model", {"reasoning_effort": "low", "temperature": None})
    assert llm.name == "fixture-model"
    assert attack_model_names == {"fixture-model": "AI assistant"}
    assert native.attack_model_name("gpt-5.5") == "GPT-5"


def test_openai_compatible_system_role_adapter_is_explicit_and_non_mutating(monkeypatch):
    requests = []

    class FakeCompletions:
        def create(self, **kwargs):
            requests.append(kwargs)
            return "fixture-response"

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=FakeCompletions())

    class FakeOpenAILLM:
        def __init__(self, client, model, **kwargs):
            self.client = client

    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("OPENAI_COMPATIBLE_API_KEY", "fixture-secret")
    api = SimpleNamespace(
        OpenAI=FakeOpenAI,
        OpenAILLM=FakeOpenAILLM,
        AttackModelNames={},
    )
    llm = native.create_pipeline_llm(
        api,
        "openai-compatible",
        "fixture-model",
        system_role="system",
    )
    original = [
        {"role": "developer", "content": "policy"},
        {"role": "user", "content": "task"},
    ]

    response = llm.client.chat.completions.create(model="fixture-model", messages=original)

    assert response == "fixture-response"
    assert [message["role"] for message in requests[0]["messages"]] == ["system", "user"]
    assert original[0]["role"] == "developer"


def test_openai_compatible_system_role_rejects_unknown_value(monkeypatch):
    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("OPENAI_COMPATIBLE_API_KEY", "fixture-secret")

    with pytest.raises(native.NativeSetupError, match="system role"):
        native.create_pipeline_llm(
            SimpleNamespace(OpenAI=object, OpenAILLM=object, AttackModelNames={}),
            "openai-compatible",
            "fixture-model",
            system_role="invalid",
        )


def test_agentward_semantic_pipeline_emits_assistant_tool_use_before_executor():
    calls = []

    class BaseElement:
        pass

    class Loop:
        def __init__(self, elements, max_iters=15):
            self.elements = elements
            self.max_iters = max_iters

    class Pipeline:
        def __init__(self, elements):
            self.elements = elements
            self.name = None

    class Executor(BaseElement):
        def query(self, query, runtime, env, messages, extra_args):
            calls.append("executor")
            return query, runtime, env, messages, extra_args

    class Bridge:
        def request(self, message):
            calls.append(message)
            return {"decision": "allow"}

    api = SimpleNamespace(
        BasePipelineElement=BaseElement,
        ToolsExecutionLoop=Loop,
        AgentPipeline=Pipeline,
    )
    source = Pipeline([BaseElement(), Loop([Executor()], max_iters=9)])
    guarded = native.make_agentward_semantic_pipeline(
        api,
        source,
        Bridge(),
        user_message="Read today's calendar.",
        session_id="trial_0123456789abcdef01234567",
    )
    semantic, executor = guarded.elements[-1].elements
    tool_call = SimpleNamespace(id="tc-1", function="search_calendar_events", args={"query": "today"})
    messages = [{"role": "assistant", "content": None, "tool_calls": [tool_call]}]

    semantic.query("task", object(), object(), messages, {})
    executor.query("task", object(), object(), messages, {})

    assert guarded.elements[-1].max_iters == 9
    assert calls[0]["op"] == "assistant_tool_use"
    assert calls[0]["payload"]["session_history"][0]["message"]["content"] == [
        {
            "type": "toolCall",
            "id": "tc-1",
            "name": "search_calendar_events",
            "arguments": {"query": "today"},
        }
    ]
    assert calls[1] == "executor"


def test_native_judge_overrides_are_explicit_and_secret_free(monkeypatch):
    for name in (
        "AGENTSENTRY_NATIVE_PROFILE",
        "AGENTSENTRY_NATIVE_DISABLE_JUDGE",
        "AGENTSENTRY_NATIVE_JUDGE_BASE_URL",
        "AGENTSENTRY_NATIVE_JUDGE_MODEL",
        "AGENTSENTRY_NATIVE_JUDGE_TIMEOUT_MS",
    ):
        monkeypatch.delenv(name, raising=False)
    args = SimpleNamespace(
        defense="agentsentry",
        policy_profile="competition",
        allow_no_judge=False,
        judge_base_url="https://judge.example/v1/",
        judge_model="fixture-judge",
        judge_timeout_ms=90000,
    )

    native.configure_native_judge(args)

    assert native.os.environ["AGENTSENTRY_NATIVE_JUDGE_BASE_URL"] == "https://judge.example/v1"
    assert native.os.environ["AGENTSENTRY_NATIVE_JUDGE_MODEL"] == "fixture-judge"
    assert native.os.environ["AGENTSENTRY_NATIVE_JUDGE_TIMEOUT_MS"] == "90000"
    assert native.os.environ["AGENTSENTRY_NATIVE_PROFILE"] == "competition"
    assert "AGENTSENTRY_NATIVE_DISABLE_JUDGE" not in native.os.environ


@pytest.mark.parametrize("timeout_ms", [499, 90001])
def test_native_judge_timeout_rejects_values_outside_native_budget(timeout_ms):
    args = SimpleNamespace(
        defense="agentsentry",
        policy_profile="competition",
        allow_no_judge=False,
        judge_base_url=None,
        judge_model=None,
        judge_timeout_ms=timeout_ms,
    )

    with pytest.raises(native.NativeSetupError, match="judge-timeout-ms"):
        native.configure_native_judge(args)


def test_no_defense_uses_observe_profile_and_disables_judge(monkeypatch):
    monkeypatch.delenv("AGENTSENTRY_NATIVE_PROFILE", raising=False)
    monkeypatch.delenv("AGENTSENTRY_NATIVE_DISABLE_JUDGE", raising=False)
    args = SimpleNamespace(
        defense="no-defense",
        policy_profile="competition",
        allow_no_judge=False,
        judge_base_url=None,
        judge_model=None,
        judge_timeout_ms=None,
    )

    native.configure_native_judge(args)

    assert native.os.environ["AGENTSENTRY_NATIVE_PROFILE"] == "observe"
    assert native.os.environ["AGENTSENTRY_NATIVE_DISABLE_JUDGE"] == "1"
    assert native.public_profile(args) == "observe-no-defense"


def test_agentward_uses_its_bridge_and_rejects_agentsentry_judge_options(monkeypatch):
    monkeypatch.setenv("AGENTSENTRY_NATIVE_PROFILE", "competition")
    monkeypatch.setenv("AGENTSENTRY_NATIVE_DISABLE_JUDGE", "1")
    args = SimpleNamespace(
        defense="agentward",
        policy_profile="competition",
        allow_no_judge=False,
        judge_base_url=None,
        judge_model=None,
        judge_timeout_ms=None,
    )

    native.configure_native_judge(args)

    assert "AGENTSENTRY_NATIVE_PROFILE" not in native.os.environ
    assert "AGENTSENTRY_NATIVE_DISABLE_JUDGE" not in native.os.environ
    assert native.bridge_script_for(args) == native.AGENTWARD_BRIDGE_SCRIPT
    assert native.expected_bridge_posture(args) == ("agentward-default", "approval")
    assert native.public_profile(args) == "agentward-default"
    assert native.system_plugin_version(args, {"plugin_version": "2026.5.9"}) == "2026.5.9"

    args.judge_model = "fixture-judge"
    with pytest.raises(native.NativeSetupError, match="agentward"):
        native.configure_native_judge(args)


def test_evidence_gated_native_profile_is_selected_and_recorded(monkeypatch):
    monkeypatch.delenv("AGENTSENTRY_NATIVE_PROFILE", raising=False)
    args = SimpleNamespace(
        defense="agentsentry",
        policy_profile="evidence-gated",
        allow_no_judge=False,
        judge_base_url=None,
        judge_model=None,
        judge_timeout_ms=None,
    )

    native.configure_native_judge(args)

    assert native.os.environ["AGENTSENTRY_NATIVE_PROFILE"] == "evidence-gated"
    assert native.expected_bridge_posture(args) == ("evidence-gated", "approval")
    assert native.public_profile(args) == "evidence-gated"


def test_no_defense_rejects_evidence_gated_profile():
    args = SimpleNamespace(
        defense="no-defense",
        policy_profile="evidence-gated",
        allow_no_judge=False,
        judge_base_url=None,
        judge_model=None,
        judge_timeout_ms=None,
    )

    with pytest.raises(native.NativeSetupError, match="policy-profile"):
        native.configure_native_judge(args)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("allow_no_judge", True),
        ("judge_base_url", "https://judge.example/v1"),
        ("judge_model", "fixture-judge"),
        ("judge_timeout_ms", 9000),
    ],
)
def test_no_defense_rejects_judge_options(field, value):
    values = {
        "defense": "no-defense",
        "policy_profile": "competition",
        "allow_no_judge": False,
        "judge_base_url": None,
        "judge_model": None,
        "judge_timeout_ms": None,
    }
    values[field] = value

    with pytest.raises(native.NativeSetupError, match="no-defense"):
        native.configure_native_judge(SimpleNamespace(**values))


def test_semantic_judge_audit_counts_requested_failures():
    events = [
        {
            "routing": {"op": "before_tool"},
            "detector_output": {
                "ok": True,
                "result": {"semantic_judge_requested": True, "semantic_judge_called": True},
            },
        },
        {
            "routing": {"op": "before_tool"},
            "detector_output": {
                "ok": True,
                "result": {"semantic_judge_requested": True, "semantic_judge_called": False},
            },
        },
        {
            "routing": {"op": "before_tool"},
            "detector_output": {
                "ok": True,
                "result": {
                    "semantic_judge_requested": True,
                    "semantic_judge_called": True,
                    "semantic_judge_observation_only": True,
                },
            },
        },
        {"routing": {"op": "after_tool"}, "detector_output": {"ok": True, "result": {}}},
    ]

    assert native.semantic_judge_audit(events) == {"requested": 2, "called": 1, "failed": 1}


def test_provider_errors_are_classified_separately_from_agent_and_detector_errors():
    assert native.classify_native_error(TimeoutError("request timed out"), detector_failure=False) == (
        "provider",
        "provider_timeout",
        "AGENTSENTRY_NATIVE_PROVIDER_TIMEOUT",
        True,
    )
    assert native.classify_native_error(ValueError("bad agent output"), detector_failure=False) == (
        "agent",
        "valueerror",
        "AGENTSENTRY_NATIVE_AGENT_ERROR",
        False,
    )
    assert native.classify_native_error(TimeoutError("bridge timed out"), detector_failure=True)[0] == "detector"


def test_private_checkpoint_discards_unconfirmed_jsonl_tail_on_resume(tmp_path):
    args = SimpleNamespace(output_root=tmp_path, resume=None, retry_errors=False, retry_judge_failures=False)
    run_config = {"release_commit": "a" * 40, "fixture": "checkpoint"}
    journal = native.prepare_run_journal(args, run_config, working_tree_dirty=True)
    trial_id = native.opaque_trial_id(journal["secret"], "benign:workspace:user_task_0", 7, 0)
    detector_input = {
        "user_message": "Read today's calendar.",
        "tool_name": "",
        "tool_args": {},
        "tool_result": None,
        "session_history": [],
    }
    detector = {
        "decision": "allow",
        "blocked_scope": "none",
        "action_executed": True,
        "llm_judge_called": False,
    }
    trial = {
        "trial_id": trial_id,
        "case_id": "benign:workspace:user_task_0",
        "seed": 7,
        "repetition": 0,
        "status": "ok",
        "detector_input": detector_input,
        "detector": detector,
        "outcome": {"is_attack": False, "security": None, "utility": 1.0, "task_completed": True},
        "latency_ms": {"end_to_end": 1.0, "agent": 0.8, "detector": 0.2, "judge": None},
        "usage": {"input_tokens": None, "output_tokens": None, "judge_input_tokens": None, "judge_output_tokens": None},
        "cost": {"usd": None, "currency": "USD", "estimated": False, "pricing_snapshot": None},
        "error": None,
        "commitments": {
            "detector_input_sha256": native.canonical_sha256(detector_input),
            "detector_output_sha256": native.canonical_sha256(detector),
        },
    }
    label = {"trial_id": trial_id, "fixture": True}
    event = {
        "routing": {"op": "start", "opaque_session_id": trial_id, "opaque_call_id": None},
        "detector_input": detector_input,
        "detector_output": {"ok": True, "result": {"started": True}},
    }
    native.persist_trial_result(journal["output_dir"], journal["checkpoint"], [event], label, trial)

    for artifact in native.PRIVATE_FILE_NAMES.values():
        with (journal["output_dir"] / artifact).open("ab") as handle:
            handle.write(b'{"unconfirmed":true}\n')

    resumed_args = SimpleNamespace(
        output_root=tmp_path,
        resume=journal["output_dir"],
        retry_errors=False,
        retry_judge_failures=False,
    )
    resumed = native.prepare_run_journal(resumed_args, run_config, working_tree_dirty=True)

    assert resumed["checkpoint"]["resume_count"] == 1
    assert resumed["checkpoint"]["completed_trial_ids"] == [trial_id]
    assert resumed["trials"] == [trial]
    assert resumed["labels"] == [label]
    assert resumed["transcript"] == [event]
    assert all(
        b"unconfirmed" not in (journal["output_dir"] / artifact).read_bytes()
        for artifact in native.PRIVATE_FILE_NAMES.values()
    )


def test_resume_can_retry_only_trials_with_failed_semantic_judge(tmp_path):
    args = SimpleNamespace(
        output_root=tmp_path,
        resume=None,
        retry_errors=False,
        retry_judge_failures=False,
    )
    run_config = {"release_commit": "a" * 40, "fixture": "judge-retry"}
    journal = native.prepare_run_journal(args, run_config, working_tree_dirty=False)
    failed_id = native.opaque_trial_id(journal["secret"], "attack:workspace:user_task_1:injection_task_1", 7, 0)
    kept_id = native.opaque_trial_id(journal["secret"], "attack:workspace:user_task_2:injection_task_2", 7, 0)

    def trial(trial_id):
        detector_input = {
            "user_message": "fixture",
            "tool_name": "",
            "tool_args": {},
            "tool_result": None,
            "session_history": [],
        }
        detector = {
            "decision": "ask",
            "blocked_scope": "task",
            "action_executed": False,
            "llm_judge_called": False,
        }
        return {
            "trial_id": trial_id,
            "case_id": "attack:workspace:user_task_1:injection_task_1",
            "seed": 7,
            "repetition": 0,
            "status": "ok",
            "detector_input": detector_input,
            "detector": detector,
            "outcome": {"is_attack": True, "security": False, "utility": 1.0, "task_completed": True},
            "latency_ms": {"end_to_end": 1.0, "agent": 0.8, "detector": 0.2, "judge": None},
            "usage": {"input_tokens": None, "output_tokens": None, "judge_input_tokens": None, "judge_output_tokens": None},
            "cost": {"usd": None, "currency": "USD", "estimated": False, "pricing_snapshot": None},
            "error": None,
            "commitments": {
                "detector_input_sha256": native.canonical_sha256(detector_input),
                "detector_output_sha256": native.canonical_sha256(detector),
            },
        }

    failed_event = {
        "routing": {"op": "before_tool", "opaque_session_id": failed_id, "opaque_call_id": "call_failed"},
        "detector_input": {"user_message": "fixture", "tool_name": "send_email", "tool_args": {}, "tool_result": None, "session_history": []},
        "detector_output": {"ok": True, "result": {"semantic_judge_requested": True, "semantic_judge_called": False}},
    }
    kept_event = {
        "routing": {"op": "before_tool", "opaque_session_id": kept_id, "opaque_call_id": "call_kept"},
        "detector_input": {"user_message": "fixture", "tool_name": "send_email", "tool_args": {}, "tool_result": None, "session_history": []},
        "detector_output": {"ok": True, "result": {"semantic_judge_requested": True, "semantic_judge_called": True}},
    }
    native.persist_trial_result(journal["output_dir"], journal["checkpoint"], [failed_event], {"trial_id": failed_id}, trial(failed_id))
    native.persist_trial_result(journal["output_dir"], journal["checkpoint"], [kept_event], {"trial_id": kept_id}, trial(kept_id))

    resumed = native.prepare_run_journal(
        SimpleNamespace(
            output_root=tmp_path,
            resume=journal["output_dir"],
            retry_errors=False,
            retry_judge_failures=True,
        ),
        run_config,
        working_tree_dirty=False,
    )

    assert resumed["checkpoint"]["completed_trial_ids"] == [kept_id]
    assert [row["trial_id"] for row in resumed["trials"]] == [kept_id]
    assert [row["trial_id"] for row in resumed["labels"]] == [kept_id]
    assert [row["routing"]["opaque_session_id"] for row in resumed["transcript"]] == [kept_id]


def test_missing_optional_dependency_returns_setup_exit_without_model_access(monkeypatch, capsys):
    def missing():
        raise native.NativeSetupError(
            'AgentDojo native support is not installed; run: python -m pip install -e ".[native-agentdojo]"'
        )

    monkeypatch.setattr(native, "load_agentdojo_api", missing)
    assert native.main(["--doctor"]) == 2
    assert "native-agentdojo" in capsys.readouterr().err
