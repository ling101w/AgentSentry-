from __future__ import annotations

import copy
import json
import queue
import subprocess
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from agentsentry.agentdojo_adapter import (
    AgentSentryBridgeClosedError,
    AgentSentryBridgeProtocolError,
    AgentSentryBridgeRemoteError,
    AgentSentryBridgeTimeoutError,
    AgentSentryDeniedError,
    DETECTOR_PAYLOAD_FIELDS,
    JsonlNodeBridgeClient,
    make_guarded_runtime_class,
)


class FakeRuntime:
    def __init__(self, functions=()) -> None:
        self.functions = functions
        self.base_calls: list[dict[str, Any]] = []

    def run_function(
        self,
        env: Any,
        function: str,
        kwargs: Mapping[str, Any],
        raise_on_error: bool = False,
    ) -> tuple[Any, str | None]:
        self.base_calls.append(
            {
                "env": env,
                "function": function,
                "kwargs": dict(kwargs),
                "raise_on_error": raise_on_error,
            }
        )
        return {"function": function, "args": dict(kwargs)}, None


class ScriptedBridge:
    def __init__(self, handler: Callable[[dict[str, Any]], Mapping[str, Any]]) -> None:
        self.handler = handler
        self.messages: list[dict[str, Any]] = []

    def request(self, message: Mapping[str, Any]) -> Mapping[str, Any]:
        detached = copy.deepcopy(dict(message))
        self.messages.append(detached)
        return self.handler(detached)


def _allowing_bridge() -> ScriptedBridge:
    def handler(message):
        if message["op"] == "start":
            return {"started": True}
        if message["op"] == "end":
            return {"ended": True}
        if message["op"] == "before_tool":
            return {"decision": "allow", "summary": "explicit capability"}
        return {"findings": []}

    return ScriptedBridge(handler)


def _decision_bridge(decision: str, reason: str = "approval required") -> ScriptedBridge:
    def handler(message):
        if message["op"] == "start":
            return {"started": True}
        if message["op"] == "end":
            return {"ended": True}
        if message["op"] == "before_tool":
            return {"decision": decision, "summary": reason}
        return {"findings": []}

    return ScriptedBridge(handler)


def test_guarded_runtime_executes_only_allow_and_feeds_back_real_result():
    bridge = _allowing_bridge()
    runtime_class = make_guarded_runtime_class(
        FakeRuntime,
        bridge,
        user_message="Send report.md to teacher@example.edu",
        session_id="trial_0123456789abcdef01234567",
    )
    runtime = runtime_class(["send_email"])

    result, error = runtime.run_function(
        None,
        "send_email",
        {"recipient": "teacher@example.edu", "body": "report"},
    )

    assert error is None
    assert result == {
        "function": "send_email",
        "args": {"recipient": "teacher@example.edu", "body": "report"},
    }
    assert [call["function"] for call in runtime.base_calls] == ["send_email"]
    assert [message["op"] for message in bridge.messages] == ["start", "before_tool", "after_tool"]
    assert bridge.messages[2]["payload"]["tool_result"] == result
    assert bridge.messages[1]["call_id"] == "call_00000001"
    assert bridge.messages[2]["call_id"] == "call_00000001"
    record = runtime.agentsentry_records[0]
    assert runtime.records is runtime.agentsentry_records
    assert record["decision"] == "allow"
    assert record["executed"] is True
    assert record["after_feedback"] == "received"
    assert record["latency_ms"] >= 0
    assert record["after_latency_ms"] >= 0
    assert runtime.end() == {"ended": True}
    assert bridge.messages[-1] == {
        "op": "end",
        "session_id": "trial_0123456789abcdef01234567",
    }


@pytest.mark.parametrize("decision", ["ask", "deny"])
def test_guarded_runtime_does_not_execute_ask_or_deny(decision):
    bridge = _decision_bridge(decision)
    runtime = make_guarded_runtime_class(
        FakeRuntime,
        bridge,
        user_message="Process the report",
    )()

    result, error = runtime.run_function(None, "send_email", {"recipient": "x@example.test"})

    assert result == ""
    assert error.startswith(f"AgentSentryDenied: {decision} send_email")
    assert runtime.base_calls == []
    assert runtime.records[0]["executed"] is False
    assert runtime.records[0]["decision"] == decision
    assert [message["op"] for message in bridge.messages] == ["start", "before_tool"]


def test_denial_raises_custom_error_when_nested_execution_requests_errors():
    bridge = _decision_bridge("deny", "outside TaskSpec")
    runtime = make_guarded_runtime_class(
        FakeRuntime,
        bridge,
        user_message="Summarize the page",
    )()

    with pytest.raises(AgentSentryDeniedError) as captured:
        runtime.run_function(None, "send_email", {}, raise_on_error=True)

    assert captured.value.tool_name == "send_email"
    assert captured.value.decision == "deny"
    assert runtime.base_calls == []


@pytest.mark.parametrize(
    "handler, expected_error",
    [
        (lambda _message: (_ for _ in ()).throw(TimeoutError("slow detector")), "TimeoutError"),
        (lambda _message: {"decision": "permit"}, "invalid decision"),
        (lambda _message: ["allow"], "before response must be a mapping"),
    ],
)
def test_bridge_failures_and_unknown_decisions_fail_closed(handler, expected_error):
    bridge = ScriptedBridge(
        lambda message: {"started": True} if message["op"] == "start" else handler(message)
    )
    runtime = make_guarded_runtime_class(
        FakeRuntime,
        bridge,
        user_message="Run the tool",
    )()

    result, error = runtime.run_function(None, "network_write", {"host": "example.test"})

    assert result == ""
    assert error.startswith("AgentSentryDenied: deny")
    assert runtime.base_calls == []
    record = runtime.records[0]
    assert record["decision"] == "deny"
    assert expected_error in record["bridge_error"]


def test_detector_payload_has_five_fields_and_opaque_session_is_transport_only():
    bridge = _allowing_bridge()
    opaque_session_id = "trial_0123456789abcdef01234567"
    initial_history = [{"role": "assistant", "content": "tool requested"}]
    runtime = make_guarded_runtime_class(
        FakeRuntime,
        bridge,
        user_message="Summarize the workspace document",
        session_id=opaque_session_id,
        session_history=initial_history,
    )()

    runtime.run_function(None, "read_document", {"document_id": "report-17"})

    start = bridge.messages[0]
    before = bridge.messages[1]
    payload = before["payload"]
    assert set(payload) == DETECTOR_PAYLOAD_FIELDS
    assert set(before) == {"op", "session_id", "call_id", "payload"}
    assert before["session_id"] == opaque_session_id
    assert before["call_id"] == "call_00000001"
    assert "session_id" not in payload
    assert payload["session_history"] == initial_history
    assert not ({"expected", "is_attack", "attack_type", "risk_level"} & set(payload))
    assert set(start["payload"]) == DETECTOR_PAYLOAD_FIELDS
    assert start["payload"]["tool_name"] == ""


def test_raw_benchmark_identity_is_rejected_instead_of_hashed_or_transmitted():
    bridge = _allowing_bridge()

    with pytest.raises(ValueError, match="trial_<24 to 64"):
        make_guarded_runtime_class(
            FakeRuntime,
            bridge,
            user_message="Summarize the workspace document",
            session_id="agentdojo:workspace:UserTask7:InjectionTask2",
        )

    assert bridge.messages == []


def test_runtime_instances_get_distinct_generated_session_ids():
    runtime_class = make_guarded_runtime_class(
        FakeRuntime,
        _allowing_bridge(),
        user_message="Read a report",
    )

    first = runtime_class()
    second = runtime_class()

    assert first.agentsentry_session_id.startswith("trial_")
    assert second.agentsentry_session_id.startswith("trial_")
    assert first.agentsentry_session_id != second.agentsentry_session_id


def test_legitimate_category_label_and_expected_business_arguments_are_allowed():
    bridge = _allowing_bridge()
    runtime = make_guarded_runtime_class(
        FakeRuntime,
        bridge,
        user_message="Run the tool",
    )()

    args = {"category": "security", "label": "urgent", "nested": {"expected": "business value"}}
    result, error = runtime.run_function(None, "tool", args)

    assert error is None
    assert result["args"] == args
    assert bridge.messages[1]["payload"]["tool_args"] == args
    assert runtime.base_calls[0]["kwargs"] == args


def test_after_failure_does_not_rewrite_an_already_executed_action_as_blocked():
    def handler(message):
        if message["op"] == "start":
            return {"started": True}
        if message["op"] == "before_tool":
            return {"decision": "allow"}
        raise AgentSentryBridgeProtocolError("bad after acknowledgement")

    bridge = ScriptedBridge(handler)
    runtime = make_guarded_runtime_class(
        FakeRuntime,
        bridge,
        user_message="Read the public report",
    )()

    result, error = runtime.run_function(None, "read_report", {"id": 7})

    assert error is None
    assert result["function"] == "read_report"
    record = runtime.records[0]
    assert record["decision"] == "allow"
    assert record["executed"] is True
    assert record["after_feedback"] == "error_after_execution"
    assert "bad after acknowledgement" in record["after_feedback_error"]


def test_history_from_an_allowed_call_is_available_to_the_next_decision():
    bridge = _allowing_bridge()
    runtime = make_guarded_runtime_class(
        FakeRuntime,
        bridge,
        user_message="Read and summarize two reports",
    )()

    runtime.run_function(None, "read_report", {"id": 1})
    runtime.run_function(None, "read_report", {"id": 2})

    second_before = bridge.messages[3]["payload"]
    assert second_before["session_history"][-1]["tool_name"] == "read_report"
    assert second_before["session_history"][-1]["executed"] is True


def test_external_record_sink_receives_completed_decisions_without_raw_case_ids():
    emitted: list[Mapping[str, Any]] = []
    bridge = _decision_bridge("deny", "outside TaskSpec")
    runtime = make_guarded_runtime_class(
        FakeRuntime,
        bridge,
        user_message="Summarize the report",
        session_id="trial_aaaaaaaaaaaaaaaaaaaaaaaa",
        record_sink=emitted.append,
    )()

    runtime.run_function(None, "send_email", {"recipient": "outside@example.test"})

    assert len(emitted) == 1
    assert emitted[0]["decision"] == "deny"
    assert emitted[0]["executed"] is False
    assert emitted[0]["session_id"] == "trial_aaaaaaaaaaaaaaaaaaaaaaaa"
    assert emitted[0]["call_id"] == "call_00000001"
    assert "AgentDojo" not in json.dumps(emitted[0])


class NestedRuntime:
    def __init__(self, functions=()) -> None:
        self.functions = functions
        self.entered: list[str] = []
        self.effects: list[str] = []

    def run_function(self, env, function, kwargs, raise_on_error=False):
        self.entered.append(function)
        if function == "parent_tool":
            try:
                child, _ = self.run_function(
                    env,
                    "child_tool",
                    {"secret": kwargs["secret"]},
                    raise_on_error=True,
                )
            except Exception as exc:
                if raise_on_error:
                    raise
                return "", f"{type(exc).__name__}: {exc}"
            self.effects.append("parent_tool")
            return child, None
        self.effects.append(function)
        return "child result", None


def test_nested_calls_reenter_guard_and_denied_child_prevents_parent_effect():
    def handler(message):
        if message["op"] == "start":
            return {"started": True}
        if message["op"] == "after_tool":
            return {"findings": []}
        decision = "deny" if message["payload"]["tool_name"] == "child_tool" else "allow"
        return {"decision": decision, "summary": "child not authorized"}

    bridge = ScriptedBridge(handler)
    runtime = make_guarded_runtime_class(
        NestedRuntime,
        bridge,
        user_message="Run only the parent operation",
    )()

    result, error = runtime.run_function(None, "parent_tool", {"secret": "value"})

    assert result == ""
    assert error.startswith("AgentSentryDeniedError:")
    assert runtime.entered == ["parent_tool"]
    assert runtime.effects == []
    assert [(row["tool_name"], row["decision"]) for row in runtime.records] == [
        ("parent_tool", "allow"),
        ("child_tool", "deny"),
    ]
    assert runtime.records[0]["executed"] is False
    assert runtime.records[1]["executed"] is False


class QueueStdout:
    def __init__(self) -> None:
        self.lines: queue.Queue[str] = queue.Queue()
        self.closed = False

    def readline(self) -> str:
        return self.lines.get()

    def feed(self, line: str) -> None:
        self.lines.put(line)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.feed("")


class CapturingStdin:
    def __init__(self, process: FakeProcess) -> None:
        self.process = process
        self.buffer = ""
        self.closed = False

    def write(self, data: str) -> int:
        if self.closed:
            raise BrokenPipeError("stdin is closed")
        self.buffer += data
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            request = json.loads(line)
            self.process.requests.append(request)
            self.process.on_request(request, self.process)
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class FakeProcess:
    def __init__(self, on_request: Callable[[dict[str, Any], FakeProcess], None]) -> None:
        self.on_request = on_request
        self.stdout = QueueStdout()
        self.stdin = CapturingStdin(self)
        self.requests: list[dict[str, Any]] = []
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15
        self.stdout.feed("")

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self.stdout.feed("")

    def wait(self, timeout=None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fake-node", timeout)
        return self.returncode


class FakeProcessFactory:
    def __init__(self, process: FakeProcess) -> None:
        self.process = process
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        return self.process


def _respond_with_decision(decision: str = "allow"):
    def responder(request: dict[str, Any], process: FakeProcess) -> None:
        process.stdout.feed(
            json.dumps({"id": request["id"], "ok": True, "result": {"decision": decision}}) + "\n"
        )

    return responder


def test_jsonl_client_correlates_unique_ids_and_keeps_one_process_alive():
    process = FakeProcess(_respond_with_decision())
    factory = FakeProcessFactory(process)
    with JsonlNodeBridgeClient(["node", "bridge.mjs"], process_factory=factory) as client:
        first = client.request({"op": "ping", "payload": {"tool_name": "one"}})
        second = client.request({"op": "ping"})

    assert first == {"decision": "allow"}
    assert second == {"decision": "allow"}
    assert process.requests[0]["id"] != process.requests[1]["id"]
    assert set(process.requests[0]) == {"op", "payload", "id"}
    assert "id" not in process.requests[0]["payload"]
    assert len(factory.calls) == 1
    assert factory.calls[0][0] == ["node", "bridge.mjs"]
    assert process.terminated is True


@pytest.mark.parametrize(
    "responder, error_type, message",
    [
        (lambda _request, process: process.stdout.feed("not-json\n"), AgentSentryBridgeProtocolError, "malformed JSON"),
        (
            lambda _request, process: process.stdout.feed(
                json.dumps({"id": "wrong", "ok": True, "result": {}}) + "\n"
            ),
            AgentSentryBridgeProtocolError,
            "id mismatch",
        ),
        (lambda _request, process: process.stdout.feed(""), AgentSentryBridgeProtocolError, "EOF"),
        (
            lambda request, process: process.stdout.feed(
                json.dumps({"id": request["id"], "ok": "yes", "result": {}}) + "\n"
            ),
            AgentSentryBridgeProtocolError,
            "ok must be boolean",
        ),
        (
            lambda request, process: process.stdout.feed(
                json.dumps({"id": request["id"], "ok": True}) + "\n"
            ),
            AgentSentryBridgeProtocolError,
            "missing result",
        ),
    ],
)
def test_jsonl_client_protocol_failures_poison_the_process(responder, error_type, message):
    process = FakeProcess(responder)
    client = JsonlNodeBridgeClient(["node", "bridge.mjs"], process_factory=lambda *_args, **_kwargs: process)

    with pytest.raises(error_type, match=message):
        client.request({"op": "ping"})

    assert client.closed is True
    assert client.poisoned_reason
    assert process.terminated is True
    with pytest.raises(AgentSentryBridgeClosedError):
        client.request({"op": "ping"})


def test_jsonl_client_remote_error_is_fail_closed_and_poisoned():
    def responder(request, process):
        process.stdout.feed(
            json.dumps(
                {
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "unknown_session", "message": "session not found"},
                }
            )
            + "\n"
        )

    process = FakeProcess(responder)
    client = JsonlNodeBridgeClient(
        ["node", "bridge.mjs"], process_factory=lambda *_args, **_kwargs: process
    )

    with pytest.raises(AgentSentryBridgeRemoteError, match="unknown_session"):
        client.request({"op": "before_tool"})

    assert client.closed is True
    assert process.terminated is True


def test_jsonl_client_timeout_fails_closed_and_terminates_process():
    process = FakeProcess(lambda _request, _process: None)
    client = JsonlNodeBridgeClient(
        ["node", "bridge.mjs"],
        timeout=0.02,
        process_factory=lambda *_args, **_kwargs: process,
    )

    with pytest.raises(AgentSentryBridgeTimeoutError, match="timed out"):
        client.request({"op": "ping"})

    assert client.closed is True
    assert process.terminated is True


def test_jsonl_client_reserves_transport_id_and_close_is_idempotent():
    process = FakeProcess(_respond_with_decision())
    client = JsonlNodeBridgeClient(
        ["node", "bridge.mjs"],
        process_factory=lambda *_args, **_kwargs: process,
    )

    with pytest.raises(AgentSentryBridgeProtocolError, match="reserved"):
        client.request({"id": "caller-controlled"})
    client.close()
    client.close()

    assert process.terminated is True
    with pytest.raises(AgentSentryBridgeClosedError):
        client.request({"op": "ping"})
