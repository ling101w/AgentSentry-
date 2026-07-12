"""AgentDojo runtime supervision without a hard AgentDojo dependency.

The adapter deliberately sits at ``FunctionsRuntime.run_function``: this is the
last boundary before AgentDojo validates and executes a tool, and nested tool
calls re-enter the same method.  The module uses duck typing so importing
AgentSentry does not require AgentDojo or any of its optional dependencies.
"""

from __future__ import annotations

import dataclasses
import json
import queue
import re
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol


ALLOWED_DECISIONS = frozenset({"allow", "ask", "deny"})
DETECTOR_PAYLOAD_FIELDS = frozenset(
    {
        "user_message",
        "tool_name",
        "tool_args",
        "tool_result",
        "session_history",
    }
)
_OPAQUE_SESSION_ID = re.compile(r"^trial_[0-9a-f]{24,64}$")
_EOF = object()


class AgentSentryBridgeError(RuntimeError):
    """Base class for bridge failures. All such failures are fail closed."""


class AgentSentryBridgeClosedError(AgentSentryBridgeError):
    """Raised when a request is attempted on a closed or poisoned bridge."""


class AgentSentryBridgeTimeoutError(AgentSentryBridgeError):
    """Raised when the Node bridge does not answer before the deadline."""


class AgentSentryBridgeProtocolError(AgentSentryBridgeError):
    """Raised when the JSONL peer violates the transport protocol."""


class AgentSentryBridgeRemoteError(AgentSentryBridgeError):
    """Raised for a well-formed ``ok: false`` response from the bridge."""


class AgentSentryDeniedError(RuntimeError):
    """Raised for a supervised ``ask`` or ``deny`` in nested tool calls."""

    def __init__(self, tool_name: str, decision: str, reason: str) -> None:
        self.tool_name = tool_name
        self.decision = decision
        self.reason = reason
        super().__init__(f"{decision} {tool_name}: {reason}")


class BridgeClient(Protocol):
    """Minimal interface accepted by :func:`make_guarded_runtime_class`."""

    def request(self, message: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclasses.dataclass(frozen=True)
class _ReaderFailure:
    error: BaseException


class JsonlNodeBridgeClient:
    """A serialized, persistent JSONL subprocess bridge.

    ``request`` owns the transport ``id``. Callers provide an operation envelope
    without that field. Only one
    request is in flight at a time, which makes response correlation explicit
    and avoids platform-specific non-blocking pipe APIs on Windows.
    """

    def __init__(
        self,
        command: str | Sequence[str],
        timeout: float = 5.0,
        process_factory: Callable[..., Any] | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if isinstance(command, str):
            normalized_command = (command,)
        else:
            normalized_command = tuple(str(part) for part in command)
        if not normalized_command or any(not part for part in normalized_command):
            raise ValueError("command must contain at least one non-empty element")

        self.command = normalized_command
        self.timeout = float(timeout)
        self._lock = threading.RLock()
        self._responses: queue.Queue[str | bytes | object | _ReaderFailure] = queue.Queue()
        self._closed = False
        self._poisoned_reason: str | None = None
        factory = process_factory or subprocess.Popen
        try:
            self._process = factory(
                list(self.command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except Exception as exc:
            raise AgentSentryBridgeError(f"failed to start bridge process: {_exception_text(exc)}") from exc
        if self._process.stdin is None or self._process.stdout is None:
            self._shutdown_process()
            raise AgentSentryBridgeError("bridge process did not expose stdin and stdout pipes")

        self._reader = threading.Thread(
            target=self._read_stdout,
            name="agentsentry-jsonl-bridge-reader",
            daemon=True,
        )
        self._reader.start()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def poisoned_reason(self) -> str | None:
        return self._poisoned_reason

    def request(self, message: Mapping[str, Any]) -> Any:
        """Send one request and return the successful response ``result``.

        A timeout or any response-side protocol error poisons the process. The
        caller must create a fresh client instead of risking a late response
        being mistaken for a later request.
        """

        if not isinstance(message, Mapping):
            raise TypeError("bridge message must be a mapping")
        if "id" in message:
            raise AgentSentryBridgeProtocolError("id is reserved for the transport envelope")

        with self._lock:
            self._ensure_open()
            request_id = uuid.uuid4().hex
            envelope = dict(message)
            envelope["id"] = request_id
            try:
                encoded = json.dumps(
                    envelope,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            except (TypeError, ValueError) as exc:
                raise AgentSentryBridgeProtocolError(f"request is not valid JSON: {exc}") from exc

            try:
                self._process.stdin.write(encoded + "\n")
                self._process.stdin.flush()
            except Exception as exc:
                error = AgentSentryBridgeError(f"failed to write bridge request: {_exception_text(exc)}")
                self._poison(str(error))
                raise error from exc

            try:
                item = self._responses.get(timeout=self.timeout)
            except queue.Empty as exc:
                error = AgentSentryBridgeTimeoutError(
                    f"bridge request {request_id} timed out after {self.timeout:g}s"
                )
                self._poison(str(error))
                raise error from exc

            if item is _EOF:
                error = AgentSentryBridgeProtocolError(
                    f"bridge reached EOF while waiting for request {request_id}"
                )
                self._poison(str(error))
                raise error
            if isinstance(item, _ReaderFailure):
                error = AgentSentryBridgeProtocolError(
                    f"bridge reader failed: {_exception_text(item.error)}"
                )
                self._poison(str(error))
                raise error from item.error

            try:
                line = item.decode("utf-8") if isinstance(item, bytes) else item
                response = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                error = AgentSentryBridgeProtocolError(f"bridge returned malformed JSON: {exc}")
                self._poison(str(error))
                raise error from exc
            if not isinstance(response, dict):
                error = AgentSentryBridgeProtocolError("bridge response must be a JSON object")
                self._poison(str(error))
                raise error
            if response.get("id") != request_id:
                error = AgentSentryBridgeProtocolError(
                    f"bridge response id mismatch for {request_id}"
                )
                self._poison(str(error))
                raise error
            if not isinstance(response.get("ok"), bool):
                error = AgentSentryBridgeProtocolError("bridge response ok must be boolean")
                self._poison(str(error))
                raise error
            if response["ok"] is False:
                remote = response.get("error")
                if isinstance(remote, Mapping):
                    code = str(remote.get("code") or "bridge_request_failed")
                    detail = str(remote.get("message") or "bridge request failed")
                else:
                    code = "bridge_request_failed"
                    detail = "bridge returned ok=false without a structured error"
                error = AgentSentryBridgeRemoteError(f"{code}: {detail}")
                self._poison(str(error))
                raise error
            if "result" not in response:
                error = AgentSentryBridgeProtocolError("successful bridge response is missing result")
                self._poison(str(error))
                raise error
            return response["result"]

    def close(self) -> None:
        """Close the pipes and terminate the persistent process, idempotently."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._shutdown_process()

    def __enter__(self) -> JsonlNodeBridgeClient:
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            detail = f": {self._poisoned_reason}" if self._poisoned_reason else ""
            raise AgentSentryBridgeClosedError(f"bridge is closed{detail}")
        return_code = self._process.poll()
        if return_code is not None:
            error = f"bridge process exited with code {return_code}"
            self._poison(error)
            raise AgentSentryBridgeClosedError(error)

    def _read_stdout(self) -> None:
        try:
            while True:
                line = self._process.stdout.readline()
                if line in {"", b"", None}:
                    self._responses.put(_EOF)
                    return
                self._responses.put(line)
        except BaseException as exc:  # The daemon thread must report failures to the requester.
            self._responses.put(_ReaderFailure(exc))

    def _poison(self, reason: str) -> None:
        self._poisoned_reason = reason
        self._closed = True
        self._shutdown_process()

    def _shutdown_process(self) -> None:
        process = getattr(self, "_process", None)
        if process is None:
            return
        stdin = getattr(process, "stdin", None)
        if stdin is not None:
            try:
                stdin.close()
            except Exception:
                pass
        try:
            running = process.poll() is None
        except Exception:
            running = True
        if running:
            try:
                process.terminate()
            except Exception:
                pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=1.0)
            except Exception:
                pass
        except Exception:
            pass
        stdout = getattr(process, "stdout", None)
        if stdout is not None:
            try:
                stdout.close()
            except Exception:
                pass
        reader = getattr(self, "_reader", None)
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=0.2)


def make_guarded_runtime_class(
    base_runtime_cls: type[Any],
    bridge: BridgeClient,
    *,
    user_message: str,
    session_id: str | None = None,
    session_history: Sequence[Mapping[str, Any]] = (),
    record_sink: Callable[[Mapping[str, Any]], None] | None = None,
    start_session: bool = True,
) -> type[Any]:
    """Create an AgentDojo-compatible runtime that supervises every tool call.

    The resulting class can be passed directly as ``runtime_class`` to
    ``TaskSuite.run_task_with_pipeline``. The class captures no benchmark case
    identifier or hidden label. A supplied session identifier must already be
    an evaluator-generated opaque ``trial_<hex>`` value and is never rewritten.
    Call :meth:`GuardedRuntime.end` in the evaluator's ``finally`` block.
    """

    if not isinstance(base_runtime_cls, type):
        raise TypeError("base_runtime_cls must be a class")
    if not callable(getattr(bridge, "request", None)):
        raise TypeError("bridge must provide a request(message) method")
    if not isinstance(user_message, str):
        raise TypeError("user_message must be a string")
    if record_sink is not None and not callable(record_sink):
        raise TypeError("record_sink must be callable")
    if session_id is not None:
        _validate_opaque_session_id(session_id)
    history_snapshot = _validated_history(session_history)

    class GuardedRuntime(base_runtime_cls):
        agentsentry_bridge = bridge

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.agentsentry_session_id = _make_opaque_session_id(session_id)
            self.agentsentry_records: list[dict[str, Any]] = []
            # ``records`` is a convenient benchmark-facing alias; both refer to
            # the same append-only list for the lifetime of this runtime.
            self.records = self.agentsentry_records
            self._agentsentry_history = _json_value(history_snapshot)
            self._agentsentry_call_sequence = 0
            self._agentsentry_started = False
            self._agentsentry_ended = False
            self.agentsentry_start_result: dict[str, Any] | None = None
            self.agentsentry_end_result: dict[str, Any] | None = None
            if start_session:
                self.start()

        def start(self) -> Mapping[str, Any]:
            """Start the isolated Node policy session, idempotently."""

            if self._agentsentry_ended:
                raise AgentSentryBridgeClosedError("AgentSentry runtime session has ended")
            if self._agentsentry_started:
                return self.agentsentry_start_result or {}
            result = self.agentsentry_bridge.request(
                {
                    "op": "start",
                    "session_id": self.agentsentry_session_id,
                    "payload": self._detector_payload("", {}, None),
                }
            )
            if not isinstance(result, Mapping):
                raise AgentSentryBridgeProtocolError("start result must be a mapping")
            self.agentsentry_start_result = _json_value(result)
            self._agentsentry_started = True
            return self.agentsentry_start_result

        def end(self) -> Mapping[str, Any]:
            """End the Node policy session without closing the shared bridge."""

            if self._agentsentry_ended:
                return self.agentsentry_end_result or {"ended": False}
            result = self.agentsentry_bridge.request(
                {"op": "end", "session_id": self.agentsentry_session_id}
            )
            if not isinstance(result, Mapping):
                raise AgentSentryBridgeProtocolError("end result must be a mapping")
            self.agentsentry_end_result = _json_value(result)
            self._agentsentry_ended = True
            self._agentsentry_started = False
            return self.agentsentry_end_result

        def __enter__(self) -> Any:
            return self

        def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
            self.end()

        def run_function(
            self,
            env: Any,
            function: str,
            kwargs: Mapping[str, Any],
            raise_on_error: bool = False,
        ) -> tuple[Any, str | None]:
            call_id = self._next_call_id()
            if not self._agentsentry_started or self._agentsentry_ended:
                return self._deny_for_adapter_error(
                    function,
                    call_id,
                    "AgentSentry policy session is not active",
                    raise_on_error,
                )
            try:
                safe_args = _json_value(kwargs)
            except Exception as exc:
                return self._deny_for_adapter_error(
                    function,
                    call_id,
                    _exception_text(exc),
                    raise_on_error,
                )
            if not isinstance(safe_args, dict):
                return self._deny_for_adapter_error(
                    function,
                    call_id,
                    "tool arguments must be a mapping",
                    raise_on_error,
                )

            record: dict[str, Any] = {
                "session_id": self.agentsentry_session_id,
                "call_id": call_id,
                "tool_name": function,
                "decision": "deny",
                "reason": "",
                "latency_ms": 0.0,
                "executed": False,
                "bridge_error": None,
                "protocol_error": None,
                "after_feedback": "not_sent",
                "after_feedback_error": None,
                "after_latency_ms": 0.0,
                "detector_result": None,
                "after_result": None,
                "record_sink_error": None,
            }
            started = time.perf_counter()
            try:
                before_payload = self._detector_payload(function, safe_args, None)
                response = self.agentsentry_bridge.request(
                    {
                        "op": "before_tool",
                        "session_id": self.agentsentry_session_id,
                        "call_id": call_id,
                        "payload": before_payload,
                    }
                )
                decision, reason = _parse_before_response(response)
                record["decision"] = decision
                record["reason"] = reason
                record["detector_result"] = _json_value(response)
            except Exception as exc:
                record["decision"] = "deny"
                record["reason"] = "AgentSentry bridge failed closed"
                record["bridge_error"] = _exception_text(exc)
                if isinstance(exc, AgentSentryBridgeProtocolError):
                    record["protocol_error"] = str(exc)
            finally:
                record["latency_ms"] = _elapsed_ms(started)

            self.agentsentry_records.append(record)
            if record["decision"] != "allow":
                self._append_history(record, safe_args, None, None)
                self._emit_record(record)
                return _denied_result(
                    function,
                    record["decision"],
                    record["reason"] or "tool call was not authorized",
                    raise_on_error,
                )

            record["executed"] = True
            try:
                result, error = super().run_function(env, function, kwargs, raise_on_error=raise_on_error)
            except Exception as exc:
                if isinstance(exc, AgentSentryDeniedError):
                    # AgentDojo resolves nested calls before invoking the parent
                    # function, so a denied nested call means the parent effect
                    # did not execute even though it was initially released.
                    record["executed"] = False
                feedback_result: Any = {"error": _exception_text(exc)}
                self._send_after(function, call_id, safe_args, feedback_result, record)
                self._append_history(record, safe_args, feedback_result, _exception_text(exc))
                self._emit_record(record)
                raise

            if isinstance(error, str) and error.startswith("AgentSentryDeniedError:"):
                record["executed"] = False
            feedback_result = result if error is None else {"output": result, "error": error}
            self._send_after(function, call_id, safe_args, feedback_result, record)
            self._append_history(record, safe_args, feedback_result, error)
            self._emit_record(record)
            return result, error

        def _detector_payload(
            self,
            function: str,
            safe_args: dict[str, Any],
            tool_result: Any,
        ) -> dict[str, Any]:
            payload = {
                "user_message": user_message,
                "tool_name": str(function),
                "tool_args": _json_value(safe_args),
                "tool_result": _json_value(tool_result),
                "session_history": _json_value(self._agentsentry_history),
            }
            _assert_detector_payload(payload)
            return payload

        def _send_after(
            self,
            function: str,
            call_id: str,
            safe_args: dict[str, Any],
            feedback_result: Any,
            record: dict[str, Any],
        ) -> None:
            started = time.perf_counter()
            try:
                response = self.agentsentry_bridge.request(
                    {
                        "op": "after_tool",
                        "session_id": self.agentsentry_session_id,
                        "call_id": call_id,
                        "payload": self._detector_payload(function, safe_args, feedback_result),
                    }
                )
                if not isinstance(response, Mapping):
                    raise AgentSentryBridgeProtocolError("after result must be a mapping")
                record["after_feedback"] = "received"
                record["after_result"] = _json_value(response)
            except Exception as exc:
                # The tool has already crossed the execution boundary. Keep the
                # original allow decision and executed=True; feedback cannot
                # retroactively block a side effect.
                record["after_feedback"] = "error_after_execution"
                record["after_feedback_error"] = _exception_text(exc)
                if record["bridge_error"] is None:
                    record["bridge_error"] = _exception_text(exc)
                if isinstance(exc, AgentSentryBridgeProtocolError):
                    record["protocol_error"] = str(exc)
            finally:
                record["after_latency_ms"] = _elapsed_ms(started)

        def _append_history(
            self,
            record: Mapping[str, Any],
            safe_args: Mapping[str, Any],
            tool_result: Any,
            error: str | None,
        ) -> None:
            event = {
                "tool_name": record["tool_name"],
                "tool_args": _json_value(safe_args),
                "tool_result": _json_value(tool_result),
                "decision": record["decision"],
                "executed": bool(record["executed"]),
                "error": error,
            }
            self._agentsentry_history.append(event)

        def _deny_for_adapter_error(
            self,
            function: str,
            call_id: str,
            reason: str,
            raise_on_error: bool,
        ) -> tuple[Any, str | None]:
            record = {
                "session_id": self.agentsentry_session_id,
                "call_id": call_id,
                "tool_name": function,
                "decision": "deny",
                "reason": reason,
                "latency_ms": 0.0,
                "executed": False,
                "bridge_error": reason,
                "protocol_error": reason,
                "after_feedback": "not_sent",
                "after_feedback_error": None,
                "after_latency_ms": 0.0,
                "detector_result": None,
                "after_result": None,
                "record_sink_error": None,
            }
            self.agentsentry_records.append(record)
            self._emit_record(record)
            return _denied_result(function, "deny", reason, raise_on_error)

        def _next_call_id(self) -> str:
            self._agentsentry_call_sequence += 1
            return f"call_{self._agentsentry_call_sequence:08d}"

        def _emit_record(self, record: dict[str, Any]) -> None:
            if record_sink is None:
                return
            try:
                record_sink(_json_value(record))
            except Exception as exc:
                # Recording cannot retroactively change whether a tool ran.
                record["record_sink_error"] = _exception_text(exc)

    GuardedRuntime.__name__ = f"AgentSentryGuarded{base_runtime_cls.__name__}"
    GuardedRuntime.__qualname__ = GuardedRuntime.__name__
    GuardedRuntime.__module__ = __name__
    return GuardedRuntime


def _parse_before_response(response: Mapping[str, Any]) -> tuple[str, str]:
    if not isinstance(response, Mapping):
        raise AgentSentryBridgeProtocolError("before response must be a mapping")
    decision = response.get("decision")
    if decision not in ALLOWED_DECISIONS:
        raise AgentSentryBridgeProtocolError(f"invalid decision {decision!r}")
    raw_reason = response.get("reason", response.get("summary", response.get("message", "")))
    reason = raw_reason if isinstance(raw_reason, str) else str(raw_reason)
    return decision, reason.strip()


def _denied_result(
    tool_name: str,
    decision: str,
    reason: str,
    raise_on_error: bool,
) -> tuple[Any, str | None]:
    if raise_on_error:
        raise AgentSentryDeniedError(tool_name, decision, reason)
    return "", f"AgentSentryDenied: {decision} {tool_name}: {reason}"


def _validated_history(history: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(history, (str, bytes)):
        raise TypeError("session_history must be a sequence of mappings")
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(history):
        if not isinstance(item, Mapping):
            raise TypeError(f"session_history[{index}] must be a mapping")
        value = _json_value(item)
        if not isinstance(value, dict):
            raise TypeError(f"session_history[{index}] must serialize to an object")
        rows.append(value)
    return rows


def _assert_detector_payload(payload: Mapping[str, Any]) -> None:
    if set(payload) != DETECTOR_PAYLOAD_FIELDS:
        extra = sorted(set(payload) - DETECTOR_PAYLOAD_FIELDS)
        missing = sorted(DETECTOR_PAYLOAD_FIELDS - set(payload))
        raise AgentSentryBridgeProtocolError(
            f"detector payload fields mismatch; extra={extra}, missing={missing}"
        )
    if not isinstance(payload["user_message"], str):
        raise AgentSentryBridgeProtocolError("detector user_message must be a string")
    if not isinstance(payload["tool_name"], str):
        raise AgentSentryBridgeProtocolError("detector tool_name must be a string")
    if not isinstance(payload["tool_args"], dict):
        raise AgentSentryBridgeProtocolError("detector tool_args must be an object")
    history = payload["session_history"]
    if not isinstance(history, list) or not all(isinstance(item, dict) for item in history):
        raise AgentSentryBridgeProtocolError("detector session_history must be an array of objects")
    try:
        json.dumps(payload, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise AgentSentryBridgeProtocolError(f"detector payload is not valid JSON: {exc}") from exc


def _json_value(value: Any) -> Any:
    """Convert AgentDojo/Pydantic values to detached JSON-compatible data."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_value(item) for item in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return _json_value(model_dump(mode="json"))
        except TypeError:
            return _json_value(model_dump())
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _json_value(dataclasses.asdict(value))
    raise AgentSentryBridgeProtocolError(
        f"value of type {type(value).__name__} is not JSON serializable"
    )


def _make_opaque_session_id(session_id: str | None) -> str:
    if session_id is None:
        return f"trial_{uuid.uuid4().hex[:24]}"
    _validate_opaque_session_id(session_id)
    return session_id


def _validate_opaque_session_id(session_id: str) -> None:
    if not isinstance(session_id, str) or not _OPAQUE_SESSION_ID.fullmatch(session_id):
        raise ValueError("session_id must match trial_<24 to 64 lowercase hex characters>")


def _elapsed_ms(started: float) -> float:
    return round(max(0.0, (time.perf_counter() - started) * 1000), 3)


def _exception_text(exc: BaseException) -> str:
    detail = str(exc).strip()
    return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__


__all__ = [
    "AgentSentryBridgeClosedError",
    "AgentSentryBridgeError",
    "AgentSentryBridgeProtocolError",
    "AgentSentryBridgeRemoteError",
    "AgentSentryBridgeTimeoutError",
    "AgentSentryDeniedError",
    "BridgeClient",
    "DETECTOR_PAYLOAD_FIELDS",
    "JsonlNodeBridgeClient",
    "make_guarded_runtime_class",
]
