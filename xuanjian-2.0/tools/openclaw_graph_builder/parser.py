"""Normalize OpenClaw and AgentSentry trajectory records.

The parser accepts three practical inputs:

* a unified trajectory object with an ``events`` list;
* one JSON object per line containing an event;
* the command-lab record shape with ``payload.business_actions``.

No evaluator-only labels are invented.  Missing labels are reported as
``unknown`` so real logs can be converted without pretending they are
ground truth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping


EVENT_TYPES = frozenset({"user_input", "tool_call", "tool_result", "assistant_output"})
_TYPE_ALIASES = {
    "user": "user_input",
    "message": "user_input",
    "user_message": "user_input",
    "before_tool_call": "tool_call",
    "before_tool": "tool_call",
    "call": "tool_call",
    "function_call": "tool_call",
    "after_tool": "tool_result",
    "tool_response": "tool_result",
    "result": "tool_result",
    "function_result": "tool_result",
    "assistant": "assistant_output",
    "assistant_message": "assistant_output",
}


@dataclass(frozen=True)
class OpenClawEvent:
    """Format-independent representation of one trajectory event."""

    event_type: str
    seq: int
    timestamp: float
    event_id: str
    call_id: str | None = None
    user_message: str = ""
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    tool_result: Any = None
    source: str = "system"
    decision: str | None = None
    risk_score: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OpenClawTrajectory:
    """A normalized session ready for causal graph construction."""

    case_id: str
    session_id: str
    user_message: str
    events: tuple[OpenClawEvent, ...]
    label: str = "unknown"
    attack_type: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def _first(mapping: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _timestamp(value: Any, fallback: float) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            except ValueError:
                pass
    return fallback


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {} if value is None else {"value": value}


def _event_type(raw_type: Any) -> str:
    value = str(raw_type or "").strip().lower().replace("-", "_").replace(" ", "_")
    value = _TYPE_ALIASES.get(value, value)
    if value not in EVENT_TYPES:
        raise ValueError(f"unsupported OpenClaw event type: {raw_type!r}")
    return value


def _is_supported_event_record(record: Mapping[str, Any]) -> bool:
    try:
        _event_type(_first(record, "type", "event_type", "kind", default=""))
    except ValueError:
        return False
    return True


def _label_and_attack_type(record: Mapping[str, Any]) -> tuple[str, str | None]:
    label_value = record.get("label")
    label = label_value if isinstance(label_value, str) else ""
    attack_type = record.get("attack_type")
    if isinstance(label_value, Mapping):
        label = str(
            _first(label_value, "trajectory_label", "label", "expected", default="")
        )
        attack_type = _first(label_value, "attack_type", "risk_source", default=attack_type)
    if label not in {"normal", "attack", "safe", "unsafe"}:
        label = "unknown"
    if label == "safe":
        label = "normal"
    elif label == "unsafe":
        label = "attack"
    return label, str(attack_type) if attack_type else None


def _normalize_event(raw: Mapping[str, Any], index: int, *, default_session: str) -> OpenClawEvent:
    event_type = _event_type(_first(raw, "type", "event_type", "kind", default=""))
    seq_value = _first(raw, "seq", "sequence", "index", default=index)
    try:
        seq = int(seq_value)
    except (TypeError, ValueError):
        seq = index
    timestamp = _timestamp(
        _first(raw, "timestamp", "created_at", "time", "ts"),
        float(seq),
    )
    event_id = str(_first(raw, "event_id", "id", default=f"event_{seq}"))
    call_id = _first(raw, "call_id", "tool_call_id", "callId")
    tool_name = str(_first(raw, "tool_name", "toolName", "name", default=""))
    args_value = _first(raw, "tool_args", "arguments", "params", "parameters", default={})
    result = _first(raw, "tool_result", "result", "results", default=None)
    message = str(_first(raw, "content", "user_message", "message", "text", default=""))
    source_value = _first(raw, "source", "origin", default="system")
    source = str(source_value) if source_value else "system"
    decision = _first(raw, "decision", "verdict", "action")
    risk_score = _first(raw, "risk_score", "riskScore")
    if isinstance(risk_score, str):
        try:
            risk_score = float(risk_score)
        except ValueError:
            risk_score = None
    metadata = {
        key: value
        for key, value in raw.items()
        if key
        not in {
            "type", "event_type", "kind", "seq", "sequence", "index", "timestamp",
            "created_at", "time", "ts", "event_id", "id", "call_id", "tool_call_id",
            "callId", "tool_name", "toolName", "name", "tool_args", "arguments", "params",
            "parameters", "tool_result", "result", "results", "content", "user_message",
            "message", "text", "source", "origin", "decision", "verdict", "action",
            "risk_score", "riskScore",
        }
    }
    metadata["session_id"] = default_session
    return OpenClawEvent(
        event_type=event_type,
        seq=seq,
        timestamp=timestamp,
        event_id=event_id,
        call_id=str(call_id) if call_id is not None else None,
        user_message=message if event_type in {"user_input", "assistant_output"} else "",
        tool_name=tool_name if event_type == "tool_call" else "",
        tool_args=_as_dict(args_value) if event_type == "tool_call" else {},
        tool_result=result if event_type == "tool_result" else None,
        source=source,
        decision=str(decision) if decision is not None else None,
        risk_score=risk_score if isinstance(risk_score, (int, float)) else None,
        metadata=metadata,
    )


def parse_trajectory(record: Mapping[str, Any], *, source: str = "") -> OpenClawTrajectory:
    """Parse one unified case or command-lab record."""
    root: Mapping[str, Any] = record
    raw_response = record.get("raw_response")
    if isinstance(raw_response, Mapping) and isinstance(raw_response.get("record"), Mapping):
        root = raw_response["record"]

    payload = root.get("payload") if isinstance(root.get("payload"), Mapping) else {}
    case_id = str(
        _first(record, "case_id", "record_id", default=_first(root, "id", "run_id", "session_key", default="trajectory"))
    )
    session_id = str(
        _first(
            record,
            "session_id",
            "session_key",
            default=_first(root, "session_id", "session_key", "run_id", default=case_id),
        )
    )
    task = record.get("task") if isinstance(record.get("task"), Mapping) else {}
    user_message = str(
        _first(
            record,
            "user_message",
            "command",
            default=_first(
                task,
                "initial_user_message",
                default=_first(
                    payload,
                    "command",
                    "user_message",
                    default=_first(root, "summary", "command", default=""),
                ),
            ),
        )
    )
    events_raw = record.get("events")
    if not isinstance(events_raw, list):
        events_raw = root.get("events")
    events: list[OpenClawEvent] = []
    if isinstance(events_raw, list):
        for index, event in enumerate(events_raw):
            if isinstance(event, Mapping):
                events.append(_normalize_event(event, index, default_session=session_id))
    else:
        actions = payload.get("business_actions") if isinstance(payload, Mapping) else None
        decisions = raw_response.get("decisions") if isinstance(raw_response, Mapping) else None
        if not isinstance(actions, list):
            actions = root.get("business_actions")
        if isinstance(actions, list):
            for index, action in enumerate(actions):
                if not isinstance(action, Mapping):
                    continue
                decision = decisions[index] if isinstance(decisions, list) and index < len(decisions) else {}
                if not isinstance(decision, Mapping):
                    decision = {}
                event = {
                    "type": "tool_call",
                    "seq": index,
                    "event_id": f"event_{index}",
                    "call_id": f"call_{index}",
                    "tool_name": _first(action, "tool_name", "toolName", "name", default=""),
                    "tool_args": _first(action, "tool_args", "params", "parameters", default={}),
                    "source": _first(action, "source", default="system"),
                    "decision": _first(decision, "decision", "verdict"),
                    "risk_score": _first(decision, "risk_score", "riskScore"),
                    "metadata": {"business_action": True},
                }
                events.append(_normalize_event(event, index, default_session=session_id))

    if not user_message:
        for event in events:
            if event.event_type == "user_input" and event.user_message:
                user_message = event.user_message
                break
    if not any(event.event_type == "user_input" for event in events) and user_message:
        events.insert(
            0,
            OpenClawEvent(
                event_type="user_input",
                seq=-1,
                timestamp=min((event.timestamp for event in events), default=0.0) - 0.001,
                event_id="event_user_0",
                user_message=user_message,
                source="user",
                metadata={"synthetic_from_record": True, "source": source},
            ),
        )
    events.sort(key=lambda event: (event.seq, event.timestamp, event.event_id))
    label, attack_type = _label_and_attack_type(record)
    if label != "attack":
        attack_type = None
    elif not attack_type and isinstance(root.get("scenario"), str):
        attack_type = root["scenario"]
    metadata = {
        "source": source,
        "schema_version": record.get("schema_version", root.get("schema_version", "")),
    }
    if isinstance(record.get("metadata"), Mapping):
        metadata.update(record["metadata"])
    return OpenClawTrajectory(
        case_id=case_id,
        session_id=session_id,
        user_message=user_message,
        events=tuple(events),
        label=label,
        attack_type=attack_type,
        metadata=metadata,
    )


def _records_from_text(text: str) -> Iterator[Mapping[str, Any]]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        for line_number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}") from exc
            if not isinstance(value, Mapping):
                raise ValueError(f"JSONL line {line_number} must contain an object")
            yield value
        return
    if isinstance(document, Mapping):
        cases = document.get("cases")
        if isinstance(cases, list):
            for case in cases:
                if isinstance(case, Mapping):
                    yield case
        else:
            yield document
    elif isinstance(document, list):
        for item in document:
            if isinstance(item, Mapping):
                yield item
    else:
        raise ValueError("input JSON must contain an object or array")


def load_trajectories(path: str | Path) -> list[OpenClawTrajectory]:
    """Load JSON, JSONL, or an array of trajectory records from disk."""
    source_path = Path(path)
    if source_path.is_dir():
        session_files = sorted(
            candidate
            for candidate in source_path.glob("*.jsonl")
            if ".trajectory." not in candidate.name
            and ".bak" not in candidate.name
            and ".deleted." not in candidate.name
            and ".reset." not in candidate.name
        )
        trajectories: list[OpenClawTrajectory] = []
        for session_file in session_files:
            trajectories.extend(load_trajectories(session_file))
        return trajectories
    text = source_path.read_text(encoding="utf-8")
    records = list(_records_from_text(text))
    if any(record.get("type") == "message" for record in records):
        return [parse_openclaw_session_records(records, source=str(source_path))]
    # OpenClaw integrations commonly append one event per JSONL line. Group
    # those lines into sessions before building a graph.
    event_records = [
        record
        for record in records
        if ("type" in record or "event_type" in record)
        and not isinstance(record.get("events"), list)
        and not isinstance(record.get("payload"), Mapping)
        and _is_supported_event_record(record)
    ]
    if event_records and all(
        ("type" in record or "event_type" in record)
        and not isinstance(record.get("events"), list)
        and not isinstance(record.get("payload"), Mapping)
        for record in records
    ):
        grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for record in event_records:
            session_id = str(
                _first(record, "session_id", "session_key", "sessionId", default="event_stream")
            )
            grouped[session_id].append(record)
        return [
            parse_event_stream(
                group,
                session_id=session_id,
                case_id=f"openclaw_{session_id}",
            )
            for session_id, group in sorted(grouped.items())
        ]
    if not event_records and records and all(
        ("type" in record or "event_type" in record) and not isinstance(record.get("events"), list)
        for record in records
    ):
        # Lifecycle-only files (session/model/config records) contain no
        # executable trajectory and should not become empty training graphs.
        return []
    return [parse_trajectory(record, source=str(source_path)) for record in records]


def parse_event_stream(events: Iterable[Mapping[str, Any]], *, session_id: str, case_id: str = "event_stream") -> OpenClawTrajectory:
    """Build a trajectory from already separated event objects."""
    return parse_trajectory(
        {"case_id": case_id, "session_id": session_id, "events": list(events)},
        source="event_stream",
    )


def _message_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(item.get("text", ""))
            for item in content
            if isinstance(item, Mapping) and item.get("type") == "text"
        )
    return ""


def parse_openclaw_session_records(
    records: Iterable[Mapping[str, Any]], *, source: str = ""
) -> OpenClawTrajectory:
    """Parse OpenClaw's native ``agents/*/sessions/*.jsonl`` format.

    OpenClaw stores assistant tool calls inside ``message.content`` and tool
    results as messages with role ``toolResult``.  Model/config lifecycle
    records are intentionally ignored because they are not agent actions.
    """
    rows = list(records)
    session_row = next((row for row in rows if row.get("type") == "session"), {})
    session_id = str(_first(session_row, "id", default="openclaw_session"))
    case_id = f"openclaw_session_{session_id}"
    events: list[OpenClawEvent] = []
    user_message = ""
    seq = 0
    for row in rows:
        if row.get("type") != "message" or not isinstance(row.get("message"), Mapping):
            continue
        message = row["message"]
        role = str(message.get("role", ""))
        timestamp = _timestamp(
            _first(message, "timestamp", default=row.get("timestamp")),
            float(seq),
        )
        content = message.get("content")
        if role == "user":
            text = _message_text(content)
            if text:
                if not user_message:
                    user_message = text
                events.append(
                    OpenClawEvent(
                        event_type="user_input",
                        seq=seq,
                        timestamp=timestamp,
                        event_id=f"event_{seq}",
                        user_message=text,
                        source="user",
                        metadata={"openclaw_role": role},
                    )
                )
                seq += 1
            continue
        if role == "assistant":
            items = content if isinstance(content, list) else [content]
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                if item.get("type") == "toolCall":
                    arguments = item.get("arguments", {})
                    if isinstance(arguments, str):
                        try:
                            arguments = json.loads(arguments)
                        except json.JSONDecodeError:
                            arguments = {"value": arguments}
                    events.append(
                        OpenClawEvent(
                            event_type="tool_call",
                            seq=seq,
                            timestamp=timestamp,
                            event_id=f"event_{seq}",
                            call_id=str(item.get("id")) if item.get("id") else None,
                            tool_name=str(item.get("name", "")),
                            tool_args=_as_dict(arguments),
                            source="system",
                            metadata={"openclaw_role": role, "api": message.get("api")},
                        )
                    )
                    seq += 1
                elif item.get("type") == "text" and item.get("text"):
                    events.append(
                        OpenClawEvent(
                            event_type="assistant_output",
                            seq=seq,
                            timestamp=timestamp,
                            event_id=f"event_{seq}",
                            user_message=str(item["text"]),
                            source="system",
                            metadata={"openclaw_role": role},
                        )
                    )
                    seq += 1
            continue
        if role == "toolResult":
            result_items = content if isinstance(content, list) else [content]
            result = [
                dict(item)
                for item in result_items
                if isinstance(item, Mapping)
            ]
            if not result:
                result = content
            events.append(
                OpenClawEvent(
                    event_type="tool_result",
                    seq=seq,
                    timestamp=timestamp,
                    event_id=f"event_{seq}",
                    call_id=str(message.get("toolCallId")) if message.get("toolCallId") else None,
                    tool_name=str(message.get("toolName", "")),
                    tool_result=result,
                    source="tool_result",
                    metadata={"openclaw_role": role, "is_error": bool(message.get("isError"))},
                )
            )
            seq += 1

    if not user_message:
        user_message = "OpenClaw session"
    metadata = {
        "source": source,
        "format": "openclaw_session_jsonl",
        "openclaw_session_id": session_id,
        "workspace_dir": session_row.get("cwd", ""),
    }
    return OpenClawTrajectory(
        case_id=case_id,
        session_id=session_id,
        user_message=user_message,
        events=tuple(events),
        metadata=metadata,
    )
