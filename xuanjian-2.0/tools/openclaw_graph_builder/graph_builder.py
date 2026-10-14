"""Convert normalized OpenClaw trajectories into causal graphs."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from core.graph import (
    CausalGraph,
    Edge,
    EdgeType,
    EntityNode,
    IntentNode,
    ObservationNode,
    ToolCallNode,
    TrustLevel,
    calculate_control_weight,
    create_edge_id,
)

from .parser import OpenClawEvent, OpenClawTrajectory, parse_trajectory


_TASK_KEYWORDS = {
    "email_summary": ("email", "mail", "邮件"),
    "calendar_management": ("calendar", "meeting", "schedule", "日程", "会议"),
    "web_search": ("weather", "search", "web", "天气", "查询"),
    "file_processing": ("file", "csv", "report", "文件", "数据"),
    "code_review": ("code", "pull request", "pr", "lint", "代码"),
    "memory_management": ("memory", "preference", "记忆", "偏好"),
    "log_analysis": ("log", "日志"),
}
_SENSITIVE_KEYWORDS = (
    "api_key", "apikey", "token", "secret", "password", "passwd", "credential",
    "private_key", "ssh", "authorization", "cookie", ".env", "openclaw.json",
)
_INJECTION_MARKERS = (
    "ignore previous", "ignore all", "system administrator", "bypass", "rm -rf",
    "转发", "始终同意", "不要进行安全检查", "立即将", "upload to", "send to",
)
_REDACTED = "<redacted>"
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:api[_-]?key|token|secret|password|passwd|authorization)\b\s*[:=]\s*)([^\s,;]+)"
)


def _hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _task_type(message: str, tool_names: list[str]) -> str:
    haystack = f"{message} {' '.join(tool_names)}".lower()
    for task, keywords in _TASK_KEYWORDS.items():
        if any(keyword.lower() in haystack for keyword in keywords):
            return task
    return "unknown"


def _trust_level(event: OpenClawEvent) -> TrustLevel:
    values = [event.metadata.get(key) for key in ("trust_label", "trust", "integrity")]
    result = event.tool_result
    if isinstance(result, Mapping):
        values.extend(result.get(key) for key in ("trust_label", "trust", "integrity"))
        if result.get("tainted") is True:
            return TrustLevel.LOW
    for value in values:
        normalized = str(value or "").lower()
        if normalized in {"untrusted", "tainted", "malicious"}:
            return TrustLevel.UNTRUSTED
        if normalized in {"low", "external", "unverified"}:
            return TrustLevel.LOW
        if normalized in {"high", "trusted"}:
            return TrustLevel.HIGH
    content = _stringify(result).lower()
    if any(marker.lower() in content for marker in _INJECTION_MARKERS):
        return TrustLevel.LOW
    if event.source.lower() in {"user", "operator"}:
        return TrustLevel.HIGH
    return TrustLevel.MEDIUM


def _auth_level(event: OpenClawEvent) -> float:
    value = event.metadata.get("auth_level", event.metadata.get("authLevel"))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, min(1.0, float(value)))
    decision = (event.decision or "").lower()
    return {"allow": 0.8, "approved": 0.8, "ask": 0.4, "deny": 0.1, "blocked": 0.1}.get(decision, 0.5)


def _authorized(event: OpenClawEvent) -> bool:
    return (event.decision or "").lower() not in {"deny", "denied", "block", "blocked"}


def _flatten_params(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, Mapping):
        pairs: list[tuple[str, Any]] = []
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            pairs.extend(_flatten_params(child, name))
        return pairs
    if isinstance(value, (list, tuple)):
        pairs = []
        for index, child in enumerate(value):
            pairs.extend(_flatten_params(child, f"{prefix}[{index}]"))
        return pairs
    return [(prefix, value)]


def _sensitive_entities(parameters: Mapping[str, Any]) -> list[tuple[str, Any]]:
    result = []
    for key, value in _flatten_params(parameters):
        normalized = key.lower()
        text = _stringify(value).lower()
        if any(marker in normalized or marker in text for marker in _SENSITIVE_KEYWORDS):
            result.append((key, value))
    return result


def _redact(value: Any, key: str = "") -> Any:
    """Keep graph shape while preventing obvious credential leakage."""
    normalized_key = key.lower()
    if any(marker in normalized_key for marker in _SENSITIVE_KEYWORDS):
        return _REDACTED
    if isinstance(value, Mapping):
        return {str(child_key): _redact(child, str(child_key)) for child_key, child in value.items()}
    if isinstance(value, list):
        return [_redact(child, key) for child in value]
    if isinstance(value, tuple):
        return [_redact(child, key) for child in value]
    if isinstance(value, str):
        if ".ssh/" in value or "BEGIN PRIVATE KEY" in value:
            return _REDACTED
        return _SECRET_ASSIGNMENT.sub(r"\1" + _REDACTED, value)
    return value


def _control_fields(parameters: Mapping[str, Any], observation: ObservationNode) -> list[str]:
    preview = observation.content_preview.lower()
    fields = []
    for key, value in _flatten_params(parameters):
        if preview and _stringify(value).lower() in preview:
            fields.append(key)
    return fields


class OpenClawGraphBuilder:
    """Build a causal graph from a normalized trajectory."""

    def __init__(self, *, redact_sensitive: bool = True, max_content_preview: int = 200):
        self.redact_sensitive = redact_sensitive
        self.max_content_preview = max(32, int(max_content_preview))

    def build(self, trajectory: OpenClawTrajectory | Mapping[str, Any]) -> CausalGraph:
        if not isinstance(trajectory, OpenClawTrajectory):
            trajectory = parse_trajectory(trajectory)
        tool_events = [event for event in trajectory.events if event.event_type == "tool_call"]
        graph = CausalGraph(graph_id=trajectory.case_id, session_id=trajectory.session_id)
        first_timestamp = min((event.timestamp for event in trajectory.events), default=0.0)
        original_request = trajectory.user_message
        safe_request = _redact(original_request) if self.redact_sensitive else original_request
        intent_metadata = {
            "label": trajectory.label,
            "attack_type": trajectory.attack_type,
            "trajectory_metadata": trajectory.metadata,
            "original_request_hash": _hash(original_request),
            "original_request_truncated": len(safe_request) > self.max_content_preview,
        }
        intent = IntentNode(
            node_id="intent_1",
            node_type=None,
            timestamp=first_timestamp,
            session_id=trajectory.session_id,
            task_type=_task_type(
                trajectory.user_message,
                [event.tool_name for event in tool_events],
            ),
            user_id=str(trajectory.metadata.get("user_id", "unknown")),
            original_request=safe_request[: self.max_content_preview],
            metadata=intent_metadata,
        )
        graph.add_node(intent)

        calls_by_id: dict[str, ToolCallNode] = {}
        last_call: ToolCallNode | None = None
        last_observation: ObservationNode | None = None
        call_number = 0
        observation_number = 0
        entity_number = 0
        for event in trajectory.events:
            if event.event_type == "user_input":
                if event.user_message and event.user_message != trajectory.user_message:
                    messages = intent.metadata.setdefault("additional_user_messages", [])
                    safe_message = _redact(event.user_message) if self.redact_sensitive else event.user_message
                    messages.append(safe_message[: self.max_content_preview])
                continue
            if event.event_type == "tool_call":
                call_number += 1
                original_parameters = event.tool_args
                parameters = _redact(original_parameters) if self.redact_sensitive else original_parameters
                call = ToolCallNode(
                    node_id=f"call_{call_number}",
                    node_type=None,
                    timestamp=event.timestamp,
                    session_id=trajectory.session_id,
                    tool_name=event.tool_name or "unknown_tool",
                    parameters=parameters,
                    source=event.source if event.source in {"user", "observation", "system"} else "system",
                    auth_level=_auth_level(event),
                    authorized=_authorized(event),
                    metadata={
                        "event_id": event.event_id,
                        "call_id": event.call_id,
                        "seq": event.seq,
                        "decision": event.decision,
                        "risk_score": event.risk_score,
                        **event.metadata,
                    },
                )
                graph.add_node(call)
                if last_call is None:
                    graph.add_edge(Edge(
                        edge_id=create_edge_id(intent.node_id, call.node_id, EdgeType.INTENT_DRIVES),
                        source_id=intent.node_id,
                        target_id=call.node_id,
                        edge_type=EdgeType.INTENT_DRIVES,
                        weight=1.0,
                        timestamp=event.timestamp,
                    ))
                else:
                    graph.add_edge(Edge(
                        edge_id=create_edge_id(last_call.node_id, call.node_id, EdgeType.CALL_SEQUENCE),
                        source_id=last_call.node_id,
                        target_id=call.node_id,
                        edge_type=EdgeType.CALL_SEQUENCE,
                        weight=1.0,
                        timestamp=event.timestamp,
                    ))
                if last_observation is not None:
                    fields = _control_fields(event.tool_args, last_observation)
                    total = [key for key, _ in _flatten_params(event.tool_args)]
                    match_ratio = calculate_control_weight(fields, total) if fields else 0.0
                    # 2026-08-30 修复：真实 OpenClaw 日志从不打 source=observation 标签
                    # （1084 个调用里 0 个），导致 control_influence 边在真实数据上
                    # 永远不出现。改为以字段匹配比例为主判定，source 标签仅作加分项。
                    explicit_observation_source = event.source == "observation"
                    if match_ratio >= 0.5 or (explicit_observation_source and fields):
                        weight = max(match_ratio, 0.5)
                        edge_type = EdgeType.CONTROL_INFLUENCE
                    else:
                        weight = 0.3
                        edge_type = EdgeType.DATA_DEPENDENCY
                    graph.add_edge(Edge(
                        edge_id=create_edge_id(last_observation.node_id, call.node_id, edge_type),
                        source_id=last_observation.node_id,
                        target_id=call.node_id,
                        edge_type=edge_type,
                        weight=weight,
                        timestamp=event.timestamp,
                        metadata={"fields_from_observation": fields},
                    ))
                for key, value in _sensitive_entities(original_parameters):
                    entity_number += 1
                    entity = EntityNode(
                        node_id=f"entity_{entity_number}",
                        node_type=None,
                        timestamp=event.timestamp,
                        session_id=trajectory.session_id,
                        entity_type="sensitive_parameter",
                        sensitivity="secret",
                        value_hash=_hash(value),
                        metadata={"parameter_key": key, "source_call": call.node_id},
                    )
                    graph.add_node(entity)
                    graph.add_edge(Edge(
                        edge_id=create_edge_id(call.node_id, entity.node_id, EdgeType.DATA_DERIVATION),
                        source_id=call.node_id,
                        target_id=entity.node_id,
                        edge_type=EdgeType.DATA_DERIVATION,
                        weight=1.0,
                        timestamp=event.timestamp,
                    ))
                calls_by_id[event.call_id] = call if event.call_id else call
                last_call = call
                continue
            if event.event_type == "tool_result":
                call = calls_by_id.get(event.call_id or "", last_call)
                if call is None:
                    continue
                observation_number += 1
                trust = _trust_level(event)
                content = _stringify(event.tool_result)
                observation = ObservationNode(
                    node_id=f"obs_{observation_number}",
                    node_type=None,
                    timestamp=event.timestamp,
                    session_id=trajectory.session_id,
                    data_source=event.metadata.get("data_source", call.tool_name),
                    trust_label=trust,
                    content_hash=_hash(event.tool_result),
                    content_preview=(
                        _redact(content) if self.redact_sensitive else content
                    )[: self.max_content_preview],
                    provenance=list(event.metadata.get("provenance", [call.tool_name])),
                    metadata={
                        "event_id": event.event_id,
                        "call_id": event.call_id,
                        "seq": event.seq,
                        "decision": event.decision,
                        **event.metadata,
                    },
                )
                graph.add_node(observation)
                graph.add_edge(Edge(
                    edge_id=create_edge_id(call.node_id, observation.node_id, EdgeType.DATA_DERIVATION),
                    source_id=call.node_id,
                    target_id=observation.node_id,
                    edge_type=EdgeType.DATA_DERIVATION,
                    weight=0.8,
                    timestamp=event.timestamp,
                ))
                last_observation = observation

        return graph


def build_graph(trajectory: OpenClawTrajectory | Mapping[str, Any]) -> CausalGraph:
    """Functional wrapper used by scripts and notebooks."""
    return OpenClawGraphBuilder().build(trajectory)
