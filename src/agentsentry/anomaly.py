from __future__ import annotations

from collections import Counter
from math import log2
from typing import Any

from .models import Confidentiality, DataValue, DetectionVerdict, FindingType, GuardFinding, Integrity, TaskSpec, ToolAction
from .policy import unwrap_arg


TOOL_ORDER = [
    "read_webpage",
    "call_api",
    "read_file",
    "write_file",
    "send_email",
    "memory_read",
    "memory_write",
    "shell_exec",
    "exec",
    "read",
    "session_status",
    "memory_search",
]

SENSITIVE_MARKERS = ("secret", "token", "api_key", "password", "credential", "identity", "session", "system_prompt", ".env", "openclaw.json")
TRAVERSAL_MARKERS = ("..", "/etc", "startup", "system32", "~/.ssh")
EXTERNAL_MARKERS = ("exfil", "webhook", "pastebin", "requestbin", "ops-archive", "external.invalid", "ingest", "telemetry", "archive route")


class BehaviorAnomalyDetector:
    """Explainable online statistical baseline for runtime anomaly detection.

    This is intentionally lightweight: the deterministic policy remains the hard
    boundary. No synthetic training set or fitted ML model participates in the
    decision; features describe scope, novelty, frequency, and recent trajectory.
    """

    def __init__(self) -> None:
        self.enabled = True

    def assess(self, action: ToolAction, task_spec: TaskSpec, history: list[dict[str, Any]]) -> GuardFinding | None:
        vector = feature_vector(action, task_spec, history)
        score, indicators = indicator_score(action, task_spec, history)
        if score < 35:
            return None

        verdict = DetectionVerdict.REQUIRE_APPROVAL if score < 70 else DetectionVerdict.BLOCK
        return GuardFinding(
            layer="Behavior Anomaly",
            finding_type=FindingType.BEHAVIORAL,
            verdict=verdict,
            reason="tool call is anomalous relative to normal business trajectories",
            score=score,
            evidence={
                "baseline": "online_statistical",
                "indicator_score": score,
                "indicators": indicators[:6],
                "tool": action.tool,
                "feature_vector": vector,
            },
        )


def feature_vector(action: ToolAction, task_spec: TaskSpec, history: list[dict[str, Any]]) -> list[float]:
    text = _arg_text(action.args)
    recipient = str(unwrap_arg(action.args.get("recipient", ""))).lower()
    path = str(unwrap_arg(action.args.get("path", ""))).lower()
    url = str(unwrap_arg(action.args.get("url", ""))).lower()
    tool_counts = Counter(str(item.get("tool", "")) for item in history if item.get("tool"))
    recent_risky = sum(1 for item in history[-4:] if item.get("decision") in {"deny", "ask"})
    labels = [_label_of(value) for value in action.args.values()]

    vector = [
        float(TOOL_ORDER.index(action.tool) if action.tool in TOOL_ORDER else len(TOOL_ORDER)),
        float(action.tool not in task_spec.allowed_tools),
        float(action.tool in task_spec.forbidden_tools),
        float(action.tool in {"send_email", "write_file", "shell_exec", "exec", "read"}),
        float(any(marker in text.lower() for marker in SENSITIVE_MARKERS)),
        float(any(marker in text.lower() for marker in TRAVERSAL_MARKERS)),
        float(any(marker in text.lower() for marker in EXTERNAL_MARKERS)),
        float(recipient.endswith("@x.com") or ("@" in recipient and recipient not in {"user@example.com", "security@example.com"})),
        float(any(marker in path for marker in TRAVERSAL_MARKERS)),
        float(url.startswith("http://") or url.startswith("https://")),
        float(sum(1 for label in labels if label and label.integrity == Integrity.UNTRUSTED)),
        float(sum(1 for label in labels if label and label.confidentiality == Confidentiality.SECRET)),
        float(len(history)),
        float(tool_counts[action.tool]),
        float(recent_risky),
        min(len(text) / 500, 5.0),
        _entropy(text),
    ]
    return vector


def indicator_score(action: ToolAction, task_spec: TaskSpec, history: list[dict[str, Any]]) -> tuple[int, list[str]]:
    text = _arg_text(action.args).lower()
    score = 0
    indicators: list[str] = []

    if action.tool not in task_spec.allowed_tools:
        score += 25
        indicators.append("outside_task_scope")
    if action.tool in {"send_email", "write_file", "shell_exec", "exec", "read"} and action.tool not in task_spec.allowed_tools:
        score += 20
        indicators.append("high_risk_tool_scope_mismatch")
    if any(marker in text for marker in SENSITIVE_MARKERS):
        score += 30
        indicators.append("sensitive_asset_reference")
    if any(marker in text for marker in TRAVERSAL_MARKERS):
        score += 30
        indicators.append("system_or_traversal_target")
    if any(marker in text for marker in EXTERNAL_MARKERS):
        score += 30
        indicators.append("external_archive_or_telemetry_sink")
    if any((_label_of(value) and _label_of(value).integrity == Integrity.UNTRUSTED) for value in action.args.values()):
        score += 20
        indicators.append("untrusted_argument_flow")
    if any(item.get("decision") in {"deny", "ask"} for item in history[-3:]) and action.tool in {"send_email", "write_file", "exec"}:
        score += 20
        indicators.append("risky_sequence_after_block")
    if Counter(str(item.get("tool", "")) for item in history)[action.tool] >= 3:
        score += 15
        indicators.append("tool_frequency_spike")

    return min(score, 100), indicators


def _arg_text(args: dict[str, Any]) -> str:
    return " ".join(str(unwrap_arg(value)) for value in args.values())


def _label_of(value: Any):
    return value.label if isinstance(value, DataValue) else None


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * log2(count / total) for count in counts.values())
