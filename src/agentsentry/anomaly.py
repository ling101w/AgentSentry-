from __future__ import annotations

from collections import Counter
from math import log2
from typing import Any

from .models import Confidentiality, DataValue, DetectionVerdict, FindingType, GuardFinding, Integrity, TaskSpec, ToolAction
from .policy import unwrap_arg

try:  # pragma: no cover - exercised when sklearn is installed in the runtime image
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover - keeps the prototype usable in constrained installs
    IsolationForest = None  # type: ignore[assignment]


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

SENSITIVE_MARKERS = ("secret", "token", "api_key", "password", "credential", "system_prompt", ".env", "openclaw.json")
TRAVERSAL_MARKERS = ("..", "/etc", "startup", "system32", "~/.ssh")
EXTERNAL_MARKERS = ("attacker@", "evil@", "exfil", "webhook", "pastebin", "requestbin")


class BehaviorAnomalyDetector:
    """Small feature-model baseline for runtime anomaly detection.

    This is intentionally lightweight: the deterministic policy remains the hard
    boundary, while this model catches unusual tool/argument/sequence patterns
    and produces an explainable learned finding for the dashboard and reports.
    """

    def __init__(self) -> None:
        self.enabled = IsolationForest is not None
        self.model = None
        if not self.enabled:
            return
        self.model = IsolationForest(n_estimators=80, contamination=0.08, random_state=17)
        self.model.fit(_training_vectors())

    def assess(self, action: ToolAction, task_spec: TaskSpec, history: list[dict[str, Any]]) -> GuardFinding | None:
        vector = feature_vector(action, task_spec, history)
        rule_score, indicators = indicator_score(action, task_spec, history)
        model_score = 0
        if self.model is not None:
            raw = float(self.model.decision_function([vector])[0])
            model_score = max(0, min(100, round((0.08 - raw) * 420)))

        score = max(rule_score, model_score)
        if score < 35:
            return None

        verdict = DetectionVerdict.REQUIRE_APPROVAL if score < 70 else DetectionVerdict.BLOCK
        return GuardFinding(
            layer="Behavior Anomaly",
            finding_type=FindingType.LEARNED,
            verdict=verdict,
            reason="tool call is anomalous relative to normal business trajectories",
            score=score,
            evidence={
                "model": "IsolationForest",
                "model_score": model_score,
                "indicator_score": rule_score,
                "indicators": indicators[:6],
                "tool": action.tool,
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
        indicators.append("external_attacker_infrastructure")
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


def _training_vectors() -> list[list[float]]:
    synthetic: list[tuple[str, dict[str, Any], str, list[str]]] = [
        ("read_webpage", {"url": "https://example.com/"}, "summarize webpage", ["read_webpage", "call_api"]),
        ("call_api", {"url": "http://127.0.0.1:8765/api/health"}, "fetch report from API", ["read_webpage", "call_api"]),
        ("send_email", {"recipient": "user@example.com", "body": "status update"}, "send email to user@example.com", ["send_email"]),
        ("write_file", {"path": "notes/report.md", "content": "summary"}, "save report to notes/report.md", ["write_file"]),
        ("write_file", {"path": "reports/status.md", "content": "summary"}, "write report", ["write_file"]),
        ("memory_read", {"key": "report_route"}, "read memory", ["memory_read", "memory_write"]),
        ("memory_write", {"key": "preference", "value": "weekly summary"}, "remember preference", ["memory_read", "memory_write"]),
    ]
    vectors: list[list[float]] = []
    for tool, args, task, allowed in synthetic:
        spec = TaskSpec(task=task, allowed_tools=allowed, forbidden_tools=[name for name in TOOL_ORDER if name not in allowed])
        vectors.append(feature_vector(ToolAction(tool=tool, args=args, reason="training"), spec, []))
        vectors.append(feature_vector(ToolAction(tool=tool, args=args, reason="training"), spec, [{"tool": "read_webpage", "decision": "allow"}]))
    return vectors


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
