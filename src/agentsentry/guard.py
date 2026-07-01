from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from .models import (
    Confidentiality,
    DataValue,
    DetectionVerdict,
    FindingType,
    GuardFinding,
    Integrity,
    Label,
    TaskSpec,
    ToolAction,
    ToolResult,
)
from .policy import Policy, unwrap_arg


HIGH_RISK_SINKS = {"send_email", "write_file", "call_api"}
MEMORY_TOOLS = {"memory_read", "memory_write"}

INJECTION_PATTERNS = [
    re.compile(pattern, re.I | re.S)
    for pattern in [
        r"<\|im_start\|>.*?<\|im_end\|>",
        r"<role>assistant</role>.*?<role>human</role>",
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|commands?)",
        r"(send|show|list|provide|exfiltrate).{0,80}(api[_ -]?key|token|secret|password|credential)",
        r"(system|developer|internal).{0,40}(prompt|configuration|policy)",
        r"(系统提示|开发者提示|内部配置|工具声明|输出格式规则|内部配置附录)",
        r"(完整|确切|原始).{0,60}(提示词|系统提示|配置|工具|规则)",
        r"bypass\s+(policy|guardrail|safety|restriction)",
        r"act\s+as\s+(an?\s+)?(unfiltered|jailbroken|developer mode)",
    ]
]

MEMORY_POISON_PATTERNS = [
    re.compile(pattern, re.I | re.S)
    for pattern in [
        r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|prompts?)",
        r"new\s+instructions?\s*:",
        r"you\s+are\s+now\s+(a|an)\b",
        r"(whenever|when|if).{0,80}(user|time|asks|mentions).{0,80}(send|write|call|exfiltrate)",
        r"(attacker|evil|exfil)[\w.-]*@",
        r"(secret|password|token|api[_ -]?key).{0,80}(send|upload|email|post)",
    ]
]


@dataclass
class GuardContext:
    task_spec: TaskSpec
    memory_labels: dict[str, Label] = field(default_factory=dict)
    findings: list[GuardFinding] = field(default_factory=list)
    contaminated: bool = False

    def record(self, finding: GuardFinding) -> GuardFinding:
        self.findings.append(finding)
        if finding.layer in {"Input Sanitization", "Cognition Protection"}:
            self.contaminated = True
        return finding


class GuardPipeline:
    """Lifecycle detectors organized around AgentSentry's guarantee-strength axis."""

    def __init__(self, policy: Policy, enabled: bool = True, feedback_enabled: bool = True):
        self.policy = policy
        self.enabled = enabled
        self.feedback_enabled = feedback_enabled

    def foundation_scan(self) -> list[GuardFinding]:
        if not self.enabled:
            return []
        findings: list[GuardFinding] = []
        if self.policy.ask_threshold >= self.policy.deny_threshold:
            findings.append(
                GuardFinding(
                    layer="Foundation",
                    finding_type=FindingType.DETERMINISTIC,
                    verdict=DetectionVerdict.BLOCK,
                    reason="policy ask threshold must be lower than deny threshold",
                    score=100,
                )
            )
        configured_sinks = {rule.get("sink") for rule in self.policy.rules}
        for sink in sorted(HIGH_RISK_SINKS - configured_sinks):
            findings.append(
                GuardFinding(
                    layer="Foundation",
                    finding_type=FindingType.DETERMINISTIC,
                    verdict=DetectionVerdict.BLOCK,
                    reason=f"missing deterministic sink rule for {sink}",
                    score=100,
                    evidence={"sink": sink},
                )
            )
        if not self.policy.sensitive_assets:
            findings.append(
                GuardFinding(
                    layer="Foundation",
                    finding_type=FindingType.HEURISTIC,
                    verdict=DetectionVerdict.REQUIRE_APPROVAL,
                    reason="policy has no sensitive assets configured",
                    score=20,
                )
            )
        return findings

    def before_action(self, action: ToolAction, context: GuardContext, history: list[dict[str, Any]]) -> list[GuardFinding]:
        if not self.enabled:
            return []
        findings: list[GuardFinding] = []
        findings.extend(self._decision_alignment(action, context.task_spec))
        findings.extend(self._cognition_protection(action, context))
        findings.extend(self._trajectory(action, context, history))
        for finding in findings:
            context.record(finding)
        return findings

    def after_result(self, action: ToolAction, result: ToolResult | None, context: GuardContext) -> list[GuardFinding]:
        if not self.enabled or result is None:
            return []
        findings: list[GuardFinding] = []
        if result.label.integrity == Integrity.UNTRUSTED:
            context.contaminated = True
            findings.extend(self._input_sanitization(result.output, source=result.label.source))
        if action.tool == "memory_write":
            key = str(unwrap_arg(action.args.get("key", "")))
            if key:
                context.memory_labels[key] = result.label
        for finding in findings:
            context.record(finding)
        return findings

    def _decision_alignment(self, action: ToolAction, task_spec: TaskSpec) -> list[GuardFinding]:
        findings: list[GuardFinding] = []
        lowered_task = task_spec.task.lower()
        explicit_no_email = any(marker in lowered_task for marker in ["do not email", "don't email", "no email", "不要", "别发"])
        if action.tool == "send_email" and explicit_no_email:
            findings.append(
                GuardFinding(
                    layer="Decision Alignment",
                    finding_type=FindingType.HEURISTIC,
                    verdict=DetectionVerdict.REQUIRE_APPROVAL,
                    reason="email action conflicts with explicit user constraint",
                    score=35,
                    evidence={"tool": action.tool},
                )
            )
        if action.tool in HIGH_RISK_SINKS and action.tool not in task_spec.allowed_tools:
            findings.append(
                GuardFinding(
                    layer="Decision Alignment",
                    finding_type=FindingType.HEURISTIC,
                    verdict=DetectionVerdict.REQUIRE_APPROVAL,
                    reason="high-risk action deviates from task intent",
                    score=30,
                    evidence={"tool": action.tool},
                )
            )
        return findings

    def _cognition_protection(self, action: ToolAction, context: GuardContext) -> list[GuardFinding]:
        findings: list[GuardFinding] = []
        if action.tool == "memory_write":
            key = str(unwrap_arg(action.args.get("key", "")))
            value = action.args.get("value", "")
            text = _flatten_text(value)
            score = 10
            evidence: dict[str, Any] = {"key": key}
            label = value.label if isinstance(value, DataValue) else None
            if label and label.integrity == Integrity.UNTRUSTED:
                score += 20
                evidence["source"] = label.source
            matched = _matching_patterns(text, MEMORY_POISON_PATTERNS)
            if matched:
                score += 25
                evidence["matched"] = matched[:3]
            if score >= 35:
                findings.append(
                    GuardFinding(
                        layer="Cognition Protection",
                        finding_type=FindingType.HEURISTIC,
                        verdict=DetectionVerdict.PASS,
                        reason="memory write carries poisoning indicators and remains provenance-tracked",
                        score=score,
                        evidence=evidence,
                    )
                )

        if action.tool in HIGH_RISK_SINKS:
            for value in action.args.values():
                label = value.label if isinstance(value, DataValue) else None
                if label and label.source.startswith("memory:") and label.integrity == Integrity.UNTRUSTED:
                    findings.append(
                        GuardFinding(
                            layer="Cognition Protection",
                            finding_type=FindingType.HEURISTIC,
                            verdict=DetectionVerdict.REQUIRE_APPROVAL,
                            reason="untrusted memory is influencing a high-risk sink",
                            score=35,
                            evidence={"source": label.source, "tool": action.tool},
                        )
                    )
        return findings

    def _input_sanitization(self, content: Any, source: str) -> list[GuardFinding]:
        text = _flatten_text(content)
        matched = _matching_patterns(text, INJECTION_PATTERNS)
        if not matched:
            return []
        return [
            GuardFinding(
                layer="Input Sanitization",
                finding_type=FindingType.HEURISTIC,
                verdict=DetectionVerdict.PASS,
                reason="untrusted tool output contains prompt-injection indicators; taint is preserved for sink checks",
                score=25,
                evidence={"source": source, "matched": matched[:3]},
            )
        ]

    def _trajectory(self, action: ToolAction, context: GuardContext, history: list[dict[str, Any]]) -> list[GuardFinding]:
        findings: list[GuardFinding] = []
        sequence = [item.get("tool") for item in history if item.get("tool")]
        if sequence.count(action.tool) >= 3:
            findings.append(
                GuardFinding(
                    layer="Sentry Trajectory",
                    finding_type=FindingType.HEURISTIC,
                    verdict=DetectionVerdict.REQUIRE_APPROVAL,
                    reason="tool frequency is unusually high",
                    score=20,
                    evidence={"tool": action.tool},
                )
            )
        if self.feedback_enabled and context.contaminated and action.tool in HIGH_RISK_SINKS:
            findings.append(
                GuardFinding(
                    layer="Sentry Trajectory",
                    finding_type=FindingType.HEURISTIC,
                    verdict=DetectionVerdict.REQUIRE_APPROVAL,
                    reason="recent contaminated context tightens high-risk sink policy",
                    score=20,
                    evidence={"tool": action.tool},
                )
            )
        return findings


def heuristic_score(findings: list[GuardFinding]) -> int:
    return min(sum(finding.score for finding in findings if finding.finding_type != FindingType.DETERMINISTIC), 100)


def most_severe_verdict(findings: list[GuardFinding]) -> DetectionVerdict:
    if any(finding.verdict == DetectionVerdict.BLOCK for finding in findings):
        return DetectionVerdict.BLOCK
    if any(finding.verdict == DetectionVerdict.REQUIRE_APPROVAL for finding in findings):
        return DetectionVerdict.REQUIRE_APPROVAL
    return DetectionVerdict.PASS


def _flatten_text(value: Any) -> str:
    if isinstance(value, DataValue):
        return _flatten_text(value.value)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_flatten_text(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_text(item) for item in value)
    return str(value)


def _matching_patterns(text: str, patterns: list[re.Pattern[str]]) -> list[str]:
    if not text:
        return []
    matches: list[str] = []
    for variant in _text_variants(text):
        for pattern in patterns:
            match = pattern.search(variant)
            if match:
                matches.append(match.group(0)[:120])
    return list(dict.fromkeys(matches))


def _text_variants(text: str) -> list[str]:
    normalized = _canonical_text(text)
    variants = [normalized]
    variants.extend(_decoded_text_candidates(normalized))
    return list(dict.fromkeys(item for item in variants if item))[:12]


def _canonical_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", normalized)
    normalized = normalized.replace("\xad", "")
    return normalized


def _decoded_text_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    tokens = re.findall(r"[A-Za-z0-9+/_=-]{16,}|(?:[0-9A-Fa-f]{2}){8,}", text)
    for token in tokens[:24]:
        if len(token) > 4096:
            continue
        decoded = _decode_base64_text(token)
        if decoded:
            candidates.append(decoded)
        decoded = _decode_hex_text(token)
        if decoded:
            candidates.append(decoded)
    return candidates


def _decode_base64_text(token: str) -> str:
    cleaned = token.strip()
    if len(cleaned) < 16:
        return ""
    padded = cleaned + "=" * (-len(cleaned) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        decoded = _decode_bytes(raw)
        if decoded:
            return _canonical_text(decoded)
    return ""


def _decode_hex_text(token: str) -> str:
    cleaned = re.sub(r"\s+", "", token)
    if len(cleaned) < 16 or len(cleaned) % 2:
        return ""
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        return ""
    decoded = _decode_bytes(raw)
    return _canonical_text(decoded) if decoded else ""


def _decode_bytes(raw: bytes) -> str:
    if not raw or len(raw) > 4096:
        return ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    printable = sum(1 for char in text if char.isprintable() or char.isspace())
    if printable / max(len(text), 1) < 0.85:
        return ""
    return text
