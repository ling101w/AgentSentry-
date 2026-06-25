from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from .models import (
    Confidentiality,
    DataValue,
    Decision,
    DetectionVerdict,
    FindingType,
    GuardFinding,
    Integrity,
    Label,
    PolicyDecision,
    TaskSpec,
    ToolAction,
)


HIGH_RISK_TOOLS = {"send_email", "write_file", "call_api"}
SYSTEM_PATH_MARKERS = ("..", "~", "/etc", "\\windows", "startup", "system32")


@dataclass(frozen=True)
class Policy:
    allowlisted_recipients: set[str]
    allowlisted_api_hosts: set[str]
    write_roots: set[str]
    sensitive_assets: set[str]
    ask_threshold: int
    deny_threshold: int
    rules: list[dict[str, Any]]

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        allowlist = raw.get("allowlist", {})
        thresholds = raw.get("risk_thresholds", {})
        return cls(
            allowlisted_recipients=set(allowlist.get("email_recipients", [])),
            allowlisted_api_hosts=set(allowlist.get("api_hosts", [])),
            write_roots=set(allowlist.get("write_roots", [])),
            sensitive_assets=set(raw.get("sensitive_assets", [])),
            ask_threshold=int(thresholds.get("ask", 40)),
            deny_threshold=int(thresholds.get("deny", 70)),
            rules=list(raw.get("rules", [])),
        )

    def rule_for(self, tool: str) -> dict[str, Any] | None:
        for rule in self.rules:
            if rule.get("sink") == tool:
                return rule
        return None


def derive_task_spec(task: str, sensitive_assets: set[str] | None = None) -> TaskSpec:
    lowered = task.lower()
    assets = sorted(sensitive_assets or {"secret.txt", "api_key", "token"})
    allowed = ["read_webpage", "call_api"]
    forbidden = ["read_file", "write_file", "send_email", "memory_write"]
    output_policy = "Only answer the user; do not exfiltrate data."

    if any(word in lowered for word in ["email", "mail", "send to", "发邮件", "发送"]):
        allowed.append("send_email")
        if "send_email" in forbidden:
            forbidden.remove("send_email")
        output_policy = "Email only approved recipients when explicitly requested."

    if any(word in lowered for word in ["write", "save", "report", "保存", "写入", "生成报告"]):
        allowed.append("write_file")
        if "write_file" in forbidden:
            forbidden.remove("write_file")

    if any(word in lowered for word in ["file", "secret", "read", "读取文件"]):
        allowed.append("read_file")
        if "read_file" in forbidden:
            forbidden.remove("read_file")

    if any(word in lowered for word in ["memory", "remember", "记住", "记忆"]):
        allowed.extend(["memory_read", "memory_write"])
        forbidden = [tool for tool in forbidden if tool not in {"memory_write"}]

    if "summarize" in lowered or "总结" in task:
        allowed.append("read_webpage")

    # Stable order without duplicates.
    allowed = list(dict.fromkeys(allowed))
    forbidden = [tool for tool in dict.fromkeys(forbidden) if tool not in allowed]
    return TaskSpec(
        task=task,
        allowed_tools=allowed,
        forbidden_tools=forbidden,
        allowed_targets=["mock://benign", "mock://attack", "mock://polluted"],
        sensitive_assets=assets,
        output_policy=output_policy,
    )


def combine_labels(values: list[DataValue | Label | Any]) -> Label:
    labels: list[Label] = []
    for value in values:
        if isinstance(value, DataValue):
            labels.append(value.label)
        elif isinstance(value, Label):
            labels.append(value)
    if not labels:
        return Label.trusted()

    integrity = Integrity.TRUSTED
    confidentiality = Confidentiality.PUBLIC
    sources: list[str] = []
    tainted = False
    for label in labels:
        sources.append(label.source)
        if label.integrity == Integrity.UNTRUSTED:
            integrity = Integrity.UNTRUSTED
        if label.confidentiality == Confidentiality.SECRET:
            confidentiality = Confidentiality.SECRET
        elif label.confidentiality == Confidentiality.INTERNAL and confidentiality != Confidentiality.SECRET:
            confidentiality = Confidentiality.INTERNAL
        tainted = tainted or label.tainted
    return Label(source="+".join(dict.fromkeys(sources)), integrity=integrity, confidentiality=confidentiality, tainted=tainted)


def label_for_path(path: str, policy: Policy) -> Label:
    lowered = path.lower()
    confidentiality = Confidentiality.PUBLIC
    if any(asset.lower() in lowered for asset in policy.sensitive_assets):
        confidentiality = Confidentiality.SECRET
    return Label(source=f"file:{path}", integrity=Integrity.UNTRUSTED, confidentiality=confidentiality, tainted=True)


def arg_label(arg: Any) -> Label:
    if isinstance(arg, DataValue):
        return arg.label
    return Label.trusted("agent_argument")


def unwrap_arg(arg: Any) -> Any:
    return arg.value if isinstance(arg, DataValue) else arg


def host_from_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme == "mock":
        return "mock.local"
    return parsed.hostname or ""


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


class PolicyEngine:
    def __init__(self, policy: Policy, deterministic_enabled: bool = True):
        self.policy = policy
        self.deterministic_enabled = deterministic_enabled
        self.api_call_counts: dict[str, int] = {}

    def decide(
        self,
        action: ToolAction,
        task_spec: TaskSpec,
        sentry_score: int = 0,
        findings: list[GuardFinding] | None = None,
    ) -> PolicyDecision:
        findings = findings or []
        reasons: list[str] = []
        violations: list[str] = []
        risk = self._base_tool_risk(action.tool)

        if self.deterministic_enabled and (action.tool in task_spec.forbidden_tools or action.tool not in task_spec.allowed_tools):
            violations.append(f"tool {action.tool} is outside TaskSpec")
        elif action.tool in task_spec.forbidden_tools or action.tool not in task_spec.allowed_tools:
            risk += 50
        else:
            reasons.append("tool is allowed by TaskSpec")

        risk += self._taint_risk(action)
        risk += sentry_score

        deterministic_finding_reasons = [
            finding.reason
            for finding in findings
            if finding.finding_type == FindingType.DETERMINISTIC and finding.layer == "Execution Control"
        ]
        if deterministic_finding_reasons:
            violations = _unique(violations + deterministic_finding_reasons)
        elif self.deterministic_enabled:
            violations.extend(self._deterministic_violations(action, task_spec))

        if violations:
            risk += 35

        deterministic_block = bool(violations)
        decision = Decision.ALLOW
        if deterministic_block:
            rule = self.policy.rule_for(action.tool)
            decision = Decision(rule.get("on_violation", "deny")) if rule else Decision.DENY
            if decision == Decision.ASK:
                decision = Decision.DENY
        elif any(finding.verdict == DetectionVerdict.BLOCK for finding in findings if finding.finding_type != FindingType.DETERMINISTIC):
            decision = Decision.DENY
        elif risk >= self.policy.deny_threshold:
            decision = Decision.DENY
        elif any(
            finding.verdict == DetectionVerdict.REQUIRE_APPROVAL
            for finding in findings
            if finding.finding_type != FindingType.DETERMINISTIC
        ) or risk >= self.policy.ask_threshold:
            decision = Decision.ASK

        return PolicyDecision(
            decision=decision,
            risk_score=min(risk, 150),
            reasons=reasons,
            violations=violations,
            sentry_score=sentry_score,
            deterministic_block=deterministic_block,
        )

    def deterministic_findings(self, action: ToolAction, task_spec: TaskSpec) -> list[GuardFinding]:
        findings: list[GuardFinding] = []
        if self.deterministic_enabled and (action.tool in task_spec.forbidden_tools or action.tool not in task_spec.allowed_tools):
            findings.append(
                GuardFinding(
                    layer="Execution Control",
                    finding_type=FindingType.DETERMINISTIC,
                    verdict=DetectionVerdict.BLOCK,
                    reason=f"tool {action.tool} is outside TaskSpec",
                    score=100,
                    evidence={"tool": action.tool},
                )
            )
        if self.deterministic_enabled:
            for violation in self._deterministic_violations(action, task_spec):
                findings.append(
                    GuardFinding(
                        layer="Execution Control",
                        finding_type=FindingType.DETERMINISTIC,
                        verdict=DetectionVerdict.BLOCK,
                        reason=violation,
                        score=100,
                        evidence={"tool": action.tool},
                    )
                )
        return findings

    def _base_tool_risk(self, tool: str) -> int:
        return {
            "read_file": 30,
            "write_file": 35,
            "send_email": 40,
            "call_api": 20,
            "memory_write": 25,
            "memory_read": 10,
            "read_webpage": 10,
        }.get(tool, 20)

    def _taint_risk(self, action: ToolAction) -> int:
        risk = 0
        for value in action.args.values():
            label = arg_label(value)
            if label.integrity == Integrity.UNTRUSTED:
                risk += 25
            if label.confidentiality == Confidentiality.SECRET:
                risk += 45
        return min(risk, 80)

    def _deterministic_violations(self, action: ToolAction, task_spec: TaskSpec) -> list[str]:
        if not self.policy.rule_for(action.tool):
            return []
        checks = {
            "send_email": self._check_send_email,
            "write_file": self._check_write_file,
            "call_api": self._check_call_api,
        }
        checker = checks.get(action.tool)
        return checker(action, task_spec) if checker else []

    def _check_send_email(self, action: ToolAction, task_spec: TaskSpec) -> list[str]:
        violations: list[str] = []
        recipient = str(unwrap_arg(action.args.get("recipient", "")))
        body = action.args.get("body", "")
        recipient_label = arg_label(action.args.get("recipient", ""))
        body_label = arg_label(body)
        if recipient_label.integrity != Integrity.TRUSTED:
            violations.append("recipient is not trusted")
        if recipient not in self.policy.allowlisted_recipients:
            violations.append(f"recipient {recipient} is not allowlisted")
        if body_label.confidentiality == Confidentiality.SECRET:
            violations.append("body contains secret-tainted data")
        if body_label.integrity == Integrity.UNTRUSTED:
            violations.append("untrusted data cannot flow to email sink")
        if "send_email" not in task_spec.allowed_tools:
            violations.append("task intent does not allow email")
        return violations

    def _check_write_file(self, action: ToolAction, task_spec: TaskSpec) -> list[str]:
        path = str(unwrap_arg(action.args.get("path", ""))).replace("\\", "/").lower()
        violations: list[str] = []
        if not path:
            violations.append("missing write path")
        if any(marker in path for marker in SYSTEM_PATH_MARKERS):
            violations.append("write path looks like a system or traversal path")
        root = path.split("/", 1)[0]
        if root not in self.policy.write_roots:
            violations.append(f"write root {root or '<empty>'} is not allowlisted")
        content_label = arg_label(action.args.get("content", ""))
        if content_label.integrity == Integrity.UNTRUSTED:
            violations.append("untrusted data cannot flow to file sink")
        if content_label.confidentiality == Confidentiality.SECRET:
            violations.append("content contains secret-tainted data")
        if "write_file" not in task_spec.allowed_tools:
            violations.append("task intent does not allow file write")
        return violations

    def _check_call_api(self, action: ToolAction, task_spec: TaskSpec) -> list[str]:
        url = str(unwrap_arg(action.args.get("url", "")))
        host = host_from_url(url)
        self.api_call_counts[host] = self.api_call_counts.get(host, 0) + 1
        violations: list[str] = []
        if host not in self.policy.allowlisted_api_hosts:
            violations.append(f"api host {host or '<empty>'} is not allowlisted")
        if self.api_call_counts[host] > 10:
            violations.append("api rate exceeds configured limit")
        payload_label = arg_label(action.args.get("body", ""))
        if payload_label.confidentiality == Confidentiality.SECRET:
            violations.append("api request contains secret-tainted data")
        if "call_api" not in task_spec.allowed_tools:
            violations.append("task intent does not allow API calls")
        return violations
