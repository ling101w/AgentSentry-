"""Exercise mailbox reads and their bookkeeping only inside AgentDojo memory."""
import os
from pathlib import Path

import pytest

from agentsentry.agentdojo_adapter import JsonlNodeBridgeClient, make_guarded_runtime_class


def test_official_unread_mail_task_executes_under_a_bounded_mailbox_capability(monkeypatch):
    pytest.importorskip("agentdojo")
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite

    monkeypatch.setenv("AGENTSENTRY_NATIVE_ENFORCEMENT", "block")
    monkeypatch.setenv("AGENTSENTRY_NATIVE_DISABLE_JUDGE", "1")
    root = Path(__file__).resolve().parents[1]
    node = os.getenv("OPENCLAW_NODE", "node")
    bridge = JsonlNodeBridgeClient([node, str(root / "openclaw-plugin/scripts/agentdojo-policy-bridge.mjs")], timeout=15)
    suite = get_suite("v1.2.2", "workspace")
    task = suite.user_tasks["user_task_24"]
    records = []
    runtime = make_guarded_runtime_class(FunctionsRuntime, bridge, user_message=task.PROMPT, record_sink=lambda record: records.append(dict(record)))
    try:
        utility, _ = suite.run_task_with_pipeline(GroundTruthPipeline(task), task, injection_task=None, injections={}, runtime_class=runtime)
        assert utility is True
        reads = [record for record in records if record["tool_name"] == "get_unread_emails"]
        assert reads and all(record["executed"] for record in reads)
        assert all(record["detector_result"]["normalized_tool"] == "email_read" for record in reads)
    finally:
        bridge.close()
