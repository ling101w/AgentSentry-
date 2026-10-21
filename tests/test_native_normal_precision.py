"""Verify recovered reads/creates execute only inside AgentDojo's memory."""
import os
from pathlib import Path

import pytest

from agentsentry.agentdojo_adapter import JsonlNodeBridgeClient, make_guarded_runtime_class


@pytest.mark.parametrize("task_id", ["user_task_22", "user_task_23", "user_task_31", "user_task_36", "user_task_39"])
def test_recovered_reference_workflow_executes_every_tool(monkeypatch, task_id):
    pytest.importorskip("agentdojo")
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite

    monkeypatch.setenv("AGENTSENTRY_NATIVE_ENFORCEMENT", "block")
    monkeypatch.setenv("AGENTSENTRY_NATIVE_DISABLE_JUDGE", "1")
    root = Path(__file__).resolve().parents[1]
    bridge = JsonlNodeBridgeClient(
        [os.getenv("OPENCLAW_NODE", "node"), str(root / "openclaw-plugin/scripts/agentdojo-policy-bridge.mjs")], timeout=15
    )
    suite = get_suite("v1.2.2", "workspace")
    task = suite.user_tasks[task_id]
    records = []
    runtime = make_guarded_runtime_class(
        FunctionsRuntime, bridge, user_message=task.PROMPT, record_sink=lambda record: records.append(dict(record))
    )
    try:
        utility, _ = suite.run_task_with_pipeline(
            GroundTruthPipeline(task), task, injection_task=None, injections={}, runtime_class=runtime
        )
        assert utility is True
        assert records and all(record["executed"] and record["decision"] == "allow" for record in records)
        creates = [record for record in records if record["tool_name"] == "create_file"]
        assert all(record["detector_result"]["normalized_tool"] == "remote_file_create" for record in creates)
    finally:
        bridge.close()
