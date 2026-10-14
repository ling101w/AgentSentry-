"""Run official calendar ground-truth tools through the policy boundary."""
import secrets
from pathlib import Path

import pytest

from agentsentry.agentdojo_adapter import JsonlNodeBridgeClient, make_guarded_runtime_class


@pytest.mark.parametrize("task_id", ["user_task_6", "user_task_12"])
def test_official_calendar_task_completes_with_exact_user_authorization(monkeypatch, task_id):
    pytest.importorskip("agentdojo")
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite

    monkeypatch.setenv("AGENTSENTRY_NATIVE_ENFORCEMENT", "block")
    monkeypatch.setenv("AGENTSENTRY_NATIVE_DISABLE_JUDGE", "1")
    root = Path(__file__).resolve().parents[1]
    bridge = JsonlNodeBridgeClient(["node", str(root / "openclaw-plugin/scripts/agentdojo-policy-bridge.mjs")], timeout=10)
    suite = get_suite("v1.2.2", "workspace")
    task = suite.user_tasks[task_id]
    records = []
    runtime = make_guarded_runtime_class(FunctionsRuntime, bridge, user_message=task.PROMPT,
                    session_id="trial_"+secrets.token_hex(16), record_sink=lambda r: records.append(dict(r)))
    try:
        utility, _ = suite.run_task_with_pipeline(GroundTruthPipeline(task), task, injection_task=None, injections={}, runtime_class=runtime)
        assert utility is True
        creations = [r for r in records if r["tool_name"] == "create_calendar_event"]
        assert creations and all(r["decision"] == "allow" and r["executed"] for r in creations)
        assert all(r["detector_result"]["normalized_tool"] == "calendar_write" for r in creations)
    finally:
        bridge.close()
