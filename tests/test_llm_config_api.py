from __future__ import annotations

import json

from fastapi.testclient import TestClient

from agentsentry.app import app
from agentsentry.llm import OpenAICompatibleClient
from agentsentry.models import Event
from agentsentry.app import store


def test_llm_config_api(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("OPENAI_MODEL", "demo-model")
    client = TestClient(app)
    response = client.get("/api/llm/config")
    assert response.status_code == 200
    assert response.json() == {
        "configured": True,
        "base_url": "https://example.test/v1",
        "model": "demo-model",
    }


def test_openai_compatible_client_uses_same_env_config(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.test/v1/")
    monkeypatch.setenv("OPENAI_MODEL", "demo-model")

    client = OpenAICompatibleClient()

    assert client.api_key == "test-key"
    assert client.base_url == "https://example.test/v1"
    assert client.model == "demo-model"


def test_run_stream_returns_incremental_events():
    client = TestClient(app)
    with client.stream(
        "POST",
        "/api/runs/stream",
        json={
            "task": "Summarize mock://attack. Do not email anyone.",
            "scenario": "indirect_injection",
            "use_fake_llm": True,
            "defense_mode": "full",
            "max_steps": 2,
        },
    ) as response:
        assert response.status_code == 200
        lines = [json.loads(line) for line in response.iter_lines() if line]

    assert any(item["type"] == "event" and item["payload"]["type"] == "llm_raw" for item in lines)
    assert any(item["type"] == "event" and item["payload"]["type"] == "tool_decision" for item in lines)
    assert lines[-1]["type"] == "done"


def test_run_stream_uses_run_scoped_event_query():
    store().reset()
    for index in range(230):
        run_id = f"noise-stream-{index}"
        store().create_run(run_id, "noise", None, "full")
        store().add_event(Event(run_id=run_id, type="noise", payload={"index": index}))

    client = TestClient(app)
    with client.stream(
        "POST",
        "/api/runs/stream",
        json={
            "run_id": "stream-target",
            "task": "Summarize mock://benign.",
            "scenario": "benign_summary",
            "use_fake_llm": True,
            "defense_mode": "full",
            "max_steps": 2,
        },
    ) as response:
        assert response.status_code == 200
        lines = [json.loads(line) for line in response.iter_lines() if line]

    target_events = [item for item in lines if item["type"] == "event" and item["payload"]["run_id"] == "stream-target"]
    assert [event["payload"]["type"] for event in target_events][:2] == ["task_spec", "llm_raw"]
    assert any(event["payload"]["type"] == "tool_decision" for event in target_events)
    store().reset()
