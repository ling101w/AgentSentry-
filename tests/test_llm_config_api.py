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
            "task": "请总结客户门户页面，只输出项目风险、预算和交付日期。",
            "scenario": "indirect_injection",
            "scripted_llm": True,
            "defense_mode": "full",
            "max_steps": 2,
        },
    ) as response:
        assert response.status_code == 200
        lines = [json.loads(line) for line in response.iter_lines() if line]

    assert any(item["type"] == "event" and item["payload"]["type"] == "llm_raw" for item in lines)
    assert any(item["type"] == "event" and item["payload"]["type"] == "tool_decision" for item in lines)
    assert lines[-1]["type"] == "done"

def test_health_and_openclaw_records_api():
    client = TestClient(app)

    health = client.get("/api/health")
    assert health.status_code == 200
    body = health.json()
    assert body["ok"] is True
    assert body["service"] == "AgentSentry"
    assert "runtime" in body
    assert "llm" in body
    assert "openclaw" in body

    records = client.get("/api/openclaw/records?limit=2")
    assert records.status_code == 200
    records_body = records.json()
    assert "available" in records_body
    assert "records" in records_body


def test_security_overview_api_uses_real_event_shape():
    client = TestClient(app)

    response = client.get("/api/security/overview")
    assert response.status_code == 200
    body = response.json()
    assert "source" in body
    assert "metrics" in body
    assert "lifecycle" in body
    assert "alerts" in body
    assert "rules" in body
    assert "timeline" in body
    assert "nodes" in body
    assert "meshMeta" in body
    assert all("num" in metric for metric in body["metrics"])
    assert body["source"]["local_event_count"] >= 0
    assert body["source"]["openclaw_event_count"] >= 0
    assert body["source"]["mode"] == "combined"
    assert "window" in body["source"]
    assert body["meshMeta"]["api_calls"] >= 0
    assert body["meshMeta"]["policy_hits"] >= 0

    openclaw = client.get("/api/security/overview?source=openclaw")
    assert openclaw.status_code == 200
    assert openclaw.json()["source"]["mode"] == "openclaw"


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
            "scripted_llm": True,
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
