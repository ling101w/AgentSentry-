from __future__ import annotations

from fastapi.testclient import TestClient

from agentsentry.app import app


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

