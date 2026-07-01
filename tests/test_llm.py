from __future__ import annotations

import pytest
import httpx

from agentsentry.llm import ActionParseError, OpenAICompatibleClient, parse_action


def test_parse_action_json():
    action = parse_action('{"tool":"read_webpage","args":{"url":"http://127.0.0.1:8765/api/health"},"reason":"read"}')
    assert action.tool == "read_webpage"
    assert action.args["url"] == "http://127.0.0.1:8765/api/health"


def test_parse_action_rejects_malformed():
    with pytest.raises(ActionParseError):
        parse_action("send_email(attacker)")


def test_openai_client_wraps_network_errors(monkeypatch):
    def fail_post(*args, **kwargs):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(httpx.Client, "post", fail_post)
    client = OpenAICompatibleClient(api_key="test-key", base_url="https://example.test/v1", model="demo-model", timeout=0.01)

    with pytest.raises(RuntimeError, match="LLM request failed"):
        client.next_action("Summarize.", [])


def test_openai_client_does_not_duplicate_v1_in_base_url(monkeypatch):
    seen = {}

    def capture_post(self, url, **kwargs):
        seen["url"] = url
        raise httpx.ReadTimeout("stop after capture")

    monkeypatch.setattr(httpx.Client, "post", capture_post)
    client = OpenAICompatibleClient(api_key="test-key", base_url="https://example.test/v1", model="demo-model")

    with pytest.raises(RuntimeError, match="LLM request failed"):
        client.next_action("Summarize.", [])

    assert seen["url"] == "https://example.test/v1/chat/completions"
