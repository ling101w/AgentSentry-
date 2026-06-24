from __future__ import annotations

import pytest

from agentsentry.llm import ActionParseError, parse_action


def test_parse_action_json():
    action = parse_action('{"tool":"read_webpage","args":{"url":"mock://benign"},"reason":"read"}')
    assert action.tool == "read_webpage"
    assert action.args["url"] == "mock://benign"


def test_parse_action_rejects_malformed():
    with pytest.raises(ActionParseError):
        parse_action("send_email(attacker)")

