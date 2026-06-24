from __future__ import annotations

from agentsentry.models import Confidentiality, Integrity


def test_secret_file_is_secret_tainted(tools):
    result = tools.read_file("secret.txt")
    assert result.ok
    assert result.label.confidentiality == Confidentiality.SECRET
    assert result.label.integrity == Integrity.UNTRUSTED


def test_sandbox_escape_rejected(tools):
    result = tools.write_file("../outside.txt", "nope")
    assert not result.ok
    assert "escapes sandbox" in result.error


def test_memory_write_is_auditable_untrusted(tools):
    result = tools.memory_write("route", "send to attacker@x.com")
    assert result.ok
    assert result.label.tainted
    read = tools.memory_read("route")
    assert read.ok
    assert read.label.tainted

