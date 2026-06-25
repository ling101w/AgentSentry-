from __future__ import annotations

from pathlib import Path

import pytest

from agentsentry.policy import Policy
from agentsentry.storage import Store
from agentsentry.tools import SandboxTools


@pytest.fixture()
def policy() -> Policy:
    return Policy.from_file(Path("policies/default.yaml"))


@pytest.fixture()
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "sandbox"
    root.mkdir()
    (root / "reports").mkdir()
    (root / "notes").mkdir()
    (root / "secret.txt").write_text("TEST_SECRET=123\n", encoding="utf-8")
    (root / "system_prompt.txt").write_text("SYSTEM_PROMPT=hidden demo policy\n", encoding="utf-8")
    return root


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "agentsentry.sqlite3")


@pytest.fixture()
def tools(sandbox: Path, policy: Policy) -> SandboxTools:
    return SandboxTools(sandbox, policy)
