from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class Decision(StrEnum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class Integrity(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Confidentiality(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SECRET = "secret"


class Label(BaseModel):
    source: str = "trusted_user"
    integrity: Integrity = Integrity.TRUSTED
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    tainted: bool = False

    @classmethod
    def trusted(cls, source: str = "trusted_user") -> "Label":
        return cls(source=source, integrity=Integrity.TRUSTED, confidentiality=Confidentiality.PUBLIC, tainted=False)

    @classmethod
    def untrusted(cls, source: str, confidentiality: Confidentiality = Confidentiality.PUBLIC) -> "Label":
        return cls(source=source, integrity=Integrity.UNTRUSTED, confidentiality=confidentiality, tainted=True)


class DataValue(BaseModel):
    value: Any
    label: Label = Field(default_factory=Label.trusted)


class TaskSpec(BaseModel):
    task: str
    allowed_tools: list[str] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    allowed_targets: list[str] = Field(default_factory=list)
    sensitive_assets: list[str] = Field(default_factory=list)
    output_policy: str = ""


class ToolAction(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class PolicyDecision(BaseModel):
    decision: Decision
    risk_score: int
    reasons: list[str] = Field(default_factory=list)
    violations: list[str] = Field(default_factory=list)
    sentry_score: int = 0
    deterministic_block: bool = False


class ToolResult(BaseModel):
    ok: bool
    output: Any = None
    error: str | None = None
    label: Label = Field(default_factory=Label.trusted)


class RunRequest(BaseModel):
    task: str
    scenario: str | None = None
    use_fake_llm: bool = False
    max_steps: int = Field(default=6, ge=1, le=20)
    defense_mode: str = "full"


class RunResponse(BaseModel):
    run_id: str
    task: str
    scenario: str | None
    decisions: list[dict[str, Any]]
    final_output: str


class Event(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evt"))
    run_id: str
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now)


class EvalResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("eval"))
    suite: str
    defense_mode: str
    metrics: dict[str, Any]
    created_at: str = Field(default_factory=utc_now)

