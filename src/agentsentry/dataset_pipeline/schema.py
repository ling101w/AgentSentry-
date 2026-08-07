from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from .io import normalize_text, stable_id
from .sources import SourceSpec


SCHEMA_VERSION = "agentsentry.research_case.v1"
THREAT_CODES = frozenset({"T1", "T2", "T3", "T4", "T5", "T6"})
BENCHMARK_CASE_FIELDS = (
    "case_id",
    "source",
    "source_ref",
    "category",
    "scenario",
    "command",
    "attack",
    "expectation",
    "tool",
    "target",
    "reset_session",
    "client_id",
    "notes",
)


def make_record(
    *,
    spec: SourceSpec,
    original_id: Any,
    source_ref: str,
    attack: bool,
    attack_type: str,
    user_instruction: Any = "",
    attacker_instruction: Any = "",
    tool_response: Any = "",
    tool_name: Any = "",
    trajectory: Sequence[Any] | None = None,
    scenario: str,
    command: Any,
    expectation: str | None = None,
    tool: Any = "",
    target: Any = "",
    reset_session: bool = True,
    client_id: str = "",
    notes: Any = "",
    version: str = "",
    license_name: str = "",
    raw_path: str = "",
    raw_sha256: str = "",
    raw_record: Mapping[str, Any] | None = None,
    threat_primary: str | None = None,
    threat_secondary: Sequence[str] | None = None,
    template_id: str = "",
) -> dict[str, Any]:
    original_id_text = normalize_text(original_id)
    reference = normalize_text(source_ref)
    record_id = stable_id(spec.dataset, original_id_text, reference, prefix=spec.key)
    primary = normalize_text(threat_primary or spec.threat_primary).upper()
    secondary_values = threat_secondary if threat_secondary is not None else spec.threat_secondary
    secondary = sorted(
        {
            normalize_text(value).upper()
            for value in secondary_values
            if normalize_text(value) and normalize_text(value).upper() != primary
        }
    )
    expected = normalize_text(expectation or ("protected" if attack else "allow"))
    return {
        "schema_version": SCHEMA_VERSION,
        "id": record_id,
        "source": {
            "dataset": spec.dataset,
            "original_id": original_id_text,
            "source_ref": reference,
            "version": normalize_text(version),
            "license": normalize_text(license_name),
            "raw_path": normalize_text(raw_path),
            "raw_sha256": normalize_text(raw_sha256),
        },
        "labels": {
            "attack": bool(attack),
            "threat_primary": primary,
            "threat_secondary": secondary,
            "attack_type": normalize_text(attack_type),
        },
        "content": {
            "user_instruction": normalize_text(user_instruction),
            "attacker_instruction": normalize_text(attacker_instruction),
            "tool_response": normalize_text(tool_response),
            "tool_name": normalize_text(tool_name),
            "trajectory": copy.deepcopy(list(trajectory or [])),
        },
        "agentsentry": {
            "scenario": normalize_text(scenario),
            "command": normalize_text(command),
            "expectation": expected,
            "tool": normalize_text(tool),
            "target": normalize_text(target),
            "reset_session": bool(reset_session),
            "client_id": normalize_text(client_id) or f"dataset-{record_id}",
            "notes": normalize_text(notes),
        },
        "provenance": {
            "adapter": spec.key,
            "template_id": normalize_text(template_id),
        },
        "raw": copy.deepcopy(dict(raw_record or {})),
        "quality": {
            "status": "unchecked",
            "reasons": [],
            "warnings": [],
            "hash_input_version": "content-v1",
            "content_sha256": "",
            "duplicate_exact": False,
            "duplicate_of": "",
            "duplicate_group": "",
        },
    }


def benchmark_case_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    source = _mapping(record.get("source"))
    labels = _mapping(record.get("labels"))
    agentsentry = _mapping(record.get("agentsentry"))
    case = {
        "case_id": normalize_text(record.get("id")),
        "source": normalize_text(source.get("dataset")),
        "source_ref": normalize_text(source.get("source_ref")),
        "category": normalize_text(labels.get("attack_type")),
        "scenario": normalize_text(agentsentry.get("scenario")),
        "command": normalize_text(agentsentry.get("command")),
        "attack": bool(labels.get("attack")),
        "expectation": normalize_text(agentsentry.get("expectation")),
        "tool": normalize_text(agentsentry.get("tool")),
        "target": normalize_text(agentsentry.get("target")),
        "reset_session": bool(agentsentry.get("reset_session", True)),
        "client_id": normalize_text(agentsentry.get("client_id")),
        "notes": normalize_text(agentsentry.get("notes")),
    }
    return {field: case[field] for field in BENCHMARK_CASE_FIELDS}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}
