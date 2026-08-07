from __future__ import annotations

import copy
import json
from collections import Counter
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .io import normalize_text
from .schema import SCHEMA_VERSION, THREAT_CODES


COMMAND_LAB_BODY_LIMIT_BYTES = 32768


def validate_records(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    id_counts = Counter(normalize_text(item.get("id")) for item in records)
    validated: list[dict[str, Any]] = []
    reason_counts: Counter[str] = Counter()
    warning_counts: Counter[str] = Counter()

    for original in records:
        record = copy.deepcopy(original)
        errors, warnings = validate_record(record)
        record_id = normalize_text(record.get("id"))
        if record_id and id_counts[record_id] > 1:
            errors.append("duplicate_id")
        errors = sorted(set(errors))
        warnings = sorted(set(warnings))
        quality = record.get("quality")
        if not isinstance(quality, dict):
            quality = {}
            record["quality"] = quality
        quality["status"] = "valid" if not errors else "invalid"
        quality["reasons"] = errors
        quality["warnings"] = warnings
        for reason in errors:
            reason_counts[reason] += 1
        for warning in warnings:
            warning_counts[warning] += 1
        validated.append(record)

    report = build_quality_report(validated)
    report["invalid_reasons"] = dict(sorted(reason_counts.items()))
    report["warnings"] = dict(sorted(warning_counts.items()))
    return validated, report


def validate_record(record: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    schema_errors = list(_research_schema_validator().iter_errors(record))
    if schema_errors:
        errors.append("research_schema_violation")
        warnings.extend(
            f"schema:{'/'.join(map(str, error.absolute_path)) or '$'}:{error.validator}"
            for error in schema_errors
        )
    source = _mapping(record.get("source"))
    labels = _mapping(record.get("labels"))
    content = _mapping(record.get("content"))
    agentsentry = _mapping(record.get("agentsentry"))

    if record.get("schema_version") != SCHEMA_VERSION:
        errors.append("unsupported_schema_version")
    if not normalize_text(record.get("id")):
        errors.append("missing_id")
    if not normalize_text(source.get("dataset")):
        errors.append("missing_source_dataset")
    if not normalize_text(source.get("source_ref")):
        errors.append("missing_source_ref")
    if "attack" not in labels or not isinstance(labels.get("attack"), bool):
        errors.append("invalid_attack_label")
    primary = normalize_text(labels.get("threat_primary")).upper()
    if primary not in THREAT_CODES:
        errors.append("invalid_threat_primary")
    secondary = labels.get("threat_secondary")
    if not isinstance(secondary, list):
        errors.append("invalid_threat_secondary")
    else:
        invalid_secondary = [value for value in secondary if normalize_text(value).upper() not in THREAT_CODES]
        if invalid_secondary:
            errors.append("invalid_threat_secondary")
        if primary in {normalize_text(value).upper() for value in secondary}:
            warnings.append("primary_repeated_as_secondary")
    if not normalize_text(labels.get("attack_type")):
        errors.append("missing_attack_type")

    trajectory = content.get("trajectory")
    if trajectory is not None and not isinstance(trajectory, list):
        errors.append("invalid_trajectory")
    original_content = any(
        normalize_text(content.get(field))
        for field in ("user_instruction", "attacker_instruction", "tool_response", "tool_name")
    ) or bool(trajectory) or bool(record.get("raw"))
    if not original_content:
        errors.append("missing_original_content")

    if not normalize_text(agentsentry.get("command")):
        errors.append("missing_agentsentry_command")
    elif _command_lab_request_bytes(record) > COMMAND_LAB_BODY_LIMIT_BYTES:
        errors.append("agentsentry_command_request_too_large")
    if not normalize_text(agentsentry.get("scenario")):
        errors.append("missing_agentsentry_scenario")
    expectation = normalize_text(agentsentry.get("expectation"))
    if expectation not in {"allow", "protected"}:
        errors.append("invalid_expectation")
    elif isinstance(labels.get("attack"), bool):
        expected = "protected" if labels["attack"] else "allow"
        if expectation != expected:
            warnings.append("expectation_label_mismatch")
    if not normalize_text(source.get("version")):
        warnings.append("missing_source_version")
    if not normalize_text(source.get("license")):
        warnings.append("missing_source_license")
    if not normalize_text(source.get("raw_sha256")):
        warnings.append("missing_raw_sha256")
    return errors, warnings


@lru_cache(maxsize=1)
def _research_schema_validator() -> Draft202012Validator:
    schema_path = Path(__file__).resolve().parents[3] / "dataset" / "schemas" / "research_case.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _command_lab_request_bytes(record: Mapping[str, Any]) -> int:
    source = _mapping(record.get("source"))
    agentsentry = _mapping(record.get("agentsentry"))
    payload: dict[str, Any] = {
        "command": normalize_text(agentsentry.get("command")),
        "scenario": normalize_text(agentsentry.get("scenario")),
        "clientId": normalize_text(agentsentry.get("client_id")),
        "resetSession": agentsentry.get("reset_session"),
        "semanticJudge": "default",
        "semanticTimeoutMs": 4000,
        "benchmarkCaseId": normalize_text(record.get("id")),
        "benchmarkSource": normalize_text(source.get("dataset")),
    }
    for source_key, request_key in (("tool", "tool"), ("target", "target")):
        value = normalize_text(agentsentry.get(source_key))
        if value:
            payload[request_key] = value
    return len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def build_quality_report(records: list[dict[str, Any]]) -> dict[str, Any]:
    status = Counter()
    by_source: Counter[str] = Counter()
    by_threat: Counter[str] = Counter()
    by_attack: Counter[str] = Counter()
    for record in records:
        quality = _mapping(record.get("quality"))
        source = _mapping(record.get("source"))
        labels = _mapping(record.get("labels"))
        status[normalize_text(quality.get("status")) or "unchecked"] += 1
        by_source[normalize_text(source.get("dataset")) or "unknown"] += 1
        by_threat[normalize_text(labels.get("threat_primary")) or "unknown"] += 1
        attack_value = labels.get("attack")
        by_attack["attack" if attack_value is True else "benign" if attack_value is False else "unknown"] += 1
    total = len(records)
    attack_count = by_attack.get("attack", 0)
    benign_count = by_attack.get("benign", 0)
    return {
        "schema_version": SCHEMA_VERSION,
        "total": total,
        "valid": status.get("valid", 0),
        "invalid": status.get("invalid", 0),
        "unchecked": status.get("unchecked", 0),
        "attack": attack_count,
        "benign": benign_count,
        "attack_ratio": round(attack_count / (attack_count + benign_count), 6) if attack_count + benign_count else 0,
        "by_source": dict(sorted(by_source.items())),
        "by_threat_primary": dict(sorted(by_threat.items())),
    }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}
