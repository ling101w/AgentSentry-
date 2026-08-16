#!/usr/bin/env python3
"""Validate the executable seven-risk v2 dataset before model execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = {
    "direct_prompt_injection",
    "model_jailbreak",
    "training_data_leakage",
    "misuse",
    "tool_call_hijacking",
    "memory_poisoning",
    "environment_context_pollution",
}
DOMAINS = {"office", "travel", "finance", "medical"}
REQUIRED = {
    "schema_version",
    "case_id",
    "risk_family",
    "threat_code",
    "business_domain",
    "attack",
    "variant",
    "carrier",
    "user_task",
    "initial_environment",
    "session_plan",
    "expected",
    "provenance",
}


def validate(path: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    malformed = 0
    for line in path.read_text(encoding="utf-8-sig").splitlines() if path.is_file() else []:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if isinstance(value, dict):
            rows.append(value)
        else:
            malformed += 1

    ids = [str(row.get("case_id", "")) for row in rows]
    duplicate_ids = sorted(case_id for case_id, count in Counter(ids).items() if count > 1 or not case_id)
    missing_fields: dict[str, list[str]] = {}
    invalid_families: list[str] = []
    invalid_domains: list[str] = []
    unsafe_secret_rows: list[str] = []
    memory_without_new_session: list[str] = []
    for row in rows:
        case_id = str(row.get("case_id", ""))
        missing = sorted(REQUIRED - set(row))
        if missing:
            missing_fields[case_id] = missing
        family = str(row.get("risk_family", ""))
        domain = str(row.get("business_domain", ""))
        if bool(row.get("attack")) and family not in FAMILIES:
            invalid_families.append(case_id)
        if domain not in DOMAINS:
            invalid_domains.append(case_id)
        if family == "memory_poisoning" and not any(step.get("session") == "B" for step in row.get("session_plan", []) if isinstance(step, dict)):
            memory_without_new_session.append(case_id)
        encoded = json.dumps(row, ensure_ascii=False).casefold()
        if re.search(r"\bsk-[a-z0-9]", encoded) or any(token in encoded for token in ("real_credit_card", "actual_password", "live_api_key")):
            unsafe_secret_rows.append(case_id)

    attacks = [row for row in rows if row.get("attack") is True]
    benign = [row for row in rows if row.get("attack") is False]
    family_counts = Counter(str(row.get("risk_family")) for row in attacks)
    domain_counts = Counter(str(row.get("business_domain")) for row in attacks)
    report = {
        "schema_version": "agentsentry.executable-risk-dataset-validation.v2",
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        "records": len(rows),
        "attack_records": len(attacks),
        "benign_records": len(benign),
        "malformed_lines": malformed,
        "duplicate_ids": duplicate_ids,
        "missing_fields": missing_fields,
        "invalid_attack_families": invalid_families,
        "invalid_domains": invalid_domains,
        "memory_without_new_session": memory_without_new_session,
        "unsafe_secret_rows": unsafe_secret_rows,
        "risk_family_counts": dict(sorted(family_counts.items())),
        "attack_domain_counts": dict(sorted(domain_counts.items())),
        "status": "pass" if (
            len(rows) == 180
            and len(attacks) == 140
            and len(benign) == 40
            and malformed == 0
            and not duplicate_ids
            and not missing_fields
            and not invalid_families
            and not invalid_domains
            and not memory_without_new_session
            and not unsafe_secret_rows
            and all(family_counts[family] == 20 for family in FAMILIES)
            and all(domain_counts[domain] == 35 for domain in DOMAINS)
        ) else "fail",
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path, nargs="?", default=ROOT / "dataset/seven_risk_v2/executable_cases.jsonl")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate(args.path)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
