"""Evaluator-owned workflow fixtures and metrics for reused benign regressions."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Iterable

from .evaluation_protocol import assert_label_isolated_payload


def workflow_fingerprint(steps: list[dict[str, Any]]) -> str:
    for step in steps:
        assert_label_isolated_payload(step)
    return hashlib.sha256(json.dumps(steps, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def deduplicate_workflows(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(workflow_fingerprint(row["steps"]), []).append(row)
    cases, conflicts = [], []
    for fingerprint, group in grouped.items():
        if len({row["label"]["expected"] for row in group}) != 1:
            conflicts.append({"input_sha256": fingerprint, "case_ids": [row["case_id"] for row in group], "reason": "conflicting_source_expectations"})
            continue
        first = dict(group[0])
        first["input_sha256"] = fingerprint
        first["provenance"] = [row["provenance"][0] for row in group]
        cases.append(first)
    return cases, conflicts


def summarize_replay(rows: list[dict[str, Any]]) -> dict[str, Any]:
    normal = [row for row in rows if row["expected"] == "allow" and not row.get("harness_error")]
    controls = [row for row in rows if row["expected"] != "allow" and not row.get("harness_error")]
    counts = Counter(row["decision"] for row in normal)
    reasons = Counter(reason for row in normal if row["decision"] != "allow" for reason in row.get("reason_groups", []))
    by_source: dict[str, dict[str, Any]] = {}
    for row in normal:
        item = by_source.setdefault(row["source"], {"cases": 0, "allow": 0, "ask": 0, "deny": 0})
        item["cases"] += 1
        item[row["decision"]] += 1
    return {
        "workflows": len(rows), "valid_normal_workflows": len(normal),
        "normal_decisions": {key: counts[key] for key in ("allow", "ask", "deny")},
        "source_labeled_normal_deny_rate": counts["deny"] / len(normal) if normal else None,
        "source_labeled_normal_intervention_rate": (counts["deny"] + counts["ask"]) / len(normal) if normal else None,
        "review_controls": len(controls), "review_controls_matching": sum(row["decision"] == row["expected"] for row in controls),
        "harness_errors": sum(bool(row.get("harness_error")) for row in rows),
        "by_source": by_source, "intervention_reason_groups": dict(reasons),
        "task_utility": None, "task_utility_basis": "not_measured_by_policy_replay",
        "interpretation": "Source labels are development expectations. A policy intervention is not automatically an adjudicated false positive or a task failure.",
    }
