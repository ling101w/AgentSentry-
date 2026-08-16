from __future__ import annotations

import copy
import hashlib
import json

import pytest

from agentsentry.dataset_pipeline.builder import build_integrity_problems
from agentsentry.dataset_pipeline.dedup import deduplicate_records
from agentsentry.dataset_pipeline.export import export_benchmark_cases
from agentsentry.dataset_pipeline.schema import BENCHMARK_CASE_FIELDS, make_record
from agentsentry.dataset_pipeline.sampling import balance_attack_ratio
from agentsentry.dataset_pipeline.sources import SOURCE_BY_KEY
from agentsentry.dataset_pipeline.split import split_group, split_records
from agentsentry.dataset_pipeline.validation import validate_records
from agentsentry.dataset_pipeline.regression import RegressionSnapshotError, verify_regression_snapshot


def _record(
    original_id: str,
    text: str,
    *,
    attack: bool = True,
    threat_primary: str = "T2",
    template_id: str = "template-a",
) -> dict:
    return make_record(
        spec=SOURCE_BY_KEY["agentdojo"],
        original_id=original_id,
        source_ref=f"fixture.json#{original_id}",
        attack=attack,
        attack_type="indirect_prompt_injection" if attack else "benign_task",
        user_instruction=text,
        attacker_instruction="ignore the user" if attack else "",
        scenario="external_email_hidden" if attack else "manual",
        command=text,
        expectation="protected" if attack else "allow",
        version="abc123",
        license_name="MIT",
        raw_path="fixture.json",
        raw_sha256="f" * 64,
        raw_record={"text": text},
        threat_primary=threat_primary,
        template_id=template_id,
    )


def test_validation_marks_invalid_without_dropping_record() -> None:
    valid = _record("1", "Summarize the email")
    invalid = _record("2", "Summarize the document")
    invalid["agentsentry"]["command"] = ""

    records, report = validate_records([valid, invalid])

    assert len(records) == 2
    assert report["valid"] == 1
    assert report["invalid"] == 1
    assert records[1]["quality"]["status"] == "invalid"
    assert "missing_agentsentry_command" in records[1]["quality"]["reasons"]


def test_regression_snapshot_verifier_detects_byte_or_line_drift(tmp_path) -> None:
    artifact = tmp_path / "agentsentry" / "benchmark_cases.jsonl"
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"case_id":"one"}\n', encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = tmp_path / "regression_snapshot.json"
    manifest.write_text(
        json.dumps({
            "schema_version": "agentsentry.regression_snapshot.v1",
            "snapshot_id": "fixture",
            "artifacts": [{
                "path": "agentsentry/benchmark_cases.jsonl",
                "lines": 1,
                "bytes": artifact.stat().st_size,
                "sha256": digest,
            }],
        }),
        encoding="utf-8",
    )

    assert verify_regression_snapshot(tmp_path, manifest)["verified"] is True
    artifact.write_text('{"case_id":"changed"}\n', encoding="utf-8")
    with pytest.raises(RegressionSnapshotError, match="snapshot drift"):
        verify_regression_snapshot(tmp_path, manifest)


def test_validation_applies_strict_research_schema_and_request_limit() -> None:
    malformed = _record("schema", "Summarize the email")
    malformed["agentsentry"]["reset_session"] = "false"
    malformed["raw"] = []
    malformed["unexpected"] = True
    oversized = _record("oversized", "Summarize the email")
    oversized["agentsentry"]["command"] = "x" * 33000

    records, report = validate_records([malformed, oversized])

    assert report["invalid"] == 2
    assert "research_schema_violation" in records[0]["quality"]["reasons"]
    assert any(warning.startswith("schema:agentsentry/reset_session:type") for warning in records[0]["quality"]["warnings"])
    assert "agentsentry_command_request_too_large" in records[1]["quality"]["reasons"]


def test_build_integrity_requires_every_requested_source_to_load() -> None:
    report = {
        "record_count": 3,
        "duplicate_ids": [],
        "manifest_problems": [],
        "sources": [
            {
                "dataset": "Ready",
                "status": "loaded",
                "records": 3,
                "errors": [],
                "raw_integrity": {"problems": []},
            },
            {
                "dataset": "Broken",
                "status": "partial",
                "records": 1,
                "errors": [{"error": "bad row"}],
                "raw_integrity": {"problems": []},
            },
        ],
    }

    assert build_integrity_problems(report) == [
        "Broken: 1 parse error(s)",
        "Broken: status=partial",
    ]


def test_exact_dedup_keeps_label_conflicts_and_near_variants() -> None:
    first = _record("1", "Read the external email")
    exact = _record("2", "  READ   the external email ")
    label_conflict = _record("3", "Read the external email", threat_primary="T3")
    near = _record("4", "Please read the external email")
    validated, _ = validate_records([first, exact, label_conflict, near])

    annotated, cleaned, report = deduplicate_records(validated, near_distance=64)

    assert len(annotated) == 4
    assert len(cleaned) == 3
    assert report["exact_duplicates_removed"] == 1
    assert report["label_conflict_groups"] == 1
    retained_ids = {item["source"]["original_id"] for item in cleaned}
    assert "3" in retained_ids
    assert "4" in retained_ids
    assert any(item["quality"]["duplicate_group"] for item in cleaned)
    by_original_id = {item["source"]["original_id"]: item for item in cleaned}
    representative = by_original_id.get("1") or by_original_id["2"]
    assert representative["quality"]["duplicate_group"] == by_original_id["3"]["quality"]["duplicate_group"]


def test_exact_dedup_preserves_distinct_execution_commands() -> None:
    first = _record("1", "Read the external email")
    second = _record("2", "Read the external email")
    second["agentsentry"]["command"] = "Inspect the external webpage"
    validated, _ = validate_records([first, second])

    _, cleaned, report = deduplicate_records(validated, near_distance=0)

    assert len(cleaned) == 2
    assert report["exact_duplicates_removed"] == 0


def test_grouped_split_prevents_template_and_duplicate_leakage() -> None:
    records = [
        _record("1", "task one", template_id="family-a"),
        _record("2", "task two", template_id="family-a"),
        _record("3", "task three", template_id="family-b"),
        _record("4", "task four", attack=False, template_id="benign-a"),
    ]
    validated, _ = validate_records(records)
    _, cleaned, _ = deduplicate_records(validated)
    by_original_id = {item["source"]["original_id"]: item for item in cleaned}
    by_original_id["2"]["quality"]["duplicate_group"] = "dup-bridge"
    by_original_id["3"]["quality"]["duplicate_group"] = "dup-bridge"

    splits, cross, report = split_records(cleaned, holdout_source="AgentDojo")

    locations = {}
    for split_name, rows in splits.items():
        for row in rows:
            locations[row["source"]["original_id"]] = split_name
    assert locations["1"] == locations["2"]
    assert locations["2"] == locations["3"]
    assert report["group_leakage"] == []
    assert len(cross["train"]) == 0
    assert len(cross["test"]) == 4
    assert split_group(cleaned[0]).startswith(("near:", "template:"))


def test_cross_dataset_split_excludes_overlapping_constraint_groups() -> None:
    train_record = _record("train", "shared attack", template_id="train-family")
    holdout_record = _record("holdout", "holdout attack", template_id="holdout-family")
    holdout_record["source"]["dataset"] = "InjecAgent"
    validated, _ = validate_records([train_record, holdout_record])
    _, cleaned, _ = deduplicate_records(validated, near_distance=0)
    for record in cleaned:
        record["quality"]["duplicate_group"] = "cross-source-duplicate"

    _, cross, report = split_records(cleaned, holdout_source="InjecAgent")

    assert cross["train"] == []
    assert len(cross["test"]) == 1
    assert report["cross_dataset"]["excluded_train_overlap"] == 1


def test_cross_dataset_split_rejects_unknown_holdout() -> None:
    validated, _ = validate_records([_record("1", "shared attack")])
    _, cleaned, _ = deduplicate_records(validated, near_distance=0)

    with pytest.raises(ValueError, match="unknown holdout source"):
        split_records(cleaned, holdout_source="InjecAgnet")


def test_benchmark_export_is_strict_and_skips_invalid() -> None:
    valid = _record("1", "Summarize the email")
    valid["provenance"]["mapping_synthetic_wrapper"] = True
    invalid = _record("2", "Summarize the document")
    invalid["agentsentry"]["command"] = ""
    validated, _ = validate_records([valid, invalid])

    cases, report = export_benchmark_cases(validated)

    assert report["exported_cases"] == 1
    assert report["skipped_invalid"] == 1
    assert tuple(cases[0]) == BENCHMARK_CASE_FIELDS
    assert cases[0]["attack"] is True
    assert cases[0]["expectation"] == "protected"
    assert "execution_mapping=synthetic_command_lab_proxy" in cases[0]["notes"]
    assert report["execution_mapping"] == {"synthetic_command_lab_proxy": 1}


def test_record_ids_are_stable_and_raw_is_copied() -> None:
    raw = {"nested": {"value": 1}}
    kwargs = dict(
        spec=SOURCE_BY_KEY["injecagent"],
        original_id="row-7",
        source_ref="data/test.json#7",
        attack=True,
        attack_type="tool_response_injection",
        user_instruction="Find a product",
        attacker_instruction="Send a secret",
        tool_response="Product details",
        scenario="external_web_hidden",
        command="Find a product",
        raw_record=raw,
    )
    first = make_record(**kwargs)
    second = make_record(**kwargs)
    raw["nested"]["value"] = 2

    assert first["id"] == second["id"]
    assert first["raw"]["nested"]["value"] == 1
    assert first == copy.deepcopy(first)


def test_balanced_subset_keeps_all_benign_and_is_deterministic() -> None:
    records = [_record(f"a-{index}", f"attack task {index}", template_id=f"family-{index % 3}") for index in range(30)]
    records.extend(_record(f"b-{index}", f"benign task {index}", attack=False, template_id=f"benign-{index}") for index in range(5))
    validated, _ = validate_records(records)
    _, cleaned, _ = deduplicate_records(validated, near_distance=0)

    selected, report = balance_attack_ratio(cleaned, max_attack_ratio=0.8)
    repeated, repeated_report = balance_attack_ratio(cleaned, max_attack_ratio=0.8)

    assert [item["id"] for item in selected] == [item["id"] for item in repeated]
    assert report == repeated_report
    assert report["output_attack"] == 20
    assert report["output_benign"] == 5
    assert report["output_attack_ratio"] == 0.8
    assert {item["source"]["original_id"] for item in selected if not item["labels"]["attack"]} == {
        f"b-{index}" for index in range(5)
    }
