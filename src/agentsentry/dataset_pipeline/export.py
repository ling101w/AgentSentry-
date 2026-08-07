from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from .io import normalize_text
from .schema import BENCHMARK_CASE_FIELDS, benchmark_case_from_record


def export_benchmark_cases(
    records: Iterable[Mapping[str, Any]],
    *,
    include_invalid: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    skipped_invalid: list[str] = []
    execution_mapping: Counter[str] = Counter()
    for record in records:
        quality = record.get("quality") if isinstance(record.get("quality"), Mapping) else {}
        if not include_invalid and quality.get("status") != "valid":
            skipped_invalid.append(normalize_text(record.get("id")))
            continue
        case = benchmark_case_from_record(record)
        provenance = record.get("provenance") if isinstance(record.get("provenance"), Mapping) else {}
        mapping_kind = "synthetic_command_lab_proxy" if provenance.get("mapping_synthetic_wrapper") is True else "native_command"
        execution_mapping[mapping_kind] += 1
        if mapping_kind == "synthetic_command_lab_proxy":
            marker = "execution_mapping=synthetic_command_lab_proxy"
            case["notes"] = "\n".join(value for value in (case["notes"], marker) if value)
        missing = [field for field in ("case_id", "source", "source_ref", "category", "scenario", "command", "expectation") if not case[field]]
        if missing:
            skipped_invalid.append(normalize_text(record.get("id")))
            continue
        if tuple(case) != BENCHMARK_CASE_FIELDS:
            raise AssertionError("BenchmarkCase exporter field order drifted")
        cases.append(case)
    cases.sort(key=lambda item: item["case_id"])
    report = {
        "input_records": len(cases) + len(skipped_invalid),
        "exported_cases": len(cases),
        "skipped_invalid": len(skipped_invalid),
        "skipped_ids": sorted(skipped_invalid),
        "schema_fields": list(BENCHMARK_CASE_FIELDS),
        "execution_mapping": dict(sorted(execution_mapping.items())),
    }
    return cases, report
