from __future__ import annotations

from pathlib import Path
from typing import Any

from .builder import DatasetBuildError, build_normalized_dataset
from .dedup import deduplicate_records
from .export import export_benchmark_cases
from .io import iter_jsonl, read_json, write_json, write_jsonl
from .registry import enrich_registry_rows
from .sampling import balance_attack_ratio
from .split import split_records
from .validation import validate_records


def prepare_dataset(
    *,
    benchmark_root: Path,
    dataset_root: Path,
    manifest_path: Path | None = None,
    selected: tuple[str, ...] = (),
    near_distance: int = 6,
    split_seed: str = "agentsentry-v1",
    holdout_source: str = "InjecAgent",
    max_attack_ratio: float = 0.80,
    allow_partial: bool = False,
) -> dict[str, Any]:
    normalized, build_report = build_normalized_dataset(
        benchmark_root,
        manifest_path=manifest_path,
        selected=selected,
        allow_partial=allow_partial,
    )
    validated, quality_report = validate_records(normalized)
    annotated, cleaned, dedup_report = deduplicate_records(validated, near_distance=near_distance)
    balanced, balance_report = balance_attack_ratio(
        cleaned,
        max_attack_ratio=max_attack_ratio,
    )
    splits, cross, split_report = split_records(
        balanced,
        seed=split_seed,
        holdout_source=holdout_source,
    )
    _, full_cross, full_cross_report = split_records(
        cleaned,
        seed=split_seed,
        holdout_source=holdout_source,
    )
    cross = full_cross
    split_report["regular_input_records"] = split_report["input_records"]
    split_report["regular_eligible_records"] = split_report["eligible_records"]
    split_report["cross_dataset"] = {
        **full_cross_report["cross_dataset"],
        "input_records": full_cross_report["input_records"],
        "eligible_records": full_cross_report["eligible_records"],
        "excluded_invalid": full_cross_report["excluded_invalid"],
    }
    benchmark_cases, export_report = export_benchmark_cases(cleaned)
    balanced_cases, balanced_export_report = export_benchmark_cases(balanced)

    if not allow_partial:
        output_problems: list[str] = []
        if quality_report["invalid"]:
            output_problems.append(f"{quality_report['invalid']} invalid research record(s)")
        if not quality_report["valid"]:
            output_problems.append("no valid research records")
        if not benchmark_cases:
            output_problems.append("no BenchmarkCase records were exported")
        if export_report["skipped_invalid"]:
            output_problems.append(f"{export_report['skipped_invalid']} records were skipped during export")
        if output_problems:
            raise DatasetBuildError("refusing to replace the full dataset: " + "; ".join(output_problems))

    paths = {
        "normalized": dataset_root / "normalized" / "all.jsonl",
        "dedup_audit": dataset_root / "cleaned" / "all.annotated.jsonl",
        "cleaned": dataset_root / "cleaned" / "all.cleaned.jsonl",
        "balanced": dataset_root / "cleaned" / "all.balanced.jsonl",
        "agentsentry": dataset_root / "agentsentry" / "benchmark_cases.jsonl",
        "agentsentry_balanced": dataset_root / "agentsentry" / "benchmark_cases.balanced.jsonl",
        "quality_report": dataset_root / "quality_report.json",
        "build_report": dataset_root / "build_report.json",
        "dedup_report": dataset_root / "cleaned" / "dedup_report.json",
        "balance_report": dataset_root / "cleaned" / "balance_report.json",
        "split_report": dataset_root / "splits" / "split_report.json",
        "export_report": dataset_root / "agentsentry" / "export_report.json",
    }
    write_jsonl(paths["normalized"], validated)
    write_jsonl(paths["dedup_audit"], annotated)
    write_jsonl(paths["cleaned"], cleaned)
    write_jsonl(paths["balanced"], balanced)
    write_jsonl(paths["agentsentry"], benchmark_cases)
    write_jsonl(paths["agentsentry_balanced"], balanced_cases)
    for name, rows in splits.items():
        write_jsonl(dataset_root / "splits" / f"{name}.jsonl", rows)
    write_jsonl(dataset_root / "splits" / "cross_dataset_train.jsonl", cross["train"])
    write_jsonl(dataset_root / "splits" / "cross_dataset_test.jsonl", cross["test"])
    write_json(paths["quality_report"], quality_report)
    write_json(paths["build_report"], build_report)
    write_json(paths["dedup_report"], dedup_report)
    write_json(paths["balance_report"], balance_report)
    write_json(paths["split_report"], split_report)
    write_json(paths["export_report"], export_report)
    write_json(dataset_root / "agentsentry" / "export_report.balanced.json", balanced_export_report)

    registry_path = dataset_root / "manifest" / "source_registry.jsonl"
    registry_rows = 0
    if registry_path.exists():
        manifest = read_json(manifest_path, {}) if manifest_path and manifest_path.exists() else {}
        enriched_registry = enrich_registry_rows(list(iter_jsonl(registry_path)), validated, manifest)
        registry_rows = write_jsonl(registry_path, enriched_registry)

    summary = {
        "normalized_records": len(validated),
        "valid_records": quality_report["valid"],
        "invalid_records": quality_report["invalid"],
        "cleaned_records": len(cleaned),
        "balanced_records": len(balanced),
        "balanced_attack_ratio": balance_report["output_attack_ratio"],
        "agentsentry_cases": len(benchmark_cases),
        "agentsentry_balanced_cases": len(balanced_cases),
        "splits": split_report["counts"],
        "cross_dataset": split_report["cross_dataset"],
        "registry_rows": registry_rows,
        "outputs": {name: str(path) for name, path in paths.items()},
    }
    write_json(dataset_root / "summary.json", summary)
    return summary
