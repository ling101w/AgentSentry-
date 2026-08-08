from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.dataset_pipeline.io import atomic_write_text, iter_jsonl, sha256_file, write_json  # noqa: E402
from agentsentry.dataset_pipeline.schema import (  # noqa: E402
    BENCHMARK_CASE_FIELDS,
    THREAT_CODES,
    benchmark_case_from_record,
)
try:  # noqa: E402
    from scripts.run_benchmark_eval import BenchmarkCase, run_case, summarize
except ModuleNotFoundError:  # Direct script execution can resolve an unrelated installed `scripts` package.
    from run_benchmark_eval import BenchmarkCase, run_case, summarize


DEFAULT_RESEARCH_INPUT = ROOT / "dataset" / "cleaned" / "all.cleaned.jsonl"
DEFAULT_INPUT = ROOT / "dataset" / "agentsentry" / "benchmark_cases.jsonl"
DEFAULT_OUTPUT = ROOT / "dataset" / "agentsentry" / "run_results.json"
DEFAULT_REPORT = ROOT / "dataset" / "agentsentry" / "run_report.md"
EVALUATION_DISCLAIMER = (
    "Command-lab results measure AgentSentry policy behavior over projected cases. "
    "They do not reproduce upstream benchmark environments and must not be reported as native upstream ASR."
)
MACRO_DENOMINATORS = {
    "protection_rate": "attack_cases",
    "unsafe_release_rate": "attack_cases",
    "benign_allow_rate": "benign_cases",
    "false_positive_rate": "benign_cases",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run exported BenchmarkCase JSONL through /api/lab/command.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument(
        "--results-input",
        type=Path,
        help="Rebuild reports from an existing run payload without calling the Dashboard.",
    )
    parser.add_argument(
        "--research-input",
        type=Path,
        default=DEFAULT_RESEARCH_INPUT,
        help="ResearchCase JSONL used for primary-threat and execution-mapping metadata.",
    )
    parser.add_argument("--base-url", default=os.environ.get("AGENTSENTRY_DASHBOARD", "http://127.0.0.1:8765"))
    parser.add_argument("--output", type=Path, help=f"JSON output (live-run default: {DEFAULT_OUTPUT}).")
    parser.add_argument("--report", type=Path, help=f"Markdown output (live-run default: {DEFAULT_REPORT}).")
    parser.add_argument("--semantic-judge", choices=("default", "on", "off"), default="default")
    parser.add_argument("--semantic-timeout-ms", type=int, default=4000)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--sleep", type=float, default=0.02)
    parser.add_argument("--max-cases", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.results_input is not None:
        if args.max_cases:
            parser.error("--max-cases cannot be used with --results-input")
        if not args.dry_run and args.output is None and args.report is None:
            parser.error("--results-input requires an explicit --output and/or --report (or --dry-run)")
        if args.report is not None and args.report.resolve() == args.results_input.resolve():
            parser.error("--report cannot overwrite the JSON --results-input")
        if args.output is not None and args.report is not None and args.output.resolve() == args.report.resolve():
            parser.error("--output and --report must be different paths")
        for option, destination in (("--output", args.output), ("--report", args.report)):
            if destination is not None and destination.resolve() == args.research_input.resolve():
                parser.error(f"{option} cannot overwrite --research-input")
        payload = upgrade_results_payload(args.results_input, args.research_input)
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "cases": payload["case_count"],
                        "results_input": str(args.results_input),
                        "results_input_sha256": sha256_file(args.results_input),
                        "research_input": str(args.research_input),
                        "research_input_sha256": payload["research_input_sha256"],
                        "evaluation_mode": payload["evaluation_mode"],
                    },
                    ensure_ascii=False,
                )
            )
            return 0
        if args.output is not None:
            write_json(args.output, payload)
        if args.report is not None:
            write_report(args.report, payload)
        print(json.dumps(payload["summary"]["overall"], ensure_ascii=False))
        overall = payload["summary"]["overall"]
        return 2 if overall["harness_errors"] or overall.get("unsupported_cases", 0) else 0

    cases = load_cases(args.input)
    if args.max_cases > 0:
        cases = cases[: args.max_cases]
    result_metadata = load_result_metadata(cases, args.research_input)
    evaluation_mode = build_evaluation_mode(result_metadata)
    if args.dry_run:
        print(
            json.dumps(
                {
                    "cases": len(cases),
                    "input": str(args.input),
                    "sha256": sha256_file(args.input),
                    "research_input": str(args.research_input),
                    "research_input_sha256": sha256_file(args.research_input),
                    "evaluation_mode": evaluation_mode,
                },
                ensure_ascii=False,
            )
        )
        return 0
    if not cases:
        raise SystemExit("input contains no BenchmarkCase records")

    results: list[dict[str, Any]] = []
    started = time.monotonic()
    for index, case in enumerate(cases, start=1):
        try:
            result = run_case(
                args.base_url.rstrip("/"),
                case,
                timeout=args.timeout,
                semantic_judge=args.semantic_judge,
                semantic_timeout_ms=args.semantic_timeout_ms,
            )
        except Exception as exc:
            result = {
                "case": asdict(case),
                "ok": False,
                "protected": False,
                "unsafe_release": False,
                "false_positive": False,
                "allowed_all": False,
                "decision_sequence": [],
                "decisions": [],
                "session": {},
                "record_id": "",
                "latency_ms": None,
                "harness_error": str(exc),
                "semantic_judge": args.semantic_judge,
            }
        result["metadata"] = dict(result_metadata[case.case_id])
        results.append(result)
        if index == 1 or index % 25 == 0 or index == len(cases):
            print(f"{index}/{len(cases)} completed in {time.monotonic() - started:.1f}s")
        if args.sleep:
            time.sleep(args.sleep)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": args.base_url.rstrip("/"),
        "input": str(args.input),
        "input_sha256": sha256_file(args.input),
        "research_input": str(args.research_input),
        "research_input_sha256": sha256_file(args.research_input),
        "case_count": len(cases),
        "evaluation_mode": evaluation_mode,
        "summary": summarize_dataset(results),
        "results": results,
    }
    write_json(args.output or DEFAULT_OUTPUT, payload)
    write_report(args.report or DEFAULT_REPORT, payload)
    print(json.dumps(payload["summary"]["overall"], ensure_ascii=False))
    overall = payload["summary"]["overall"]
    return 2 if overall["harness_errors"] or overall.get("unsupported_cases", 0) else 0


def load_cases(path: Path) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    validator = benchmark_case_validator()
    for line_number, row in enumerate(iter_jsonl(path), start=1):
        cases.append(parse_benchmark_case(row, f"{path}:{line_number}", validator))
    return cases


def benchmark_case_validator() -> Draft202012Validator:
    schema = json.loads((ROOT / "dataset" / "schemas" / "benchmark_case.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def parse_benchmark_case(
    row: Mapping[str, Any],
    location: str,
    validator: Draft202012Validator,
) -> BenchmarkCase:
    schema_errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
    if schema_errors:
        first = schema_errors[0]
        field = "/".join(map(str, first.absolute_path)) or "$"
        raise ValueError(f"{location}: schema {field}: {first.message}")
    extra = sorted(set(row) - set(BENCHMARK_CASE_FIELDS))
    if extra:
        raise ValueError(f"{location}: unexpected BenchmarkCase fields: {', '.join(extra)}")
    try:
        return BenchmarkCase(**dict(row))
    except TypeError as exc:
        raise ValueError(f"{location}: {exc}") from exc


def load_result_metadata(cases: list[BenchmarkCase], path: Path) -> dict[str, dict[str, str]]:
    case_by_id: dict[str, BenchmarkCase] = {}
    for case in cases:
        if case.case_id in case_by_id:
            raise ValueError(f"duplicate BenchmarkCase case_id: {case.case_id}")
        case_by_id[case.case_id] = case

    schema = json.loads((ROOT / "dataset" / "schemas" / "research_case.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    metadata: dict[str, dict[str, str]] = {}
    for line_number, row in enumerate(iter_jsonl(path), start=1):
        record_id = str(row.get("id") or "")
        case = case_by_id.get(record_id)
        if case is None:
            continue
        if record_id in metadata:
            raise ValueError(f"{path}:{line_number}: duplicate ResearchCase id selected by benchmark input: {record_id}")
        schema_errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if schema_errors:
            first = schema_errors[0]
            location = "/".join(map(str, first.absolute_path)) or "$"
            raise ValueError(f"{path}:{line_number}: schema {location}: {first.message}")
        quality = row.get("quality") if isinstance(row.get("quality"), Mapping) else {}
        if quality.get("status") != "valid":
            raise ValueError(f"{path}:{line_number}: selected ResearchCase is not valid: {record_id}")

        labels = row.get("labels") if isinstance(row.get("labels"), Mapping) else {}
        primary_threat = str(labels.get("threat_primary") or "")
        if primary_threat not in THREAT_CODES:
            raise ValueError(f"{path}:{line_number}: invalid primary threat for {record_id}: {primary_threat!r}")
        provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
        synthetic_wrapper = provenance.get("mapping_synthetic_wrapper") is True
        execution_mapping = "synthetic_command_lab_proxy" if synthetic_wrapper else "native_command"

        expected_projection = benchmark_case_from_record(row)
        if synthetic_wrapper:
            marker = "execution_mapping=synthetic_command_lab_proxy"
            expected_projection["notes"] = "\n".join(
                value for value in (expected_projection["notes"], marker) if value
            )
        actual_projection = asdict(case)
        mismatched = [
            field
            for field in BENCHMARK_CASE_FIELDS
            if actual_projection.get(field) != expected_projection.get(field)
        ]
        if mismatched:
            raise ValueError(
                f"{path}:{line_number}: BenchmarkCase projection mismatch for {record_id}: {', '.join(mismatched)}"
            )
        metadata[record_id] = {
            "primary_threat": primary_threat,
            "execution_mapping": execution_mapping,
        }

    missing = sorted(set(case_by_id) - set(metadata))
    if missing:
        preview = ", ".join(missing[:5])
        suffix = "" if len(missing) <= 5 else f" (+{len(missing) - 5} more)"
        raise ValueError(f"{path}: missing research metadata for {len(missing)} selected case(s): {preview}{suffix}")
    return metadata


def upgrade_results_payload(results_path: Path, research_path: Path) -> dict[str, Any]:
    try:
        raw_payload = json.loads(results_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{results_path}: invalid JSON: {exc.msg}") from exc
    if not isinstance(raw_payload, dict):
        raise ValueError(f"{results_path}: expected a JSON object")
    raw_results = raw_payload.get("results")
    if not isinstance(raw_results, list):
        raise ValueError(f"{results_path}: results must be an array")

    validator = benchmark_case_validator()
    cases: list[BenchmarkCase] = []
    results: list[dict[str, Any]] = []
    for index, raw_result in enumerate(raw_results):
        location = f"{results_path}:results/{index}"
        if not isinstance(raw_result, dict):
            raise ValueError(f"{location}: expected an object")
        raw_case = raw_result.get("case")
        if not isinstance(raw_case, Mapping):
            raise ValueError(f"{location}/case: expected an object")
        case = parse_benchmark_case(raw_case, f"{location}/case", validator)
        cases.append(case)
        results.append(dict(raw_result))

    declared_count = raw_payload.get("case_count")
    if declared_count is not None and (not isinstance(declared_count, int) or declared_count != len(results)):
        raise ValueError(
            f"{results_path}: case_count {declared_count!r} does not match {len(results)} stored result(s)"
        )
    if not cases:
        raise ValueError(f"{results_path}: results contains no completed cases")

    result_metadata = load_result_metadata(cases, research_path)
    for result, case in zip(results, cases, strict=True):
        result["metadata"] = dict(result_metadata[case.case_id])

    payload = dict(raw_payload)
    payload.update(
        {
            "report_updated_at": datetime.now(timezone.utc).isoformat(),
            "research_input": str(research_path),
            "research_input_sha256": sha256_file(research_path),
            "case_count": len(results),
            "evaluation_mode": build_evaluation_mode(result_metadata),
            "summary": summarize_dataset(results),
            "results": results,
        }
    )
    return payload


def build_evaluation_mode(result_metadata: Mapping[str, Mapping[str, str]]) -> dict[str, Any]:
    counts = Counter(str(item.get("execution_mapping") or "unknown") for item in result_metadata.values())
    return {
        "mode": "command_lab_proxy",
        "endpoint": "/api/lab/command",
        "upstream_native": False,
        "execution_mapping_counts": dict(sorted(counts.items())),
        "disclaimer": EVALUATION_DISCLAIMER,
        "mapping_note": (
            "native_command describes a direct command projection only; it does not indicate native upstream benchmark execution."
        ),
    }


def summarize_dataset(results: list[dict[str, Any]]) -> dict[str, Any]:
    summary = summarize(results)
    summary["micro_overall"] = dict(summary["overall"])
    by_primary_threat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        metadata = result.get("metadata") if isinstance(result.get("metadata"), Mapping) else {}
        primary_threat = str(metadata.get("primary_threat") or "")
        if primary_threat not in THREAT_CODES:
            case = result.get("case") if isinstance(result.get("case"), Mapping) else {}
            raise ValueError(f"result for {case.get('case_id', '<unknown>')} has no valid primary_threat metadata")
        by_primary_threat[primary_threat].append(result)

    threat_rows: list[dict[str, Any]] = []
    for primary_threat, group in sorted(by_primary_threat.items()):
        row = dict(summarize(group)["overall"])
        row["name"] = primary_threat
        threat_rows.append(row)
    summary["by_primary_threat"] = threat_rows
    summary["macro_by_source"] = summarize_macro(summary["by_source"])
    summary["macro_by_primary_threat"] = summarize_macro(threat_rows)
    return summary


def summarize_macro(rows: list[dict[str, Any]]) -> dict[str, Any]:
    macro: dict[str, Any] = {
        "groups_total": len(rows),
        "eligible_groups": {},
    }
    for metric, denominator in MACRO_DENOMINATORS.items():
        eligible = [row for row in rows if int(row.get(denominator) or 0) > 0]
        macro["eligible_groups"][metric] = [str(row.get("name") or "unknown") for row in eligible]
        macro[metric] = (
            round(sum(float(row.get(metric) or 0.0) for row in eligible) / len(eligible), 4)
            if eligible
            else None
        )
    return macro


def render_report(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    overall = summary["overall"]
    evaluation = payload["evaluation_mode"]
    mapping_counts = json.dumps(evaluation.get("execution_mapping_counts", {}), ensure_ascii=False, sort_keys=True)
    lines = [
        "# AgentSentry Dataset Run",
        "",
        f"- Input SHA-256: `{payload['input_sha256']}`",
        f"- Research input SHA-256: `{payload['research_input_sha256']}`",
        "",
        "## Evaluation Mode",
        "",
        f"- Mode: `{evaluation['mode']}` via `{evaluation['endpoint']}`",
        f"- Upstream native benchmark: `{str(bool(evaluation['upstream_native'])).lower()}`",
        f"- Execution mappings: `{mapping_counts}`",
        f"- Fidelity: {evaluation['disclaimer']}",
        f"- Mapping note: {evaluation['mapping_note']}",
        "",
        "## Micro Overall",
        "",
        f"- Cases: {overall['cases']} (attack {overall['attack_cases']}, benign {overall['benign_cases']})",
        f"- Protection rate: {_format_rate(_group_rate(overall, 'protection_rate'))}",
        f"- Unsafe release rate: {_format_rate(_group_rate(overall, 'unsafe_release_rate'))}",
        f"- Benign allow rate: {_format_rate(_group_rate(overall, 'benign_allow_rate'))}",
        f"- False positive rate: {_format_rate(_group_rate(overall, 'false_positive_rate'))}",
        f"- Harness errors: {overall['harness_errors']}",
        "",
        "## Action Projection Coverage",
        "",
        f"- Faithful mapping coverage: {_format_rate(overall.get('mapping_coverage_rate'))} "
        f"({overall.get('mapping_supported_cases', 0)}/{overall.get('cases', 0)} cases).",
        f"- Unsupported projections: {overall.get('unsupported_cases', 0)} "
        f"({_format_rate(overall.get('unsupported_rate'))}); excluded from security denominators.",
        f"- Projected actions with policy decisions: {overall.get('policy_decisions', 0)}/"
        f"{overall.get('projected_actions', 0)} ({_format_rate(overall.get('action_coverage_rate'))}).",
        f"- Source overblock rate among scorable attacks: {_format_rate(overall.get('source_overblock_rate'))} "
        f"({overall.get('source_overblock_cases', 0)}/{overall.get('attack_cases', 0)}).",
        f"- Sink compatibility-affected attacks: {overall.get('compatibility_affected_attack_cases', 0)} "
        f"({_format_rate(overall.get('compatibility_affected_attack_rate'))}); "
        f"sink compatibility-only protected: {overall.get('compatibility_dependent_protected_cases', 0)} "
        f"({_format_rate(overall.get('compatibility_dependent_protected_rate'))} of protected cases).",
        f"- Compatibility-clean protection: {overall.get('compatibility_clean_protected_cases', 0)}/"
        f"{overall.get('compatibility_clean_attack_cases', 0)} "
        f"({_format_rate(overall.get('compatibility_clean_protection_rate'))}); "
        f"coverage {_format_rate(overall.get('compatibility_clean_attack_coverage_rate'))} of scorable attacks "
        f"and {_format_rate(overall.get('compatibility_clean_attempted_attack_coverage_rate'))} of attempted attacks.",
        f"- Security-attribution strict subset: {overall.get('strict_attribution_protected_cases', 0)}/"
        f"{overall.get('strict_attribution_attack_cases', 0)} "
        f"({_format_rate(overall.get('strict_attribution_protection_rate'))}); "
        f"coverage {_format_rate(overall.get('strict_attribution_attack_coverage_rate'))} of scorable attacks "
        f"and {_format_rate(overall.get('strict_attribution_attempted_attack_coverage_rate'))} of attempted attacks.",
        f"- Mapping-warning union (source overblock OR projection fallback): {overall.get('mapping_warning_union_cases', 0)} "
        f"({_format_rate(overall.get('mapping_warning_union_rate'))}); flag-clean protection: "
        f"{overall.get('mapping_flag_clean_protected_cases', 0)}/{overall.get('mapping_flag_clean_attack_cases', 0)} "
        f"({_format_rate(overall.get('mapping_flag_clean_protection_rate'))}), diagnostic only.",
        f"- Protection evidence classes: `{json.dumps(overall.get('protection_evidence_class_counts', {}), ensure_ascii=False, sort_keys=True)}`.",
        f"- Compatibility reason codes: `{json.dumps(overall.get('compatibility_reason_counts', {}), ensure_ascii=False, sort_keys=True)}`.",
        f"- Whole-case compatibility-only protected cases: {overall.get('whole_case_compatibility_only_cases', 0)}.",
        f"- False-positive policy reasons: `{json.dumps(summary.get('false_positive_reason_counts', {}), ensure_ascii=False, sort_keys=True)}`.",
        f"- Tool execution attempts: {summary.get('execution_action_counts', {}).get('attempted', 0)}; "
        f"succeeded: {summary.get('execution_action_counts', {}).get('succeeded', 0)}; "
        f"failed: {summary.get('execution_action_counts', {}).get('failed', 0)}.",
        "- Policy blocks/asks before execution are tracked separately from allowed actions whose tool execution fails.",
        f"- Projection modes: `{json.dumps(summary.get('projection_mode_counts', {}), ensure_ascii=False, sort_keys=True)}`.",
        f"- Action decisions: `{json.dumps(summary.get('action_decision_counts', {}), ensure_ascii=False, sort_keys=True)}`.",
        f"- Unsupported reasons: `{json.dumps(summary.get('unsupported_reason_counts', {}), ensure_ascii=False, sort_keys=True)}`.",
        "",
        "## Macro Summary",
        "",
        "| Grouping | Groups | Protection | Unsafe release | Benign allow | False positive |",
        "|---|---:|---:|---:|---:|---:|",
        _render_macro_row("Source", summary["macro_by_source"]),
        _render_macro_row("Primary threat", summary["macro_by_primary_threat"]),
        "",
        "## Per Source",
        "",
        *_render_group_table(summary["by_source"]),
        "",
        "## Per Primary Threat",
        "",
        *_render_group_table(summary["by_primary_threat"]),
        "",
        "Per-case decisions, alert records, primary threats, and execution mappings are stored in the JSON result file.",
        "",
    ]
    return "\n".join(lines)


def write_report(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, render_report(payload))


def _format_rate(value: Any) -> str:
    return "N/A" if value is None else f"{float(value):.2%}"


def _group_rate(row: Mapping[str, Any], metric: str) -> Any:
    denominator = MACRO_DENOMINATORS[metric]
    return row.get(metric) if int(row.get(denominator) or 0) > 0 else None


def _render_macro_row(label: str, macro: Mapping[str, Any]) -> str:
    eligible = macro.get("eligible_groups") if isinstance(macro.get("eligible_groups"), Mapping) else {}

    def cell(metric: str) -> str:
        groups = eligible.get(metric)
        count = len(groups) if isinstance(groups, list) else 0
        return f"{_format_rate(macro.get(metric))} (n={count})"

    return (
        f"| {label} | {macro.get('groups_total', 0)} | {cell('protection_rate')} | "
        f"{cell('unsafe_release_rate')} | {cell('benign_allow_rate')} | {cell('false_positive_rate')} |"
    )


def _render_group_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Group | Cases | Evaluated | Attack | Benign | Protection | Unsafe release | Benign allow | False positive | Compat affected | Strict attribution | Errors |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['name']} | {row['cases']} | {row['evaluated_cases']} | {row['attack_cases']} | "
            f"{row['benign_cases']} | {_format_rate(_group_rate(row, 'protection_rate'))} | "
            f"{_format_rate(_group_rate(row, 'unsafe_release_rate'))} | "
            f"{_format_rate(_group_rate(row, 'benign_allow_rate'))} | "
            f"{_format_rate(_group_rate(row, 'false_positive_rate'))} | "
            f"{row.get('compatibility_affected_attack_cases', 0)} | "
            f"{row.get('strict_attribution_protected_cases', 0)}/{row.get('strict_attribution_attack_cases', 0)} "
            f"({_format_rate(row.get('strict_attribution_protection_rate') if int(row.get('strict_attribution_attack_cases') or 0) else None)}) | "
            f"{row['harness_errors']} |"
        )
    return lines


if __name__ == "__main__":
    raise SystemExit(main())
