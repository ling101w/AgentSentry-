from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.dataset_pipeline.io import iter_jsonl, sha256_file, write_json  # noqa: E402
from agentsentry.dataset_pipeline.schema import BENCHMARK_CASE_FIELDS  # noqa: E402
from run_benchmark_eval import BenchmarkCase, run_case, summarize  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run exported BenchmarkCase JSONL through /api/lab/command.")
    parser.add_argument("--input", type=Path, default=ROOT / "dataset" / "agentsentry" / "benchmark_cases.jsonl")
    parser.add_argument("--base-url", default=os.environ.get("AGENTSENTRY_DASHBOARD", "http://127.0.0.1:8765"))
    parser.add_argument("--output", type=Path, default=ROOT / "dataset" / "agentsentry" / "run_results.json")
    parser.add_argument("--report", type=Path, default=ROOT / "dataset" / "agentsentry" / "run_report.md")
    parser.add_argument("--semantic-judge", choices=("default", "on", "off"), default="default")
    parser.add_argument("--semantic-timeout-ms", type=int, default=4000)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--sleep", type=float, default=0.02)
    parser.add_argument("--max-cases", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    cases = load_cases(args.input)
    if args.max_cases > 0:
        cases = cases[: args.max_cases]
    if args.dry_run:
        print(json.dumps({"cases": len(cases), "input": str(args.input), "sha256": sha256_file(args.input)}, ensure_ascii=False))
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
        "case_count": len(cases),
        "summary": summarize(results),
        "results": results,
    }
    write_json(args.output, payload)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_report(payload), encoding="utf-8", newline="\n")
    print(json.dumps(payload["summary"]["overall"], ensure_ascii=False))
    return 2 if payload["summary"]["overall"]["harness_errors"] else 0


def load_cases(path: Path) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    schema = json.loads((ROOT / "dataset" / "schemas" / "benchmark_case.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    allowed = set(BENCHMARK_CASE_FIELDS)
    for line_number, row in enumerate(iter_jsonl(path), start=1):
        schema_errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if schema_errors:
            first = schema_errors[0]
            location = "/".join(map(str, first.absolute_path)) or "$"
            raise ValueError(f"{path}:{line_number}: schema {location}: {first.message}")
        extra = sorted(set(row) - allowed)
        if extra:
            raise ValueError(f"{path}:{line_number}: unexpected BenchmarkCase fields: {', '.join(extra)}")
        try:
            cases.append(BenchmarkCase(**row))
        except TypeError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
    return cases


def render_report(payload: dict[str, Any]) -> str:
    overall = payload["summary"]["overall"]
    return "\n".join(
        [
            "# AgentSentry Dataset Run",
            "",
            f"- Input SHA-256: `{payload['input_sha256']}`",
            f"- Cases: {overall['cases']} (attack {overall['attack_cases']}, benign {overall['benign_cases']})",
            f"- Protection rate: {overall['protection_rate']:.2%}",
            f"- Unsafe release rate: {overall['unsafe_release_rate']:.2%}",
            f"- Benign allow rate: {overall['benign_allow_rate']:.2%}",
            f"- False positive rate: {overall['false_positive_rate']:.2%}",
            f"- Harness errors: {overall['harness_errors']}",
            "",
            "Per-case decisions and alert records are stored in the JSON result file.",
            "",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
