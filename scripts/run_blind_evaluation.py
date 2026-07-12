# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.evaluation_protocol import (  # noqa: E402
    EvaluationObservation,
    compute_security_metrics,
    detector_payload,
    load_sealed_cases,
)


DEFAULT_CASES = ROOT / "evaluation" / "blind" / "blind_holdout.jsonl"
DEFAULT_OUTPUT = ROOT / "reports" / "blind_evaluation"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a sealed label-isolated holdout against AgentSentry command-lab.")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--allow-dirty", action="store_true", help="Allow a development-only run from a dirty or non-Git workspace.")
    parser.add_argument("--include-case-details", action="store_true", help="Include evaluator-private per-case labels and decisions in the output.")
    args = parser.parse_args()

    if args.repetitions < 1:
        parser.error("--repetitions must be at least 1")
    if not args.cases.exists():
        parser.error(
            f"sealed holdout not found: {args.cases}. "
            "An independent evaluator must place it there immediately before the run."
        )
    worktree_dirty = git_worktree_dirty()
    if worktree_dirty is not False and not args.allow_dirty:
        parser.error(
            "sealed evaluation requires a clean Git worktree with a resolvable HEAD; "
            "commit/freeze the release first, or use --allow-dirty only for pipeline development"
        )

    cases = load_sealed_cases(args.cases)
    unsupported = [
        case.case_id
        for case in cases
        if case.detector_input.tool_result is not None or case.detector_input.session_history
    ]
    if unsupported:
        parser.error(
            "command-lab adapter cannot faithfully replay tool_result/session_history for: "
            + ", ".join(unsupported[:10])
            + ". Use a native OpenClaw adapter for these cases."
        )

    observations: list[EvaluationObservation] = []
    case_results: list[dict[str, Any]] = []
    endpoint = args.base_url.rstrip("/") + "/api/lab/command"
    client_id_secret = secrets.token_bytes(32)
    for repetition in range(args.repetitions):
        for case in cases:
            isolated = detector_payload(case)
            request_payload = {
                "command": isolated["user_message"],
                "tool": isolated["tool_name"],
                "params": isolated["tool_args"],
                "clientId": opaque_client_id(client_id_secret, case.case_id, repetition),
                "resetSession": True,
                "semanticJudge": "default",
            }
            started = time.perf_counter()
            try:
                response = post_json(endpoint, request_payload, args.timeout)
            except Exception as exc:  # Continue the sealed run and report harness failures separately.
                latency_ms = round((time.perf_counter() - started) * 1000, 2)
                error = f"{type(exc).__name__}: {exc}"[:500]
                observations.append(
                    EvaluationObservation(
                        case_id=case.case_id,
                        decision="ask",
                        task_completed=False,
                        action_executed=False,
                        latency_ms=latency_ms,
                        repetition=repetition,
                        harness_error=error,
                    )
                )
                case_results.append(
                    {
                        "case_id": case.case_id,
                        "repetition": repetition,
                        "decision": None,
                        "expected": case.hidden_label.expected,
                        "correct": None,
                        "latency_ms": latency_ms,
                        "harness_error": error,
                    }
                )
                continue
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            decisions = response.get("decisions") if isinstance(response.get("decisions"), list) else []
            decision = most_severe_decision(decisions)
            action_executed = decision == "allow" and bool(response.get("ok"))
            judge_called = judge_called_for_decisions(decisions)
            observation = EvaluationObservation(
                case_id=case.case_id,
                decision=decision,
                task_completed=action_executed,
                action_executed=action_executed,
                latency_ms=latency_ms,
                blocked_scope="action",
                llm_judge_called=judge_called,
                repetition=repetition,
            )
            observations.append(observation)
            case_results.append(
                {
                    "case_id": case.case_id,
                    "repetition": repetition,
                    "decision": decision,
                    "expected": case.hidden_label.expected,
                    "correct": decision == case.hidden_label.expected,
                    "latency_ms": latency_ms,
                    "harness_error": "",
                }
            )

    scored_results = [row for row in case_results if isinstance(row["correct"], bool)]
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "release_commit": git_commit(),
        "working_tree_dirty": worktree_dirty,
        "holdout_sha256": sha256_file(args.cases),
        "case_count": len(cases),
        "repetitions": args.repetitions,
        "detector_input_fields": ["user_message", "tool_name", "tool_args", "tool_result", "session_history"],
        "labels_entered_detector": False,
        "opaque_client_ids": True,
        "metrics": compute_security_metrics(cases, observations),
        "expected_decision_accuracy": round(sum(row["correct"] for row in scored_results) / len(scored_results), 4) if scored_results else 0.0,
        "case_details_included": bool(args.include_case_details),
    }
    if args.include_case_details:
        payload["case_results"] = case_results
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    privacy_suffix = ".private" if args.include_case_details else ""
    output = args.output_dir / f"blind_evaluation_{stamp}{privacy_suffix}.json"
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    latest = args.output_dir / f"blind_evaluation.latest{privacy_suffix}.json"
    latest.write_text(output.read_text(encoding="utf-8"), encoding="utf-8")
    print(json.dumps(payload["metrics"], ensure_ascii=False, indent=2))
    print(f"report: {output}")
    return 0


def post_json(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(url, data=encoded, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=timeout) as response:
        parsed = json.loads(response.read().decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("evaluation endpoint returned a non-object response")
    return parsed


def most_severe_decision(decisions: list[Any]) -> str:
    values = [str(row.get("decision", "")) for row in decisions if isinstance(row, dict)]
    if "deny" in values:
        return "deny"
    if "ask" in values:
        return "ask"
    return "allow" if values and all(value == "allow" for value in values) else "ask"


def judge_called_for_decisions(decisions: list[Any]) -> bool:
    for row in decisions:
        if not isinstance(row, dict):
            continue
        if row.get("semantic_judge_called") is True:
            return True
        finding_types = row.get("finding_types")
        if isinstance(finding_types, list) and "semantic" in finding_types:
            return True
        findings = row.get("findings")
        if isinstance(findings, list) and any(
            isinstance(finding, dict) and finding.get("finding_type") == "semantic"
            for finding in findings
        ):
            return True
    return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def opaque_client_id(secret: bytes, case_id: str, repetition: int) -> str:
    message = f"{case_id}\0{repetition}".encode("utf-8")
    return "blind-trial-" + hmac.new(secret, message, hashlib.sha256).hexdigest()[:24]


def git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return completed.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def git_worktree_dirty() -> bool | None:
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return bool(completed.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return None


if __name__ == "__main__":
    raise SystemExit(main())
