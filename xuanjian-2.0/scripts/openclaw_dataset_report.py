"""Validate and report an OpenClaw causal-graph JSONL snapshot.

The report intentionally contains graph-level metadata only. It does not copy
user messages, tool arguments, or observation previews into the label queue.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"(?i)password=([^<\"\s]+)"),
    # Ignore shell variable references and redaction placeholders; report only
    # a concrete assignment value that could be copied as a credential.
    re.compile(
        r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*"
        r"(?!<redacted>|[$\\.\"'\-?:])[^,\s\"}]+"
    ),
)
KNOWN_NODE_TYPES = {"intent", "tool_call", "observation", "entity"}
KNOWN_EDGE_TYPES = {
    "intent_drives",
    "control_influence",
    "data_dependency",
    "call_sequence",
    "data_derivation",
}


def load_graph_records(path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Load JSONL graph records and return records plus validation errors."""
    source = Path(path)
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    if not source.is_file():
        return [], [f"input file does not exist: {source}"]
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: invalid JSON ({exc.msg})")
            continue
        if not isinstance(record, dict):
            errors.append(f"line {line_number}: record must be an object")
            continue
        records.append(record)
    return records, errors


def validate_record(record: dict[str, Any], seen_ids: set[str]) -> list[str]:
    errors: list[str] = []
    graph_id = record.get("graph_id")
    if not isinstance(graph_id, str) or not graph_id:
        errors.append("missing graph_id")
    elif graph_id in seen_ids:
        errors.append(f"duplicate graph_id: {graph_id}")
    else:
        seen_ids.add(graph_id)

    nodes = record.get("nodes")
    edges = record.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return errors + ["nodes and edges must be arrays"]
    node_ids = [node.get("node_id") for node in nodes if isinstance(node, dict)]
    if len(node_ids) != len(set(node_ids)):
        errors.append(f"{graph_id}: duplicate node_id")
    node_id_set = set(node_ids)
    for node in nodes:
        if not isinstance(node, dict) or node.get("node_type") not in KNOWN_NODE_TYPES:
            errors.append(f"{graph_id}: invalid node type")
    for edge in edges:
        if not isinstance(edge, dict):
            errors.append(f"{graph_id}: edge must be an object")
            continue
        if edge.get("source") not in node_id_set or edge.get("target") not in node_id_set:
            errors.append(f"{graph_id}: edge references unknown node")
        if edge.get("type") not in KNOWN_EDGE_TYPES:
            errors.append(f"{graph_id}: invalid edge type {edge.get('type')!r}")
        weight = edge.get("weight", 1.0)
        if not isinstance(weight, (int, float)) or not 0 <= weight <= 1:
            errors.append(f"{graph_id}: invalid edge weight")
    intents = [node for node in nodes if isinstance(node, dict) and node.get("node_type") == "intent"]
    if len(intents) != 1:
        errors.append(f"{graph_id}: expected exactly one intent node")
    return errors


def _contains_secret(value: Any) -> bool:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def summarize(records: list[dict[str, Any]], errors: list[str]) -> dict[str, Any]:
    labels = Counter(str(record.get("label", "unknown")) for record in records)
    tasks = Counter(
        str(next(
            (
                node.get("task_type", "unknown")
                for node in record.get("nodes", [])
                if isinstance(node, dict) and node.get("node_type") == "intent"
            ),
            "unknown",
        ))
        for record in records
    )
    tools = Counter(
        str(node.get("tool_name", "unknown"))
        for record in records
        for node in record.get("nodes", [])
        if isinstance(node, dict) and node.get("node_type") == "tool_call"
    )
    tool_counts = [
        sum(
            1
            for node in record.get("nodes", [])
            if isinstance(node, dict) and node.get("node_type") == "tool_call"
        )
        for record in records
    ]
    unknown_label_count = labels.get("unknown", 0)
    return {
        "records": len(records),
        "labels": labels,
        "tasks": tasks,
        "tools": tools,
        "min_tool_calls": min(tool_counts) if tool_counts else 0,
        "max_tool_calls": max(tool_counts) if tool_counts else 0,
        "avg_tool_calls": sum(tool_counts) / len(tool_counts) if tool_counts else 0.0,
        "unknown_label_count": unknown_label_count,
        "secret_scan_hits": sum(_contains_secret(record) for record in records),
        "errors": errors,
    }


def write_label_queue(records: list[dict[str, Any]], path: str | Path) -> int:
    """Write metadata-only records that require human labels."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("w", encoding="utf-8") as handle:
        for record in records:
            if record.get("label", "unknown") not in {"unknown", ""}:
                continue
            nodes = record.get("nodes", [])
            intents = [
                node for node in nodes
                if isinstance(node, dict) and node.get("node_type") == "intent"
            ]
            calls = [
                node for node in nodes
                if isinstance(node, dict) and node.get("node_type") == "tool_call"
            ]
            queue_record = {
                "graph_id": record.get("graph_id"),
                "session_id": record.get("session_id"),
                "label": "unknown",
                "attack_type": None,
                "task_type": intents[0].get("task_type", "unknown") if intents else "unknown",
                "node_count": len(nodes),
                "edge_count": len(record.get("edges", [])),
                "tool_names": [call.get("tool_name", "unknown") for call in calls],
                "annotator_label": None,
                "annotator_attack_type": None,
                "annotation_notes": "",
            }
            handle.write(json.dumps(queue_record, ensure_ascii=False) + "\n")
            count += 1
    return count


def render_report(summary: dict[str, Any], input_path: str, queue_path: str) -> str:
    def table(counter: Counter) -> str:
        return "\n".join(
            f"| `{key}` | {value} |"
            for key, value in sorted(counter.items())
        ) or "| (none) | 0 |"

    error_lines = "\n".join(f"- {error}" for error in summary["errors"]) or "- None"
    return f"""# OpenClaw Dataset Quality Report

Input: `{input_path}`

## Snapshot

| Metric | Value |
|---|---:|
| Graph records | {summary['records']} |
| Unknown labels | {summary['unknown_label_count']} |
| Tool calls (min/avg/max) | {summary['min_tool_calls']} / {summary['avg_tool_calls']:.2f} / {summary['max_tool_calls']} |
| Secret-pattern scan hits | {summary['secret_scan_hits']} |
| Validation errors | {len(summary['errors'])} |

## Labels

| Label | Count |
|---|---:|
{table(summary['labels'])}

## Heuristic Task Types

These task types come from the graph builder's keyword heuristic and are not ground truth.

| Task type | Count |
|---|---:|
{table(summary['tasks'])}

## Tool Usage

| Tool | Count |
|---|---:|
{table(summary['tools'])}

## Validation Errors

{error_lines}

## Label Queue

Unknown-label metadata queue: `{queue_path}`. It intentionally excludes user messages,
tool arguments, and observation contents.
"""


def run(input_path: str | Path, report_path: str | Path, queue_path: str | Path) -> dict[str, Any]:
    records, errors = load_graph_records(input_path)
    seen_ids: set[str] = set()
    for record in records:
        errors.extend(validate_record(record, seen_ids))
    summary = summarize(records, errors)
    queued = write_label_queue(records, queue_path)
    summary["queued_for_labeling"] = queued
    Path(report_path).write_text(
        render_report(summary, str(input_path), str(queue_path)),
        encoding="utf-8",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="OpenClaw graph JSONL")
    parser.add_argument("--report", help="Markdown report path")
    parser.add_argument("--queue", help="unknown-label queue JSONL path")
    args = parser.parse_args()
    input_path = Path(args.input)
    report_path = Path(args.report) if args.report else input_path.with_suffix(".report.md")
    queue_path = Path(args.queue) if args.queue else input_path.with_suffix(".label_queue.jsonl")
    summary = run(input_path, report_path, queue_path)
    print(f"Validated {summary['records']} graph records")
    print(f"Queued for labeling: {summary['queued_for_labeling']}")
    print(f"Validation errors: {len(summary['errors'])}")
    print(f"Wrote {report_path}")
    print(f"Wrote {queue_path}")
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
