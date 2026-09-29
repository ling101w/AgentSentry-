"""Validate and summarize the synthetic causal-graph dataset."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List


ATTACK_TOOLS = {
    "send_email": "IPI",
    "upload_file": "data_exfiltration",
    "delete_file": "privilege_escalation",
    "update_memory": "memory_poisoning",
}
KNOWN_EDGE_TYPES = {
    "intent_drives",
    "control_influence",
    "data_dependency",
    "call_sequence",
    "data_derivation",
}


def _label_for(path: Path, record: Dict[str, Any]) -> str:
    label = record.get("label")
    if label in {"normal", "attack"}:
        return label
    if path.name.startswith("normal_"):
        return "normal"
    if path.name.startswith("attack_"):
        return "attack"
    raise ValueError(f"{path.name}: missing normal/attack label")


def _attack_type(record: Dict[str, Any], label: str) -> str | None:
    if label != "attack":
        return None
    if record.get("attack_type"):
        return record["attack_type"]
    tool_names = {
        node.get("tool_name")
        for node in record.get("nodes", [])
        if node.get("node_type") == "tool_call"
    }
    for tool_name, attack_type in ATTACK_TOOLS.items():
        if tool_name in tool_names:
            return attack_type
    return "unknown"


def collect_records(data_dir: str | os.PathLike[str]) -> List[Dict[str, Any]]:
    """Load, validate, and annotate all generated dataset records."""
    root = Path(data_dir)
    if not root.is_dir():
        raise ValueError(f"dataset directory does not exist: {root}")
    paths = sorted(
        path
        for pattern in ("normal_*.json", "attack_*.json")
        for path in root.glob(pattern)
    )
    records: List[Dict[str, Any]] = []
    graph_ids: set[str] = set()

    for path in paths:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"{path.name}: invalid JSON ({exc})") from exc

        label = _label_for(path, record)
        graph_id = record.get("graph_id")
        nodes = record.get("nodes")
        edges = record.get("edges")
        if not graph_id or not isinstance(nodes, list) or not isinstance(edges, list):
            raise ValueError(f"{path.name}: missing graph_id, nodes, or edges")
        if graph_id in graph_ids:
            raise ValueError(f"duplicate graph_id: {graph_id}")
        graph_ids.add(graph_id)

        node_ids = [node.get("node_id") for node in nodes]
        if any(not node_id for node_id in node_ids) or len(node_ids) != len(set(node_ids)):
            raise ValueError(f"{path.name}: node IDs must be present and unique")
        node_id_set = set(node_ids)
        control_edge_count = 0
        for edge in edges:
            if edge.get("source") not in node_id_set or edge.get("target") not in node_id_set:
                raise ValueError(f"{path.name}: edge references an unknown node")
            if edge.get("type") not in KNOWN_EDGE_TYPES:
                raise ValueError(f"{path.name}: unknown edge type {edge.get('type')!r}")
            weight = edge.get("weight", 1.0)
            if not isinstance(weight, (int, float)) or not 0 <= weight <= 1:
                raise ValueError(f"{path.name}: edge weights must be in [0, 1]")
            if edge.get("type") == "control_influence":
                control_edge_count += 1

        intent_nodes = [node for node in nodes if node.get("node_type") == "intent"]
        if len(intent_nodes) != 1:
            raise ValueError(f"{path.name}: expected exactly one intent node")
        if label == "attack" and control_edge_count == 0:
            raise ValueError(f"{path.name}: attack record has no control_influence edge")
        if label == "normal" and control_edge_count:
            raise ValueError(f"{path.name}: normal record contains control_influence edge")
        attack_type = _attack_type(record, label)
        if label == "attack" and attack_type == "unknown":
            raise ValueError(f"{path.name}: attack type cannot be inferred")

        record = dict(record)
        record.update(
            {
                "_path": str(path),
                "_label": label,
                "_attack_type": attack_type,
                "_task_type": intent_nodes[0].get("task_type", "unknown"),
                "_node_count": len(nodes),
                "_edge_count": len(edges),
            }
        )
        records.append(record)
    return records


def summarize(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    records = list(records)
    labels = Counter(record["_label"] for record in records)
    tasks = Counter(record["_task_type"] for record in records)
    attack_types = Counter(
        record["_attack_type"] for record in records if record["_label"] == "attack"
    )
    node_types = Counter(
        node["node_type"]
        for record in records
        for node in record.get("nodes", [])
    )
    edge_types = Counter(
        edge["type"]
        for record in records
        for edge in record.get("edges", [])
    )
    node_counts = [record["_node_count"] for record in records]
    edge_counts = [record["_edge_count"] for record in records]
    return {
        "total": len(records),
        "labels": labels,
        "tasks": tasks,
        "attack_types": attack_types,
        "node_types": node_types,
        "edge_types": edge_types,
        "avg_nodes": mean(node_counts) if node_counts else 0,
        "avg_edges": mean(edge_counts) if edge_counts else 0,
    }


def render_markdown(summary: Dict[str, Any], data_dir: str) -> str:
    labels: Counter = summary["labels"]
    total = summary["total"] or 1

    def rows(counter: Counter, include_share: bool = True) -> str:
        return "\n".join(
            (
                f"| `{key}` | {value} | {value / total:.1%} |"
                if include_share
                else f"| `{key}` | {value} |"
            )
            for key, value in sorted(counter.items())
        ) or ("| (none) | 0 | 0.0% |" if include_share else "| (none) | 0 |")

    task_rows = "\n".join(
        f"| `{key}` | {value} |"
        for key, value in sorted(summary["tasks"].items())
    ) or "| (none) | 0 |"
    attack_rows = "\n".join(
        f"| `{key}` | {value} |"
        for key, value in sorted(summary["attack_types"].items())
    ) or "| (none) | 0 |"

    return f"""# Synthetic Dataset Statistics

Generated from `{data_dir}`.

## Overview

| Metric | Value |
|---|---:|
| Total records | {summary['total']} |
| Normal | {labels.get('normal', 0)} |
| Attack | {labels.get('attack', 0)} |
| Average nodes per graph | {summary['avg_nodes']:.2f} |
| Average edges per graph | {summary['avg_edges']:.2f} |

## Labels

| Label | Count | Share |
|---|---:|---:|
{rows(labels)}

## Task Types

| Task type | Count |
|---|---:|
{task_rows}

## Attack Types

| Attack type | Count |
|---|---:|
{attack_rows}

## Graph Schema Usage

### Nodes

| Node type | Count |
|---|---:|
{rows(summary['node_types'], include_share=False)}

### Edges

| Edge type | Count |
|---|---:|
{rows(summary['edge_types'], include_share=False)}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    project_root = Path(__file__).resolve().parents[1]
    parser.add_argument(
        "--data-dir",
        default=str(project_root / "data" / "synthetic"),
        help="directory containing normal_*.json and attack_*.json",
    )
    parser.add_argument(
        "--output",
        default=str(project_root / "dataset_stats.md"),
        help="Markdown report path",
    )
    args = parser.parse_args()

    records = collect_records(args.data_dir)
    summary = summarize(records)
    report = render_markdown(summary, args.data_dir)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"Validated {summary['total']} records")
    print(f"Normal: {summary['labels'].get('normal', 0)}")
    print(f"Attack: {summary['labels'].get('attack', 0)}")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
