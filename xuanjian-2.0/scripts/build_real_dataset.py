"""Assemble the real-session graph dataset for TemporalGAT training.

Sources (reports/graph-learning/):
* replay_graphs.control-rebuilt.jsonl       replay sessions + organic sessions
* wsl_sessions_final.control-rebuilt.jsonl  organic sessions (29 overlap)

Labels:
* organic sessions  -> annotations.v1.jsonl (human-reviewed)
* xjreplay sessions -> annotations.v2.jsonl (verified injection outcome);
  records still marked CANDIDATE or ambiguous are dropped, never guessed.

Dropped on purpose:
* `synthetic://normal/*` stubs: single-node placeholders with no edges. Kept
  as normals they let any model separate classes by graph size alone.
* graphs whose session has no verified annotation.

Each output graph carries:
* `group_id`  split key. Sessions with an identical tool-call signature
  (the standup near-duplicate cluster) share one group so they never
  straddle train/test.
* `origin`    "organic" | "replay", used for the shortcut-check slice.
* `ground_truth_anomaly_nodes` = [critical_action_id] for attacks.

Usage (from xuanjian-2.0 project root):
    python -m scripts.build_real_dataset
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT.parent / "reports" / "graph-learning"
GRAPH_FILES = [
    REPORTS_DIR / "replay_graphs.control-rebuilt.jsonl",
    REPORTS_DIR / "wsl_sessions_final.control-rebuilt.jsonl",
]
ANNOTATION_FILES = [
    PROJECT_ROOT / "data" / "annotation" / "annotations.v1.jsonl",
    PROJECT_ROOT / "data" / "annotation" / "annotations.v2.jsonl",
]
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "real" / "real_graphs.v1.jsonl"


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def is_verified(record: Dict[str, Any]) -> bool:
    if record.get("trajectory_label") not in {"normal", "attack"}:
        return False
    if "CANDIDATE" in str(record.get("annotation_notes", "")):
        return False
    replay = record.get("injection_replay")
    if replay is not None and not replay.get("injection_outcome"):
        return False
    return True


def tool_signature(graph: Dict[str, Any]) -> str:
    calls = [
        (n.get("tool_name", ""), json.dumps(n.get("parameters", {}), sort_keys=True, ensure_ascii=False))
        for n in graph["nodes"]
        if n["node_type"] == "tool_call"
    ]
    return hashlib.sha1(json.dumps(calls, ensure_ascii=False).encode("utf-8")).hexdigest()[:12]


def load_graphs() -> Dict[str, Dict[str, Any]]:
    """First file wins on session_id collisions (the 29 overlaps are byte-identical)."""
    graphs: Dict[str, Dict[str, Any]] = {}
    for path in GRAPH_FILES:
        for graph in read_jsonl(path):
            if str(graph.get("source", "")).startswith("synthetic://"):
                continue
            graphs.setdefault(graph["session_id"], graph)
    return graphs


def build(output: Path) -> Dict[str, Any]:
    graphs = load_graphs()
    annotations: Dict[str, Dict[str, Any]] = {}
    for path in ANNOTATION_FILES:
        for record in read_jsonl(path):
            annotations[record["session_id"]] = record

    rows, skipped = [], Counter()
    for session_id, graph in sorted(graphs.items()):
        record = annotations.get(session_id)
        if record is None:
            skipped["no_annotation"] += 1
            continue
        if not is_verified(record):
            skipped[f"unverified:{record.get('trajectory_label')}"] += 1
            continue
        node_ids = {n["node_id"] for n in graph["nodes"]}
        critical = record.get("critical_action_id")
        if record["trajectory_label"] == "attack" and critical not in node_ids:
            skipped["attack_missing_critical_node"] += 1
            continue
        replay = record.get("injection_replay") or {}
        rows.append({
            **graph,
            "label": record["trajectory_label"],
            "attack_type": record["attack_type"],
            "ground_truth_anomaly_nodes": [critical] if record["trajectory_label"] == "attack" else [],
            "origin": "replay" if session_id.startswith("xjreplay") else "organic",
            "injection_outcome": replay.get("injection_outcome"),
            "tool_signature": tool_signature(graph),
        })

    # Near-duplicate clusters share one split group.
    signature_groups: Dict[str, str] = {}
    for row in rows:
        signature_groups.setdefault(row["tool_signature"], row["session_id"])
        row["group_id"] = signature_groups[row["tool_signature"]]

    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    summary = {
        "output": output.name,
        "graphs": len(rows),
        "groups": len({r["group_id"] for r in rows}),
        "by_label_origin": {f"{k[0]}/{k[1]}": v for k, v in sorted(Counter((r["label"], r["origin"]) for r in rows).items())},
        "by_injection_outcome": dict(Counter(r["injection_outcome"] for r in rows if r["origin"] == "replay")),
        "by_attack_type": dict(Counter(r["attack_type"] for r in rows if r["label"] == "attack")),
        "multi_member_groups": sum(1 for _, n in Counter(r["group_id"] for r in rows).items() if n > 1),
        "skipped": dict(skipped),
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    args.output = args.output.resolve()
    summary = build(args.output)
    summary_path = args.output.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
