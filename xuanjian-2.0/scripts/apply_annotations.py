"""Validate annotation records and apply them to the graph JSONL files.

Validation:
* JSON Schema conformance (data/annotation/annotation.schema.json).
* Cross-checks against the graph files: graph_id / session_id must exist,
  critical_action_id must be an existing node, evidence_edge_ids must be
  existing edges.
* Split integrity: one label per session_id (records are keyed by session,
  and the label must be identical across both graph files).

Application (writes NEW files, originals are never modified):
* reports/graph-learning/replay_graphs.control-rebuilt.annotated.jsonl
* reports/graph-learning/wsl_sessions_final.control-rebuilt.annotated.jsonl
  - top-level label / attack_type replaced
  - intent node metadata label / attack_type replaced
  - annotation_metadata block attached to each record
* label_queue.jsonl annotator_* fields updated in annotated copies.

Usage (from xuanjian-2.0 project root):
    python -m scripts.apply_annotations
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

REPORTS_DIR = PROJECT_ROOT.parent / "reports" / "graph-learning"
GRAPH_FILES = [
    REPORTS_DIR / "replay_graphs.control-rebuilt.jsonl",
    REPORTS_DIR / "wsl_sessions_final.control-rebuilt.jsonl",
]
ANNOTATIONS_PATH = PROJECT_ROOT / "data" / "annotation" / "annotations.v1.jsonl"
SCHEMA_PATH = PROJECT_ROOT / "data" / "annotation" / "annotation.schema.json"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> int:
    import jsonschema

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    annotations = load_jsonl(ANNOTATIONS_PATH)
    by_session = {a["session_id"]: a for a in annotations}

    errors: list[str] = []
    if len(by_session) != len(annotations):
        errors.append("duplicate session_id in annotations")

    validator = jsonschema.Draft7Validator(schema)
    for annotation in annotations:
        for issue in validator.iter_errors(annotation):
            errors.append(f"schema: {annotation['session_id']}: {issue.message}")

    applied = {p.name: 0 for p in GRAPH_FILES}
    for path in GRAPH_FILES:
        records = load_jsonl(path)
        for record in records:
            sid = record["session_id"]
            if record.get("label") != "unknown":
                continue
            annotation = by_session.get(sid)
            if annotation is None:
                errors.append(f"{path.name}: unknown session {sid} has no annotation")
                continue
            # cross-check node / edge references
            node_ids = {n["node_id"] for n in record["nodes"]}
            edge_ids = {e["edge_id"] for e in record["edges"]}
            if annotation["graph_id"] != record["graph_id"]:
                errors.append(f"{path.name}: graph_id mismatch for {sid}")
            if annotation["critical_action_id"] and annotation["critical_action_id"] not in node_ids:
                errors.append(f"{sid}: critical_action_id {annotation['critical_action_id']} not a node")
            for edge_id in annotation["evidence_edge_ids"]:
                if edge_id not in edge_ids:
                    errors.append(f"{sid}: evidence edge {edge_id} not in graph")

        # write annotated copy
        out_path = path.with_name(path.name.replace(".jsonl", ".annotated.jsonl"))
        with open(out_path, "w", encoding="utf-8") as fh:
            for record in records:
                sid = record["session_id"]
                annotation = by_session.get(sid)
                if annotation and record.get("label") == "unknown":
                    record["label"] = annotation["trajectory_label"]
                    record["attack_type"] = annotation["attack_type"]
                    record["annotation_metadata"] = {
                        k: annotation[k]
                        for k in (
                            "trajectory_label",
                            "severity",
                            "critical_action_id",
                            "evidence_edge_ids",
                            "reviewer_confidence",
                            "annotation_notes",
                            "annotator",
                            "annotated_at",
                            "schema_version",
                            "evidence_pack",
                            "raw_source_available",
                        )
                    }
                    applied[path.name] += 1
                # keep intent node metadata in sync with the top-level label
                # (pre-existing attack records were relabeled top-level only)
                for node in record["nodes"]:
                    if node["node_type"] == "intent":
                        node["metadata"]["label"] = record["label"]
                        node["metadata"]["attack_type"] = record["attack_type"]
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

        # update label queue copy
        queue_path = path.with_name(path.name.replace(".jsonl", ".label_queue.jsonl"))
        if queue_path.exists():
            queue_out = queue_path.with_name(queue_path.name.replace(".jsonl", ".annotated.jsonl"))
            with open(queue_out, "w", encoding="utf-8") as fh:
                for row in load_jsonl(queue_path):
                    annotation = by_session.get(row["session_id"])
                    if annotation and row.get("annotator_label") is None:
                        row["annotator_label"] = annotation["trajectory_label"]
                        row["annotator_attack_type"] = annotation["attack_type"]
                        row["annotation_notes"] = annotation["annotation_notes"]
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    if errors:
        print("VALIDATION FAILED:")
        for error in errors:
            print(f"  - {error}")
        return 1

    label_counts: dict[str, int] = {}
    confidence = []
    for annotation in annotations:
        label_counts[annotation["trajectory_label"]] = label_counts.get(annotation["trajectory_label"], 0) + 1
        confidence.append(annotation["reviewer_confidence"])
    print("validation: OK")
    print(f"records: {len(annotations)} | labels: {label_counts}")
    print(f"confidence: min={min(confidence)} mean={sum(confidence)/len(confidence):.3f}")
    for name, count in applied.items():
        print(f"applied {count} labels -> {name.replace('.jsonl', '.annotated.jsonl')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
