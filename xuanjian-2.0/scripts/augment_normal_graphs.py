"""Augment the replay graph JSONL with minimal normal-only graphs.

Why this exists
---------------
``scripts/convert_openclaw.py`` filters out trajectories that contain no
``tool_call`` events. This is correct for the original use case (lifecycle
files should not become empty training graphs), but it also drops the 60
``label=normal`` replay sessions because the OpenClaw agent never invoked
any tool when there was no untrusted payload to act on. As a result the
replay graph dataset was 78 attack / 0 normal, which makes binary
detector training infeasible.

This script reads ``data/replay/manifest.jsonl``, takes every entry with
``label == "normal"``, and emits a synthetic minimal graph containing a
single intent node whose ``task_type`` is inferred from the
``user_message`` via the same keyword heuristic used by
``graph_builder._task_type``. The resulting graphs are appended to
``data/replay/replay_graphs.jsonl`` (or any --out path). No call events,
no observations, no edges: the structural absence of ``control_influence``
edges is precisely the discriminator the detector needs to learn.

Schema invariants honored
-------------------------
* exactly one intent node (passes ``dataset_stats.py`` invariant)
* label == "normal"
* attack_type == null
* source_dataset / threat_primary preserved from manifest
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Same keyword heuristic as tools/openclaw_graph_builder/graph_builder.py
_TASK_KEYWORDS = {
    "email_summary": ("email", "mail", "邮件"),
    "calendar_management": ("calendar", "meeting", "schedule", "日程", "会议"),
    "web_search": ("weather", "search", "web", "天气", "查询"),
    "file_processing": ("file", "csv", "report", "文件", "数据"),
    "code_review": ("code", "pull request", "pr", "lint", "代码"),
    "memory_management": ("memory", "preference", "记忆", "偏好"),
    "log_analysis": ("log", "日志"),
}


def _infer_task_type(user_message: str) -> str:
    if not user_message:
        return "unknown"
    text = user_message.lower()
    for task_type, keywords in _TASK_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in text:
                return task_type
    return "unknown"


def _intent_node(record: Mapping[str, Any]) -> dict[str, Any]:
    user_message = str(record.get("user_message", ""))
    return {
        "node_id": "intent_1",
        "node_type": "intent",
        "timestamp": 0.0,
        "session_id": f"normal::{record['replay_id']}",
        "task_type": _infer_task_type(user_message),
        "user_id": "unknown",
        "original_request": user_message[:512],
        "metadata": {
            "label": "normal",
            "attack_type": None,
            "trajectory_metadata": {
                "synthetic": True,
                "reason": "no_tool_calls_in_replay",
                "source": "augment_normal_graphs",
            },
        },
    }


def _build_graph(record: Mapping[str, Any]) -> dict[str, Any]:
    rid = record["replay_id"]
    user_message = str(record.get("user_message", ""))
    return {
        "graph_id": f"normal_{rid}",
        "session_id": f"normal::{rid}",
        "created_at": 0.0,
        "nodes": [_intent_node(record)],
        "edges": [],
        "statistics": {"node_count": 1, "edge_count": 0},
        "schema_version": "2.0",
        "label": "normal",
        "attack_type": None,
        "source": f"synthetic://normal/{rid}",
        "user_message": user_message,
    }


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _existing_session_ids(paths: Iterable[Path]) -> set[str]:
    seen: set[str] = set()
    for path in paths:
        if not path.is_file():
            continue
        for record in _load_jsonl(path):
            seen.add(record.get("session_id"))
            seen.add(record.get("graph_id"))
    return seen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default=str(PROJECT_ROOT / "data" / "replay" / "manifest.jsonl"),
        help="Replay manifest path (one case per line).",
    )
    parser.add_argument(
        "--out",
        default=str(PROJECT_ROOT / "data" / "replay" / "replay_graphs.normal.jsonl"),
        help="Where to write synthetic normal graphs (jsonl).",
    )
    parser.add_argument(
        "--existing",
        action="append",
        default=None,
        help="Existing graphs file(s) whose graph_id/session_id should be "
        "treated as already present (skip duplicates). Pass multiple times.",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        raise SystemExit(f"manifest not found: {manifest_path}")

    existing = _existing_session_ids(
        [Path(p) for p in (args.existing or [])]
    ) if args.existing else set()

    manifest = _load_jsonl(manifest_path)
    normal_records = [r for r in manifest if r.get("label") == "normal"]
    print(f"manifest total={len(manifest)}, normal={len(normal_records)}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped_existing = 0
    task_counter: dict[str, int] = {}
    with out_path.open("w", encoding="utf-8") as fh:
        for record in normal_records:
            graph = _build_graph(record)
            if graph["graph_id"] in existing or graph["session_id"] in existing:
                skipped_existing += 1
                continue
            fh.write(json.dumps(graph, ensure_ascii=False) + "\n")
            task_counter[graph["nodes"][0]["task_type"]] = (
                task_counter.get(graph["nodes"][0]["task_type"], 0) + 1
            )
            written += 1

    print(f"wrote {written} normal graphs to {out_path}")
    if skipped_existing:
        print(f"skipped {skipped_existing} (already in existing set)")
    print("task_type distribution:")
    for task, count in sorted(task_counter.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {task}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
