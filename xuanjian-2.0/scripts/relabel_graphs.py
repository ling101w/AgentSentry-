"""Relabel converted replay graphs using the replay manifest + runner log.

convert_openclaw.py emits label=unknown for every real session. This script
joins graph JSONL entries with scripts/replay_wsl.sh's log (replay_id ->
session mapping) and the manifest (replay_id -> label), then rewrites the
label/attack_type fields. Graphs that cannot be attributed stay unknown.

Usage (from xuanjian-2.0 project root):
    python scripts/relabel_graphs.py \
        --graphs data/replay/replay_graphs.jsonl \
        --manifest data/replay/manifest.jsonl \
        --log data/replay/sessions.jsonl.log.jsonl \
        --in-place
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", type=str, required=True)
    parser.add_argument("--manifest", type=str, required=True)
    parser.add_argument("--log", type=str, required=True)
    parser.add_argument("--in-place", action="store_true",
                        help="overwrite the graphs file instead of writing .labeled.jsonl")
    return parser.parse_args()


def load_jsonl(path: Path) -> list[dict]:
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def main() -> int:
    args = parse_args()
    graphs_path = Path(args.graphs)
    if not graphs_path.is_absolute():
        graphs_path = PROJECT_ROOT / graphs_path

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = PROJECT_ROOT / manifest_path
    manifest = {m["replay_id"]: m for m in load_jsonl(manifest_path)}

    # session_id -> replay attribution (first replay that produced the session)
    session_to_replay: dict[str, str] = {}
    status_counts: dict[str, int] = {}
    log_path = Path(args.log)
    if not log_path.is_absolute():
        log_path = PROJECT_ROOT / log_path
    for entry in load_jsonl(log_path):
        status_counts[entry.get("status", "?")] = status_counts.get(entry.get("status", "?"), 0) + 1
        if entry.get("status") != "ok":
            continue
        for session in entry.get("new_sessions", []):
            session_to_replay.setdefault(session, entry["replay_id"])

    graphs = load_jsonl(graphs_path)
    stats = {"attack": 0, "normal": 0, "unknown": 0}
    for graph in graphs:
        session_id = str(graph.get("session_id", ""))
        graph_id = str(graph.get("graph_id", ""))
        replay_id = session_to_replay.get(session_id) or session_to_replay.get(graph_id)
        case = manifest.get(replay_id) if replay_id else None
        if case is None:
            # fallback: OpenClaw session keys embed our replay id (xjreplay-<rid>)
            for marker, m in manifest.items():
                if marker in session_id or marker in graph_id:
                    case = m
                    replay_id = marker
                    break
        if case is None:
            stats["unknown"] += 1
            continue
        graph["label"] = case["label"]
        graph["attack_type"] = case.get("attack_type")
        graph["replay_id"] = replay_id
        graph["source_dataset"] = case.get("source")
        stats[case["label"]] = stats.get(case["label"], 0) + 1

    if args.in_place:
        out_path = graphs_path
    else:
        out_path = graphs_path.with_name(graphs_path.stem + ".labeled.jsonl")
    with open(out_path, "w", encoding="utf-8") as fh:
        for graph in graphs:
            fh.write(json.dumps(graph, ensure_ascii=False) + "\n")

    print(f"[relabel] {len(graphs)} graphs -> {out_path}")
    print(f"  labels: {stats}")
    print(f"  runner status: {status_counts}")
    unattributed = stats["unknown"]
    if unattributed:
        print(f"  [warn] {unattributed} graphs could not be attributed to a replay case")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
