"""Build one markdown evidence pack per unknown session for human annotation.

Inputs (auto-discovered, project-relative):
* reports/graph-learning/replay_graphs.control-rebuilt.jsonl   (label=unknown rows)
* reports/graph-learning/wsl_sessions_final.control-rebuilt.jsonl (all rows)
* data/annotation/raw_sessions/<session_id>.jsonl               (optional, full source)

The two graph files overlap on 29 sessions; every unique session emits exactly
one evidence pack. If the raw OpenClaw session file exists, full observation
text replaces the 200-char graph preview for that session.

Usage (from xuanjian-2.0 project root):
    python -m scripts.build_annotation_evidence
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

GRAPH_SOURCES = [
    PROJECT_ROOT.parent / "reports" / "graph-learning" / "replay_graphs.control-rebuilt.jsonl",
    PROJECT_ROOT.parent / "reports" / "graph-learning" / "wsl_sessions_final.control-rebuilt.jsonl",
]
RAW_DIR = PROJECT_ROOT / "data" / "annotation" / "raw_sessions"
OUT_DIR = PROJECT_ROOT / "data" / "annotation" / "evidence"

MAX_RAW_OBSERVATION = 6000
MAX_ASSISTANT_TEXT = 800
MAX_USER_MESSAGE = 1500


def load_graphs() -> dict[str, dict[str, Any]]:
    """Return session_id -> graph record, keeping the first occurrence."""
    by_session: dict[str, dict[str, Any]] = {}
    for path in GRAPH_SOURCES:
        if not path.exists():
            continue
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if record.get("label") != "unknown":
                    continue
                sid = record["session_id"]
                if sid not in by_session:
                    by_session[sid] = record
    return by_session


def load_raw_events(path: Path) -> list[dict[str, Any]]:
    """Parse an OpenClaw native session file into ordered display events."""
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("type") != "message":
                continue
            message = row.get("message") or {}
            role = message.get("role", "")
            content = message.get("content")
            if isinstance(content, str):
                content = [{"type": "text", "text": content}]
            if not isinstance(content, list):
                continue
            for item in content:
                if not isinstance(item, dict):
                    continue
                itype = item.get("type")
                if role == "user" and itype == "text":
                    events.append({"kind": "user", "text": item.get("text", "")})
                elif role == "assistant" and itype == "toolCall":
                    events.append(
                        {
                            "kind": "call",
                            "call_id": item.get("id", ""),
                            "name": item.get("name", ""),
                            "arguments": item.get("arguments", {}),
                        }
                    )
                elif role == "toolResult":
                    events.append(
                        {
                            "kind": "result",
                            "call_id": message.get("toolCallId", ""),
                            "name": message.get("toolName", ""),
                            "is_error": bool(message.get("isError")),
                            "text": item.get("text", ""),
                        }
                    )
    return events


def clip(text: str, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f" ...[truncated, {len(text)} chars total]"


def render(session_id: str, graph: dict[str, Any], raw_path: Path) -> str:
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    intent = next((n for n in graph["nodes"] if n["node_type"] == "intent"), None)
    lines: list[str] = []
    lines.append(f"# Evidence pack: {session_id}")
    lines.append("")
    lines.append(f"- graph_id: `{graph['graph_id']}`")
    lines.append(f"- created_at: {graph.get('created_at')}")
    lines.append(f"- nodes/edges: {graph['statistics']['num_nodes']} / {graph['statistics']['num_edges']}")
    lines.append(f"- raw session file: {'YES' if raw_path.exists() else 'MISSING (graph-node evidence only)'}")
    control_edges = [e for e in graph["edges"] if e["type"] == "control_influence"]
    lines.append(f"- control_influence candidate edges: {len(control_edges)}")
    lines.append("")

    lines.append("## User messages")
    lines.append("")
    user_messages: list[str] = []
    if intent:
        req = intent["metadata"].get("original_request")
        if isinstance(req, str) and req.strip():
            user_messages.append(clip(req, MAX_USER_MESSAGE))
        for extra in intent["metadata"].get("additional_user_messages", []) or []:
            if isinstance(extra, str) and extra.strip():
                user_messages.append(clip(extra, MAX_USER_MESSAGE))
    if user_messages:
        for i, msg in enumerate(user_messages, 1):
            lines.append(f"**[{i}]** {msg}")
            lines.append("")
    else:
        lines.append("(none recorded)")
        lines.append("")

    raw_events = load_raw_events(raw_path)
    if raw_events:
        lines.append("## Full event stream (from raw session file)")
        lines.append("")
        call_seq = 0
        for event in raw_events:
            if event["kind"] == "user":
                lines.append(f"### USER")
                lines.append("```")
                lines.append(clip(event["text"], MAX_USER_MESSAGE))
                lines.append("```")
                lines.append("")
            elif event["kind"] == "call":
                call_seq += 1
                lines.append(f"### call_{call_seq} — `{event['name']}`")
                lines.append("```json")
                lines.append(clip(json.dumps(event["arguments"], ensure_ascii=False, indent=1), 1200))
                lines.append("```")
                lines.append("")
            elif event["kind"] == "result":
                marker = " (ERROR)" if event["is_error"] else ""
                lines.append(f"#### result{marker} for `{event['name']}`")
                lines.append("```")
                lines.append(clip(event["text"], MAX_RAW_OBSERVATION))
                lines.append("```")
                lines.append("")
    else:
        lines.append("## Event stream (graph-node evidence)")
        lines.append("")
        lines.append("Observation text is limited to the 200-char builder preview.")
        lines.append("")
        for node in sorted(graph["nodes"], key=lambda n: n.get("timestamp", 0)):
            if node["node_type"] == "tool_call":
                lines.append(f"### {node['node_id']} — `{node.get('tool_name')}` (auth={node.get('authorized')})")
                lines.append("```json")
                lines.append(clip(json.dumps(node.get("parameters", {}), ensure_ascii=False, indent=1), 1200))
                lines.append("```")
                lines.append("")
            elif node["node_type"] == "observation":
                preview = node.get("content_preview", "")
                lines.append(f"#### {node['node_id']} preview (from `{node.get('data_source')}`)")
                lines.append("```")
                lines.append(clip(preview, 200))
                lines.append("```")
                lines.append("")

    if control_edges:
        lines.append("## control_influence candidate edges (structural candidates only — NOT ground truth)")
        lines.append("")
        for edge in control_edges:
            src = nodes.get(edge["source"], {})
            fields = edge.get("metadata", {}).get("fields_from_observation", [])
            lines.append(
                f"- `{edge['edge_id']}` matched fields={fields} "
                f"(src tool: `{src.get('data_source', '?')}`)"
            )
        lines.append("")

    lines.append("## Graph summary")
    lines.append("")
    lines.append("```json")
    lines.append(
        json.dumps(
            {
                "nodes_by_type": graph["statistics"]["nodes_by_type"],
                "edges_by_type": graph["statistics"]["edges_by_type"],
            },
            ensure_ascii=False,
            indent=1,
        )
    )
    lines.append("```")
    return "\n".join(lines)


def main() -> int:
    graphs = load_graphs()
    if not graphs:
        print("no unknown-label graphs found", file=sys.stderr)
        return 2
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []
    for session_id in sorted(graphs):
        graph = graphs[session_id]
        raw_path = RAW_DIR / f"{session_id}.jsonl"
        content = render(session_id, graph, raw_path)
        out_path = OUT_DIR / f"{session_id}.md"
        out_path.write_text(content, encoding="utf-8")
        manifest.append(
            {
                "session_id": session_id,
                "graph_id": graph["graph_id"],
                "evidence_pack": str(out_path.relative_to(PROJECT_ROOT)),
                "raw_source_available": raw_path.exists(),
                "digest": hashlib.md5(content.encode("utf-8")).hexdigest()[:12],
            }
        )
    manifest_path = PROJECT_ROOT / "data" / "annotation" / "evidence_manifest.jsonl"
    with open(manifest_path, "w", encoding="utf-8") as fh:
        for row in manifest:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    raw_count = sum(1 for row in manifest if row["raw_source_available"])
    print(f"wrote {len(manifest)} evidence packs ({raw_count} with raw source) to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
