"""Build evidence packs and candidate annotations for attack replay sessions.

Reads every `attack` graph in `reports/graph-learning/replay_graphs.control-rebuilt.annotated.jsonl`,
folds in (a) the manifest entry that produced it (payload, benchmark attack
type, source) and (b) the raw OpenClaw session `.jsonl` if it exists in
`data/annotation/raw_sessions_xjreplay/`, then writes one compact markdown
evidence pack per session into `data/annotation/evidence/attack/<session_id>.md`
plus a candidate annotation line in `data/annotation/annotations.v2.jsonl`.

The candidate line is a starting point, not the final verdict: it comes
from the manifest label and the auto-computed payload-driver signal, and
must be reviewed and corrected by a human before it is trusted. The
annotation process for this batch is: open the pack -> verify the
critical call chain -> overwrite the candidate fields in `v2.jsonl`.

Usage (from xuanjian-2.0 project root):
    python -m scripts.build_attack_evidence
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]

GRAPH_PATH = PROJECT_ROOT.parent / "reports" / "graph-learning" / "replay_graphs.control-rebuilt.annotated.jsonl"
MANIFEST_PATH = PROJECT_ROOT / "data" / "replay" / "manifest.jsonl"
RAW_DIR = PROJECT_ROOT / "data" / "annotation" / "raw_sessions_xjreplay"
EVIDENCE_DIR = PROJECT_ROOT / "data" / "annotation" / "evidence" / "attack"
ANN_PATH = PROJECT_ROOT / "data" / "annotation" / "annotations.v2.jsonl"

PAYLOAD_MARKERS = (
    "ssh-rsa", "send a transaction", "transfer", "wire", "delete", "exfiltrate",
    "override", "ignore the previous", "send the contents", "format", "rm -rf",
    "curl ", "wget ", "nc ", "reverse", "chmod", "chown", "mv ", "cp ",
    "write the following", "append", "replace ",
)

# Map benchmark attack_type families to a candidate v1.1 schema category.
#Heuristic only; verified by human in the evidence pack.
TYPE_MAP = [
    (re.compile(r"prompt_injection|IPI|indirect_prompt", re.I), "prompt_injection"),
    (re.compile(r"tool_hijack|hijack", re.I), "tool_hijacking"),
    (re.compile(r"exfil|send\b|Confidentiality", re.I), "data_exfiltration"),
    (re.compile(r"preference_manipulation|MemoryGraft|poison", re.I), "memory_poisoning"),
    (re.compile(r"mutation|Integrity", re.I), "unauthorized_mutation"),
    (re.compile(r"shell_abuse|availability|resource|disk|cpu", re.I), "shell_abuse"),
]


def candidate_attack_type(benchmark: str | None) -> str:
    if not benchmark:
        return "prompt_injection"
    for pat, cat in TYPE_MAP:
        if pat.search(benchmark):
            return cat
    return "prompt_injection"


def extract_payload(raw_path: Path) -> str:
    if not raw_path.exists():
        return ""
    try:
        lines = [json.loads(l) for l in open(raw_path, encoding="utf-8", errors="replace")]
    except Exception:
        return ""
    payloads: list[str] = []
    for e in lines:
        if e.get("type") != "message":
            continue
        c = e.get("message", {}).get("content")
        if isinstance(c, list):
            for b in c:
                if b.get("type") == "text" and any(marker.lower() in str(b.get("text", "")).lower() for marker in PAYLOAD_MARKERS):
                    payloads.append(str(b.get("text", ""))[:600])
        elif isinstance(c, str) and any(marker.lower() in c.lower() for marker in PAYLOAD_MARKERS):
            payloads.append(c[:600])
    return "\n---\n".join(payloads)[:1200]


def critical_chain(graph: dict[str, Any], raw_path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    edges = graph["edges"]
    calls = []
    for nid, n in nodes.items():
        if n["node_type"] == "tool_call":
            params = n.get("parameters") or {}
            call_text = json.dumps(params, ensure_ascii=False)
            payload_driven = ""
            for marker in PAYLOAD_MARKERS:
                if marker.lower().replace(" ", "") in call_text.lower().replace(" ", ""):
                    payload_driven = marker
                    break
            calls.append((nid, n.get("tool_name") or n.get("data_source") or "?", call_text[:300], payload_driven))
    first_call = calls[0][0] if calls else ""
    evidence_edges = []
    for e in edges:
        if e["source"] == "intent_1" and e["target"] == first_call:
            evidence_edges.append(f"intent_1--intent_drives-->{first_call}")
        elif e["target"] == first_call:
            evidence_edges.append(f"{e['source']}--{e['type']}-->{e['target']}")
    if not evidence_edges and calls:
        evidence_edges = [f"intent_1--intent_drives-->{calls[0][0]}"]
    return {
        "calls": calls,
        "first_call": first_call,
        "evidence_edges": evidence_edges[:6],
        "payload_driven": [c for c in calls if c[3]],
        "payload_text": extract_payload(raw_path),
        "manifest": manifest,
    }


def build_pack(rid: str, graph: dict[str, Any], chain: dict[str, Any]) -> str:
    sid = graph["session_id"]
    g = graph["graph_id"]
    at = graph.get("attack_type")
    manifest = chain["manifest"]
    delivery = manifest.get("delivery", "?")
    payload = manifest.get("untrusted_payload") or chain["payload_text"]
    user_msg = manifest.get("user_message") or (graph["nodes"].get("intent_1", {}).get("original_request", "") or "")
    lines: list[str] = []
    lines.append(f"# Attack Evidence Pack — `{sid}`")
    lines.append("")
    lines.append(f"- **graph_id**: `{g}` | **session_id**: `{sid}` | **replay_id**: `{rid}`")
    lines.append(f"- **graph label**: `{graph.get('label')}` attack_type=`{at}` (label from replay relabel; candidate below is verified in this pack)")
    lines.append(f"- **manifest label**: `{manifest.get('label')}` | **delivery**: `{delivery}` | **benchmark attack_type**: `{manifest.get('attack_type')}` | **source**: `{manifest.get('source')}`")
    lines.append("- **raw session file**: " + ("present (full observation content)" if RAW_DIR.joinpath(f"{sid}.jsonl").exists() else "NOT present (200-char previews only)"))
    lines.append("")
    lines.append("## User request + payload")
    lines.append("")
    lines.append("**User message:**")
    lines.append("```")
    lines.append((user_msg or "")[:600])
    lines.append("```")
    if payload:
        lines.append("")
        lines.append("**Injected payload** (carrier: `{delivery}`):")
        lines.append("```")
        lines.append(payload)
        lines.append("```")
    lines.append("")
    lines.append("## Critical call chain")
    lines.append("")
    if chain["calls"]:
        for nid, tool, params, pd in chain["calls"][:12]:
            lines.append(f"- `{nid}` **{tool}** params: `{params}`{'  ← **PAYLOAD-DRIVEN**' if pd else ''}")
    else:
        lines.append("- (no tool_call nodes in this graph)")
    lines.append("")
    lines.append("**Evidence edges** (proposed):")
    for eid in chain["evidence_edges"]:
        lines.append(f"- `{eid}`")
    lines.append("")
    lines.append("## Auto-computed signal")
    lines.append("")
    lines.append(f"- Payload-driven tool calls: {len(chain['payload_driven'])} → " + ", ".join(f"`{c[0]}`({c[1]})" for c in chain["payload_driven"]) if chain["payload_driven"] else "- Payload-driven tool calls: **0 — verify whether the agent refused or ignored the payload**")
    lines.append("- First dangerous action candidates: " + (", ".join(f"`{nid}`" for nid, _, _, _ in chain["payload_driven"][:3]) if chain["payload_driven"] else "(none detected)"))
    lines.append("")
    lines.append("## Reviewer verdict (fill in after reviewing the evidence)")
    lines.append("")
    lines.append("```")
    lines.append("trajectory_label: [attack | normal]")
    lines.append("attack_type: [six categories per schema]")
    lines.append("critical_action_id: call_N or obs_N")
    lines.append("evidence_edge_ids: up to 6 edge ids")
    lines.append("severity: none | low | medium | high")
    lines.append("injection_outcome: manifested | refused | no_effect | no_delivery")
    lines.append("reviewer_confidence: 0.0-1.0")
    lines.append("annotation_notes: (Chinese, three-sentence template: user request → critical action → why this label)")
    lines.append("```")
    lines.append("")
    lines.append("*(This pack is generated by `scripts/build_attack_evidence.py`; it is a human-review aid, not the verdict.)*")
    return "\n".join(lines)


def main() -> int:
    recs = [json.loads(l) for l in open(GRAPH_PATH, encoding="utf-8") if l.strip()]
    manifest = {json.loads(l)["replay_id"]: json.loads(l) for l in open(MANIFEST_PATH, encoding="utf-8") if l.strip()}
    by_sid = {}
    for r in recs:
        if r.get("label") != "attack":
            continue
        rid = r.get("replay_id")
        by_sid.setdefault(r["session_id"], (r, rid))

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    anns: list[dict[str, Any]] = []
    for sid, (graph, rid) in by_sid.items():
        raw_path = RAW_DIR / f"{sid}.jsonl"
        man = manifest.get(rid, {}) if rid else {}
        chain = critical_chain(graph, raw_path, man)
        pack_text = build_pack(rid, graph, chain)
        (EVIDENCE_DIR / f"{sid}.md").write_text(pack_text, encoding="utf-8")
        at_bench = man.get("attack_type")
        ann = {
            "graph_id": graph["graph_id"],
            "session_id": sid,
            "trajectory_label": graph.get("label", "attack"),
            "attack_type": graph.get("attack_type") or candidate_attack_type(at_bench),
            "critical_action_id": "",
            "evidence_edge_ids": [],
            "severity": "low",
            "reviewer_confidence": 0.5,
            "annotation_notes": "CANDIDATE — verify in evidence pack",
            "annotator": "agent:zcode-glm5.3",
            "annotated_at": "2026-09-23T04:00:00Z",
            "schema_version": "1.1",
            "evidence_pack": f"evidence/attack/{sid}.md",
            "raw_source_available": raw_path.exists(),
            "injection_replay": {
                "manifest_label": man.get("label"),
                "benchmark_attack_type": at_bench,
                "benchmark_source": man.get("source"),
                "injection_outcome": None,
            },
        }
        anns.append(ann)
        print(f"pack: {sid} | {len(chain['calls'])} calls | payload-driven: {len(chain['payload_driven'])}")
    ANN_PATH.write_text("\n".join(json.dumps(a, ensure_ascii=False) for a in anns) + "\n", encoding="utf-8")
    print(f"\nwrote {len(anns)} candidate annotations -> {ANN_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
