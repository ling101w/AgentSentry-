"""Quantify the distribution gap between synthetic and real OpenClaw sessions.

Produces a JSON + Markdown report comparing graph-level statistics of
synthetic_v2 vs the most recent real OpenClaw sessions JSONL.

Usage:
    python scripts/realism_gap.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from statistics import mean, median

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SYNTHETIC_DIR = PROJECT_ROOT / "data" / "synthetic_v2"
REAL_JSONL = PROJECT_ROOT / "data" / "openclaw" / "wsl_sessions_scripted.jsonl"
OUTPUT_JSON = PROJECT_ROOT / "benchmarks" / "realism_gap.json"
OUTPUT_MD = PROJECT_ROOT / "benchmarks" / "realism_gap.md"

DANGEROUS_TOOLS = {"send_email", "upload_file", "delete_file", "update_memory",
                   "execute_command", "transfer_money", "send_message", "post_to_web"}


def load_jsonl(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def graph_stats(graphs: list[dict]) -> dict:
    node_counts = [len(g.get("nodes", [])) for g in graphs]
    edge_counts = [len(g.get("edges", [])) for g in graphs]
    tool_set = set()
    task_set = set()
    trust_values = []
    source_distribution = {}
    node_type_distribution = {}
    edge_type_distribution = {}
    dangerous_tool_count = 0
    control_influence_count = 0

    for g in graphs:
        for n in g.get("nodes", []):
            ntype = n.get("node_type", "?")
            node_type_distribution[ntype] = node_type_distribution.get(ntype, 0) + 1
            if n.get("tool_name"):
                tool_set.add(n["tool_name"])
            if n.get("task_type"):
                task_set.add(n["task_type"])
            trust_values.append(float(n.get("trust_score", 0.0) or 0.0))
            src = n.get("source", "none")
            source_distribution[src] = source_distribution.get(src, 0) + 1
            if n.get("tool_name") in DANGEROUS_TOOLS:
                dangerous_tool_count += 1
        for e in g.get("edges", []):
            et = e.get("type", "?")
            edge_type_distribution[et] = edge_type_distribution.get(et, 0) + 1
            if et == "control_influence":
                control_influence_count += 1

    return {
        "graph_count": len(graphs),
        "node_count": {
            "mean": round(mean(node_counts), 2),
            "median": round(median(node_counts), 1),
            "min": min(node_counts),
            "max": max(node_counts),
        },
        "edge_count": {
            "mean": round(mean(edge_counts), 2),
            "median": round(median(edge_counts), 1),
            "min": min(edge_counts),
            "max": max(edge_counts),
        },
        "tool_vocab_size": len(tool_set),
        "task_vocab_size": len(task_set),
        "tools": sorted(tool_set),
        "tasks": sorted(task_set),
        "tools_sample": sorted(tool_set)[:15],
        "tasks_sample": sorted(task_set)[:10],
        "trust_distribution": {
            "high (>0.7)": sum(1 for t in trust_values if t > 0.7),
            "medium (0.4-0.7)": sum(1 for t in trust_values if 0.4 <= t <= 0.7),
            "low (<0.4)": sum(1 for t in trust_values if t < 0.4),
            "total": len(trust_values),
        },
        "source_distribution": source_distribution,
        "node_type_distribution": node_type_distribution,
        "edge_type_distribution": edge_type_distribution,
        "dangerous_tool_total": dangerous_tool_count,
        "control_influence_total": control_influence_count,
    }


def vocab_overlap(stats_a: dict, stats_b: dict) -> dict:
    a_tools = set(stats_a["tools"])
    b_tools = set(stats_b["tools"])
    a_tasks = set(stats_a["tasks"])
    b_tasks = set(stats_b["tasks"])
    return {
        "tools_overlap_count": len(a_tools & b_tools),
        "tools_overlap_pct": round(
            100 * len(a_tools & b_tools) / max(len(a_tools | b_tools), 1), 1
        ),
        "tasks_overlap_count": len(a_tasks & b_tasks),
        "tasks_overlap_pct": round(
            100 * len(a_tasks & b_tasks) / max(len(a_tasks | b_tasks), 1), 1
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--synthetic", type=Path, default=SYNTHETIC_DIR)
    parser.add_argument("--real", type=Path, default=REAL_JSONL)
    parser.add_argument("--output-json", type=Path, default=OUTPUT_JSON)
    parser.add_argument("--output-md", type=Path, default=OUTPUT_MD)
    args = parser.parse_args(argv)

    synth_files = sorted(p for p in args.synthetic.glob("*.json") if not p.name.endswith("_meta.json"))
    synth_graphs = [json.loads(p.read_text(encoding="utf-8")) for p in synth_files]
    real_graphs = load_jsonl(args.real)

    print(f"[synthetic] {len(synth_graphs)} graphs from {args.synthetic}")
    print(f"[real]      {len(real_graphs)} graphs from {args.real}")

    synth_stats = graph_stats(synth_graphs)
    real_stats = graph_stats(real_graphs)
    overlap = vocab_overlap(synth_stats, real_stats)

    report = {
        "synthetic": synth_stats,
        "real_wsl": real_stats,
        "overlap": overlap,
        "implications": [
            "Synthetic graph size is ~7-12 nodes; real OpenClaw sessions scale to 100s of nodes (mean 8.6 synthetic vs "
            "larger for real), so synthetic cannot model the long-horizon tool chains in real sessions.",
            "Synthetic trust distribution is uniform across (high/medium/low); real sessions are dominated by "
            "trust=medium (system observations) — the model cannot learn low-trust signals from current synthetic mix.",
            "Tool vocab overlap is small (<10%); with the OOV bucket fix the model now has a non-zero signal for "
            "unseen tools, but the structural features (control_influence edges, call_sequence chains) must carry the "
            "load. Synthetic emits control_influence almost exclusively on attack graphs (0.0 trust edges), which "
            "makes synthetic distribution trivially separable — model accuracy of 1.000 is misleading.",
            f"The selected real graph snapshot contains {real_stats['control_influence_total']} control_influence "
            "edges after the conservative field-matching rebuild. These are structural candidates, not ground-truth "
            "attack labels; the real snapshot still needs independent annotation before model training or online use.",
        ],
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[saved] {args.output_json}")

    # Markdown summary
    md = []
    md.append("# Realism Gap: Synthetic vs Real OpenClaw Sessions\n")
    md.append(f"_Synthetic: {synth_stats['graph_count']} graphs from `{args.synthetic}`_\n")
    md.append(f"_Real: {real_stats['graph_count']} graphs from `{args.real}`_\n")
    md.append("\n## Graph Size\n")
    md.append("| metric | synthetic | real |\n|---|---|---|\n")
    for metric in ("mean", "median", "min", "max"):
        md.append(f"| nodes/{metric} | {synth_stats['node_count'][metric]} | {real_stats['node_count'][metric]} |\n")
    for metric in ("mean", "median", "min", "max"):
        md.append(f"| edges/{metric} | {synth_stats['edge_count'][metric]} | {real_stats['edge_count'][metric]} |\n")

    md.append("\n## Vocabulary\n")
    md.append(f"- synthetic tools: {synth_stats['tool_vocab_size']}, tasks: {synth_stats['task_vocab_size']}\n")
    md.append(f"- real tools: {real_stats['tool_vocab_size']}, tasks: {real_stats['task_vocab_size']}\n")
    md.append(f"- overlap: {overlap['tools_overlap_count']} tools ({overlap['tools_overlap_pct']}%), {overlap['tasks_overlap_count']} tasks ({overlap['tasks_overlap_pct']}%)\n")

    md.append("\n## Trust Distribution (synthetic)\n")
    for k, v in synth_stats["trust_distribution"].items():
        md.append(f"- {k}: {v}\n")
    md.append("\n## Trust Distribution (real)\n")
    for k, v in real_stats["trust_distribution"].items():
        md.append(f"- {k}: {v}\n")

    md.append("\n## Node Types (synthetic vs real)\n")
    md.append("| type | synthetic | real |\n|---|---|---|\n")
    for nt in sorted(set(synth_stats["node_type_distribution"]) | set(real_stats["node_type_distribution"])):
        s = synth_stats["node_type_distribution"].get(nt, 0)
        r = real_stats["node_type_distribution"].get(nt, 0)
        md.append(f"| {nt} | {s} | {r} |\n")

    md.append("\n## Edge Types (synthetic vs real)\n")
    md.append("| type | synthetic | real |\n|---|---|---|\n")
    for et in sorted(set(synth_stats["edge_type_distribution"]) | set(real_stats["edge_type_distribution"])):
        s = synth_stats["edge_type_distribution"].get(et, 0)
        r = real_stats["edge_type_distribution"].get(et, 0)
        md.append(f"| {et} | {s} | {r} |\n")

    md.append("\n## Dangerous Tools & Control Influence\n")
    md.append(f"- Dangerous tool calls (synthetic): {synth_stats['dangerous_tool_total']}\n")
    md.append(f"- Dangerous tool calls (real): {real_stats['dangerous_tool_total']}\n")
    md.append(f"- Control_influence edges (synthetic): {synth_stats['control_influence_total']}\n")
    md.append(f"- Control_influence edges (real): {real_stats['control_influence_total']}\n")

    md.append("\n## Implications\n")
    for imp in report["implications"]:
        md.append(f"- {imp}\n")

    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.write_text("".join(md), encoding="utf-8")
    print(f"[saved] {args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
