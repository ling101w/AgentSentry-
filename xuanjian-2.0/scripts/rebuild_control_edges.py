"""Rebuild control_influence edges in existing causal graph JSONL files.

背景（2026-08-30 盲测发现）：graph_builder 旧逻辑要求 event.source ==
"observation" 才画 control_influence 边，但真实 OpenClaw 日志从不打这个
标签（30 条真实 session 的 1084 个调用里 0 个），导致真实图 3255 条边里
0 条控制边，模型在真实数据上无信号可用。

本脚本对已生成的 JSONL 图做后处理：对每条 observation -> tool_call 的
data_dependency 边，重新计算"参数值 ⊂ 观测 content_preview"的字段匹配
比例；比例 >= 阈值（默认 0.5）的边升级为 control_influence，权重取匹配
比例（下限 0.5）。与修复后的 graph_builder.py 规则一致。

用法：
    python -m scripts.rebuild_control_edges --input <file.jsonl> [--analyze-only]
    python -m scripts.rebuild_control_edges --input <file.jsonl> --output <file.jsonl>
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.openclaw_graph_builder.graph_builder import _flatten_params  # noqa: E402


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def compute_match_ratio(call: Dict[str, Any], observation: Dict[str, Any]) -> Tuple[float, List[str]]:
    """参数值出现在观测 content_preview 中的字段比例（与 builder 的 _control_fields 一致）."""
    preview = (observation.get("content_preview") or "").lower()
    if not preview:
        return 0.0, []
    matched = []
    params = call.get("parameters") or {}
    for key, value in _flatten_params(params):
        text = _stringify(value).lower()
        if text and text in preview:
            matched.append(key)
    total = [key for key, _ in _flatten_params(params)]
    if not total:
        return 0.0, []
    return len(matched) / len(total), matched


def rebuild_graph(graph: Dict[str, Any], threshold: float) -> Tuple[Dict[str, Any], Counter, List[float]]:
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    ratios: List[float] = []
    stats: Counter = Counter()
    new_edges = []
    for edge in graph["edges"]:
        src = nodes.get(edge["source"])
        dst = nodes.get(edge["target"])
        is_obs_to_call = (
            src is not None and dst is not None
            and src["node_type"] == "observation" and dst["node_type"] == "tool_call"
        )
        if is_obs_to_call and edge["type"] in ("data_dependency", "control_influence"):
            ratio, matched = compute_match_ratio(dst, src)
            ratios.append(ratio)
            if ratio >= threshold:
                stats["upgraded_to_control"] += 1
                new_edge = dict(edge)
                new_edge["type"] = "control_influence"
                new_edge["weight"] = round(max(ratio, 0.5), 3)
                new_edge["metadata"] = dict(edge.get("metadata") or {})
                new_edge["metadata"]["fields_from_observation"] = matched
                new_edge["edge_id"] = f"{edge['source']}--control_influence-->{edge['target']}"
                new_edges.append(new_edge)
                continue
        stats["kept_as_is"] += 1
        new_edges.append(edge)
    graph = dict(graph)
    graph["edges"] = new_edges
    # 更新 statistics 里的边计数
    edge_counts: Dict[str, int] = {}
    for e in new_edges:
        edge_counts[e["type"]] = edge_counts.get(e["type"], 0) + 1
    graph["statistics"] = dict(graph.get("statistics") or {})
    graph["statistics"]["edges_by_type"] = edge_counts
    graph["statistics"]["num_edges"] = len(new_edges)
    return graph, stats, ratios


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, required=True, help="JSONL file of graphs")
    parser.add_argument("--output", type=str, default=None, help="Output JSONL (default: in-place)")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--analyze-only", action="store_true")
    args = parser.parse_args()

    in_path = Path(args.input)
    graphs = []
    with open(in_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                graphs.append(json.loads(line))

    all_ratios: List[float] = []
    total_stats: Counter = Counter()
    rebuilt = []
    for graph in graphs:
        new_graph, stats, ratios = rebuild_graph(graph, args.threshold)
        rebuilt.append(new_graph)
        total_stats.update(stats)
        all_ratios.extend(ratios)

    print(f"[input] {len(graphs)} graphs, {len(all_ratios)} obs->call edges")
    if all_ratios:
        above = sum(1 for r in all_ratios if r >= args.threshold)
        print(f"[match ratio] min={min(all_ratios):.2f} max={max(all_ratios):.2f} "
              f"mean={sum(all_ratios)/len(all_ratios):.2f}")
        print(f"[ratio >= {args.threshold}] {above}/{len(all_ratios)} edges "
              f"({above/len(all_ratios)*100:.1f}%)")
        hist = Counter(round(r, 1) for r in all_ratios)
        print("[ratio histogram]", " ".join(f"{k:.1f}:{v}" for k, v in sorted(hist.items())))
    print(f"[edges] upgraded_to_control={total_stats['upgraded_to_control']} "
          f"kept_as_is={total_stats['kept_as_is']}")

    if not args.analyze_only:
        out_path = Path(args.output) if args.output else in_path
        with open(out_path, "w", encoding="utf-8") as fh:
            for graph in rebuilt:
                fh.write(json.dumps(graph, ensure_ascii=False) + "\n")
        print(f"[saved] {out_path}")


if __name__ == "__main__":
    main()
