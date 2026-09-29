"""Layer 2 / Layer 3 explanation over TemporalGAT outputs.

The base TemporalGAT only emits per-node anomaly probabilities. To make a
flagged graph actionable, we layer two graph-traversal heuristics on top:

  Layer 2 — path ranking
      For every intent node, walk forward along any directed edge and
      score paths ending at a high-risk tool call. Path score is the
      product of (mean node prob on the path) and (sum of edge weights).
      The top-k paths are returned so the analyst sees the chain that
      mattered, not just the leaf node.

  Layer 3 — control-influence back-tracing
      For every tool call whose risk probability exceeds a threshold,
      follow incoming control_influence edges backwards. Each step adds
      the upstream observation/entity; we stop when we hit a low-trust
      node (the likely injection source) or when the chain cycles. The
      result is a "this observation drove that dangerous tool" attribution.

Both layers are pure-Python over the JSON graph + model outputs; they
add no extra learned parameters and run in O(V + E) per graph.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

LOW_TRUST_LABELS = {"low", "untrusted"}
HIGH_RISK_NODE_THRESHOLD = 0.5
PATH_LENGTH_LIMIT = 6
TOP_K_PATHS = 3


def _node_index(graph: Dict[str, Any]) -> Dict[str, int]:
    return {n["node_id"]: i for i, n in enumerate(graph.get("nodes", []))}


def _adjacency(graph: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for edge in graph.get("edges", []):
        out[edge["source"]].append(edge)
    return out


def _is_intent(node: Dict[str, Any]) -> bool:
    return node.get("node_type") == "intent"


def _is_tool_call(node: Dict[str, Any]) -> bool:
    return node.get("node_type") == "tool_call"


def _is_dangerous_tool(node: Dict[str, Any]) -> bool:
    return _is_tool_call(node) and node.get("tool_name") in {
        "send_email",
        "upload_file",
        "delete_file",
        "update_memory",
        "execute_command",
        "transfer_money",
        "send_message",
        "post_to_web",
    }


def _is_low_trust(node: Dict[str, Any]) -> bool:
    trust_label = str(node.get("trust_label", "")).lower()
    if trust_label in LOW_TRUST_LABELS:
        return True
    return float(node.get("trust_score", 1.0) or 1.0) < 0.4


def layer2_paths(
    graph: Dict[str, Any],
    node_probs: List[float],
    *,
    top_k: int = TOP_K_PATHS,
    risk_threshold: float = HIGH_RISK_NODE_THRESHOLD,
    max_depth: int = PATH_LENGTH_LIMIT,
) -> List[Dict[str, Any]]:
    """Return ranked paths from each intent to a high-risk tool call.

    Each path entry:
      {
        "intent_id": str,
        "target_id": str,
        "target_tool": str | None,
        "node_ids": [...],
        "edges": [(src, dst, type, weight), ...],
        "score": float,
        "mean_node_prob": float,
        "edge_weight_sum": float,
      }
    """
    nodes = graph.get("nodes", [])
    index = _node_index(graph)
    adj = _adjacency(graph)

    flagged_tool_ids = {
        n["node_id"]: n
        for n in nodes
        if _is_tool_call(n)
        and index.get(n["node_id"]) is not None
        and node_probs[index[n["node_id"]]] >= risk_threshold
    }
    if not flagged_tool_ids:
        return []

    candidates: List[Dict[str, Any]] = []
    for intent in (n for n in nodes if _is_intent(n)):
        intent_id = intent["node_id"]
        # BFS/DFS bounded by depth; keep best path per (intent, target)
        best: Dict[str, Dict[str, Any]] = {}
        stack: List[Tuple[List[str], List[Dict[str, Any]]]] = [([intent_id], [])]
        while stack:
            path_nodes, path_edges = stack.pop()
            if len(path_nodes) > max_depth:
                continue
            tail = path_nodes[-1]
            for edge in adj.get(tail, []):
                nxt = edge["target"]
                if nxt in path_nodes:
                    continue  # avoid cycles
                new_nodes = path_nodes + [nxt]
                new_edges = path_edges + [edge]
                if nxt in flagged_tool_ids:
                    probs = [
                        node_probs[index[nid]]
                        for nid in new_nodes
                        if index.get(nid) is not None
                    ]
                    if not probs:
                        continue
                    mean_prob = sum(probs) / len(probs)
                    edge_weight_sum = sum(float(e.get("weight", 1.0)) for e in new_edges)
                    score = mean_prob * edge_weight_sum
                    candidate = {
                        "intent_id": intent_id,
                        "target_id": nxt,
                        "target_tool": flagged_tool_ids[nxt].get("tool_name"),
                        "node_ids": new_nodes,
                        "edges": [
                            {
                                "source": e["source"],
                                "target": e["target"],
                                "type": e["type"],
                                "weight": float(e.get("weight", 1.0)),
                            }
                            for e in new_edges
                        ],
                        "score": round(score, 4),
                        "mean_node_prob": round(mean_prob, 4),
                        "edge_weight_sum": round(edge_weight_sum, 4),
                    }
                    prev = best.get(nxt)
                    if prev is None or candidate["score"] > prev["score"]:
                        best[nxt] = candidate
                stack.append((new_nodes, new_edges))
        candidates.extend(best.values())

    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates[:top_k]


def layer3_trace(
    graph: Dict[str, Any],
    node_probs: List[float],
    *,
    risk_threshold: float = HIGH_RISK_NODE_THRESHOLD,
    max_hops: int = 5,
) -> List[Dict[str, Any]]:
    """For each high-risk tool, trace control_influence back to a low-trust source.

    Returns one entry per high-risk tool:
      {
        "tool_call_id": str,
        "tool_name": str | None,
        "risk_prob": float,
        "chain": [
            {"node_id": str, "node_type": str, "trust_label": str,
             "trust_score": float, "hop": int, "via_edge": dict | None},
            ...
        ],
        "root": dict | None,  # low-trust observation/entity, if reached
        "hops": int,
      }
    """
    nodes = graph.get("nodes", [])
    index = _node_index(graph)

    incoming_ctrl: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for edge in graph.get("edges", []):
        if edge.get("type") == "control_influence":
            incoming_ctrl[edge["target"]].append(edge)

    results: List[Dict[str, Any]] = []
    for node in nodes:
        if not _is_tool_call(node):
            continue
        nid = node["node_id"]
        idx = index.get(nid)
        if idx is None or node_probs[idx] < risk_threshold:
            continue
        chain: List[Dict[str, Any]] = [
            {
                "node_id": nid,
                "node_type": node.get("node_type"),
                "tool_name": node.get("tool_name"),
                "trust_label": node.get("trust_label"),
                "trust_score": float(node.get("trust_score", 0.0) or 0.0),
                "hop": 0,
                "via_edge": None,
            }
        ]
        cursor = nid
        for hop in range(1, max_hops + 1):
            upstreams = incoming_ctrl.get(cursor, [])
            if not upstreams:
                break
            # Prefer the highest-weight incoming control edge; ties broken by trust
            upstreams_sorted = sorted(
                upstreams,
                key=lambda e: (
                    -float(e.get("weight", 1.0)),
                    -float(nodes[index[e["source"]]].get("trust_score", 1.0) or 1.0)
                    if index.get(e["source"]) is not None
                    else 0,
                ),
            )
            edge = upstreams_sorted[0]
            src_id = edge["source"]
            src_node = nodes[index[src_id]] if index.get(src_id) is not None else None
            if src_node is None:
                break
            chain.append({
                "node_id": src_id,
                "node_type": src_node.get("node_type"),
                "tool_name": src_node.get("tool_name"),
                "trust_label": src_node.get("trust_label"),
                "trust_score": float(src_node.get("trust_score", 0.0) or 0.0),
                "hop": hop,
                "via_edge": {
                    "type": edge["type"],
                    "weight": float(edge.get("weight", 1.0)),
                },
            })
            if _is_low_trust(src_node):
                break
            if src_id in {c["node_id"] for c in chain[:-1]}:
                break
            cursor = src_id

        root = next((c for c in chain if _is_low_trust({
            "trust_label": c.get("trust_label"),
            "trust_score": c.get("trust_score"),
        })), None)
        results.append({
            "tool_call_id": nid,
            "tool_name": node.get("tool_name"),
            "risk_prob": round(float(node_probs[idx]), 4),
            "chain": chain,
            "root": root,
            "hops": len(chain) - 1,
        })

    results.sort(key=lambda r: r["risk_prob"], reverse=True)
    return results


def explain_graph(
    graph: Dict[str, Any],
    node_probs: List[float],
    graph_risk: float,
    *,
    risk_threshold: float = HIGH_RISK_NODE_THRESHOLD,
) -> Dict[str, Any]:
    """One-shot wrapper: run layer 2 and 3 and package the verdict.

    The verdict includes the graph-level risk, the highest-probability
    node, the top suspicious paths, and the control-influence chains.
    Callers can persist the dict as JSON for downstream alerting.
    """
    index = _node_index(graph)
    if not index:
        return {
            "graph_id": graph.get("graph_id"),
            "graph_risk": round(graph_risk, 4),
            "verdict": "flagged" if graph_risk >= risk_threshold else "clean",
            "paths": [],
            "traces": [],
            "top_nodes": [],
        }

    top_nodes = sorted(
        (
            {
                "node_id": n["node_id"],
                "node_type": n.get("node_type"),
                "tool_name": n.get("tool_name"),
                "prob": round(float(node_probs[index[n["node_id"]]]), 4),
            }
            for n in graph.get("nodes", [])
            if index.get(n["node_id"]) is not None
        ),
        key=lambda x: x["prob"],
        reverse=True,
    )[:3]

    paths = layer2_paths(graph, node_probs, risk_threshold=risk_threshold)
    traces = layer3_trace(graph, node_probs, risk_threshold=risk_threshold)

    verdict = "flagged" if (
        graph_risk >= risk_threshold
        or any(t["root"] for t in traces)
        or any(p["score"] >= risk_threshold for p in paths)
    ) else "clean"

    return {
        "graph_id": graph.get("graph_id"),
        "graph_risk": round(float(graph_risk), 4),
        "verdict": verdict,
        "top_nodes": top_nodes,
        "paths": paths,
        "traces": traces,
    }
