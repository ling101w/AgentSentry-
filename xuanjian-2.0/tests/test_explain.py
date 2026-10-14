"""Unit tests for models/temporal_gat/explain.py."""

import pytest
import json
from models.temporal_gat.explain import (
    layer2_paths,
    layer3_trace,
    explain_graph,
    HIGH_RISK_NODE_THRESHOLD,
)


MINIMAL_GRAPH = {
    "graph_id": "test_1",
    "nodes": [
        {"node_id": "i1", "node_type": "intent", "task_type": "email_summary"},
        {"node_id": "tc1", "node_type": "tool_call", "tool_name": "read_email"},
        {"node_id": "o1", "node_type": "observation", "trust_label": "medium", "trust_score": 0.6},
        {"node_id": "tc2", "node_type": "tool_call", "tool_name": "send_email"},
        {"node_id": "e1", "node_type": "entity", "entity_type": "email"},
    ],
    "edges": [
        {"source": "i1", "target": "tc1", "type": "intent_drives", "weight": 1.0},
        {"source": "tc1", "target": "o1", "type": "data_dependency", "weight": 0.8},
        {"source": "o1", "target": "tc2", "type": "control_influence", "weight": 0.9},
        {"source": "o1", "target": "e1", "type": "data_derivation", "weight": 0.7},
        {"source": "tc2", "target": "e1", "type": "call_sequence", "weight": 0.9},
    ],
}

ATTACK_GRAPH = {
    "graph_id": "test_attack",
    "nodes": [
        {"node_id": "i1", "node_type": "intent", "task_type": "email_summary"},
        {"node_id": "tc1", "node_type": "tool_call", "tool_name": "read_email"},
        {
            "node_id": "o1",
            "node_type": "observation",
            "trust_label": "low",
            "trust_score": 0.3,
        },
        {"node_id": "tc2", "node_type": "tool_call", "tool_name": "send_email"},
    ],
    "edges": [
        {"source": "i1", "target": "tc1", "type": "intent_drives", "weight": 1.0},
        {"source": "tc1", "target": "o1", "type": "data_dependency", "weight": 0.8},
        {"source": "o1", "target": "tc2", "type": "control_influence", "weight": 0.95},
        # Layer-2 path: i1 -> tc1 (call_seq) -> tc2
        {"source": "tc1", "target": "tc2", "type": "call_sequence", "weight": 0.9},
    ],
}


class TestLayer2Paths:
    def test_no_paths_when_no_high_risk_nodes(self):
        probs = [0.1, 0.1, 0.1, 0.1]
        paths = layer2_paths(MINIMAL_GRAPH, probs, risk_threshold=0.9)
        assert paths == []

    def test_path_found_to_high_risk_tool(self):
        # tc2 (index 3) is the attack sink
        probs = [0.1, 0.1, 0.1, 0.95]
        paths = layer2_paths(ATTACK_GRAPH, probs, risk_threshold=0.5)
        assert len(paths) == 1
        assert paths[0]["target_id"] == "tc2"
        assert paths[0]["target_tool"] == "send_email"
        assert "i1" in paths[0]["node_ids"]
        assert paths[0]["score"] > 0

    def test_path_score_is_ranked(self):
        # Two intent nodes both reaching tc2
        graph = {
            "graph_id": "dual",
            "nodes": [
                {"node_id": "i1", "node_type": "intent"},
                {"node_id": "i2", "node_type": "intent"},
                {"node_id": "tc1", "node_type": "tool_call", "tool_name": "read_email"},
                {"node_id": "tc2", "node_type": "tool_call", "tool_name": "send_email"},
            ],
            "edges": [
                {"source": "i1", "target": "tc1", "type": "intent_drives", "weight": 1.0},
                {"source": "tc1", "target": "tc2", "type": "control_influence", "weight": 0.9},
                {"source": "i2", "target": "tc2", "type": "intent_drives", "weight": 1.0},
            ],
        }
        probs = [0.1, 0.5, 0.1, 0.95]
        paths = layer2_paths(graph, probs, risk_threshold=0.5)
        assert len(paths) == 2
        scores = [p["score"] for p in paths]
        assert scores == sorted(scores, reverse=True)

    def test_top_k_limit(self):
        # 4 intents, each reaches the bad tool via a 3-hop chain (depth 4).
        # depth=4 fits within PATH_LENGTH_LIMIT=6, so all 4 paths can be found.
        nodes = []
        edges = []
        for i in range(4):
            nodes.append({"node_id": f"intent_{i}", "node_type": "intent"})
            nodes.append({"node_id": f"hop_a_{i}", "node_type": "tool_call", "tool_name": "intermediate"})
            nodes.append({"node_id": f"hop_b_{i}", "node_type": "tool_call", "tool_name": "intermediate"})
            edges.append({"source": f"intent_{i}", "target": f"hop_a_{i}",
                          "type": "intent_drives", "weight": 1.0})
            edges.append({"source": f"hop_a_{i}", "target": f"hop_b_{i}",
                          "type": "call_sequence", "weight": 0.9})
            edges.append({"source": f"hop_b_{i}", "target": "tc_bad",
                          "type": "call_sequence", "weight": 0.9})
        nodes.append({"node_id": "tc_bad", "node_type": "tool_call", "tool_name": "send_email"})
        graph = {"graph_id": "many_paths", "nodes": nodes, "edges": edges}

        probs = [0.1] * (len(nodes) - 1) + [0.95]
        paths = layer2_paths(graph, probs, risk_threshold=0.5, top_k=3)
        assert len(paths) == 3
        # All paths share the same target tool, ranked by score
        assert all(p["target_id"] == "tc_bad" for p in paths)


class TestLayer3Trace:
    def test_no_trace_when_no_high_risk_tools(self):
        probs = [0.1, 0.1, 0.1, 0.1]
        traces = layer3_trace(MINIMAL_GRAPH, probs, risk_threshold=0.9)
        assert traces == []

    def test_trace_reaches_low_trust_root(self):
        # o1 is low-trust and drives tc2 via control_influence
        probs = [0.1, 0.1, 0.1, 0.95]
        traces = layer3_trace(ATTACK_GRAPH, probs, risk_threshold=0.5)
        assert len(traces) == 1
        assert traces[0]["tool_call_id"] == "tc2"
        assert traces[0]["hops"] == 1
        assert traces[0]["root"] is not None
        assert traces[0]["root"]["node_id"] == "o1"
        assert traces[0]["root"]["trust_label"] == "low"

    def test_trace_chain_contains_edge_info(self):
        probs = [0.1, 0.1, 0.1, 0.95]
        traces = layer3_trace(ATTACK_GRAPH, probs, risk_threshold=0.5)
        chain = traces[0]["chain"]
        # hop 1: observation_3 -> tc2
        hop1 = next(c for c in chain if c["hop"] == 1)
        assert hop1["via_edge"]["type"] == "control_influence"
        assert hop1["via_edge"]["weight"] == 0.95

    def test_empty_graph(self):
        empty = {"graph_id": "empty", "nodes": [], "edges": []}
        traces = layer3_trace(empty, [], risk_threshold=0.5)
        assert traces == []


class TestExplainGraph:
    def test_clean_verdict_low_risk(self):
        probs = [0.05] * 5
        result = explain_graph(MINIMAL_GRAPH, probs, graph_risk=0.05, risk_threshold=0.5)
        assert result["verdict"] == "clean"
        assert result["paths"] == []
        assert result["traces"] == []

    def test_flagged_verdict_high_graph_risk(self):
        # ATTACK_GRAPH has 4 nodes (i1, tc1, o1, tc2); tc2 is the dangerous sink
        probs = [0.1, 0.1, 0.1, 0.95]
        result = explain_graph(ATTACK_GRAPH, probs, graph_risk=0.8, risk_threshold=0.5)
        assert result["verdict"] == "flagged"
        assert len(result["paths"]) >= 1
        assert len(result["traces"]) >= 1

    def test_top_nodes_sorted_by_prob(self):
        probs = [0.05, 0.1, 0.3, 0.95]
        result = explain_graph(ATTACK_GRAPH, probs, graph_risk=0.8, risk_threshold=0.5)
        probs_out = [n["prob"] for n in result["top_nodes"]]
        assert probs_out == sorted(probs_out, reverse=True)

    def test_empty_graph_handled(self):
        empty = {"graph_id": "empty", "nodes": [], "edges": []}
        result = explain_graph(empty, [], graph_risk=0.0)
        assert result["verdict"] == "clean"
        assert result["top_nodes"] == []
