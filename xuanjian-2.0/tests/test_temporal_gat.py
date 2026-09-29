"""Unit tests for the TemporalGAT model package."""

import sys
import unittest
from pathlib import Path

import torch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.temporal_gat.dataset import (  # noqa: E402
    BASE_FEATURE_DIM,
    CausalGraphDataset,
    collate_graphs,
    graph_to_tensors,
)
from models.temporal_gat.model import TemporalGAT, compute_loss  # noqa: E402


def _make_graph(graph_id: str, label: str, attack: bool) -> dict:
    """Minimal causal graph: intent -> call -> obs -> call2, plus anomaly node."""
    nodes = [
        {"node_id": "intent_1", "node_type": "intent", "timestamp": 100.0,
         "session_id": "s1", "task_type": "email_summary", "user_id": "u1"},
        {"node_id": "call_1", "node_type": "tool_call", "timestamp": 101.0,
         "session_id": "s1", "tool_name": "read_email", "parameters": {},
         "source": "user", "auth_level": 0.8, "authorized": True},
        {"node_id": "obs_1", "node_type": "observation", "timestamp": 102.0,
         "session_id": "s1", "data_source": "email", "trust_label": "low",
         "trust_score": 0.3, "content_hash": "abc", "content_preview": "x"},
        {"node_id": "call_2", "node_type": "tool_call", "timestamp": 103.0,
         "session_id": "s1", "tool_name": "send_email", "parameters": {},
         "source": "observation" if attack else "user", "auth_level": 0.5,
         "authorized": True},
    ]
    edges = [
        {"edge_id": "e1", "source": "intent_1", "target": "call_1",
         "type": "intent_drives", "weight": 1.0},
        {"edge_id": "e2", "source": "call_1", "target": "obs_1",
         "type": "data_derivation", "weight": 0.8},
        {"edge_id": "e3", "source": "obs_1", "target": "call_2",
         "type": "control_influence" if attack else "data_dependency",
         "weight": 0.9 if attack else 0.3},
    ]
    return {
        "graph_id": graph_id,
        "session_id": "s1",
        "nodes": nodes,
        "edges": edges,
        "label": label,
        "attack_type": "IPI" if attack else None,
        "ground_truth_anomaly_nodes": ["call_2"] if attack else [],
    }


class TestGraphToTensors(unittest.TestCase):
    def setUp(self):
        self.tool_vocab = ["read_email", "send_email"]
        self.task_vocab = ["email_summary"]

    def test_shapes_and_labels(self):
        result = graph_to_tensors(_make_graph("g1", "attack", True),
                                  self.tool_vocab, self.task_vocab)
        feat_dim = BASE_FEATURE_DIM + 2 + 1
        self.assertEqual(result["node_feat"].shape, (4, feat_dim))
        self.assertEqual(result["edge_index"].shape, (2, 3))
        self.assertEqual(result["edge_type"].shape, (3,))
        self.assertEqual(result["graph_label"].item(), 1.0)
        self.assertEqual(result["node_label"].sum().item(), 1.0)
        self.assertEqual(result["node_label"][3].item(), 1.0)  # call_2 is anomaly

    def test_normal_graph_label_zero(self):
        result = graph_to_tensors(_make_graph("g2", "normal", False),
                                  self.tool_vocab, self.task_vocab)
        self.assertEqual(result["graph_label"].item(), 0.0)
        self.assertEqual(result["node_label"].sum().item(), 0.0)

    def test_control_weight_feature(self):
        attack = graph_to_tensors(_make_graph("g3", "attack", True),
                                  self.tool_vocab, self.task_vocab)
        normal = graph_to_tensors(_make_graph("g4", "normal", False),
                                  self.tool_vocab, self.task_vocab)
        # feature 19 = max incoming control_influence weight
        self.assertGreater(attack["node_feat"][3, 19].item(),
                           normal["node_feat"][3, 19].item())

    def test_empty_edges(self):
        graph = _make_graph("g5", "normal", False)
        graph["edges"] = []
        result = graph_to_tensors(graph, self.tool_vocab, self.task_vocab)
        self.assertEqual(result["edge_index"].shape, (2, 0))

    def test_missing_edge_endpoint_ignored(self):
        graph = _make_graph("g6", "normal", False)
        graph["edges"].append({"edge_id": "e9", "source": "ghost", "target": "call_1",
                               "type": "control_influence", "weight": 0.5})
        result = graph_to_tensors(graph, self.tool_vocab, self.task_vocab)
        self.assertEqual(result["edge_index"].shape, (2, 3))


class TestCollateAndModel(unittest.TestCase):
    def _batch(self):
        graphs = [
            _make_graph("g1", "attack", True),
            _make_graph("g2", "normal", False),
        ]
        tool_vocab = ["read_email", "send_email"]
        task_vocab = ["email_summary"]
        samples = [graph_to_tensors(g, tool_vocab, task_vocab) for g in graphs]
        return collate_graphs(samples)

    def test_collate_offsets(self):
        batch = self._batch()
        self.assertEqual(batch["num_graphs"], 2)
        self.assertEqual(batch["node_feat"].shape[0], 8)
        # second graph edges offset by 4
        max_index = batch["edge_index"].max().item()
        self.assertLessEqual(max_index, 7)
        self.assertEqual(len(batch["node_slices"]), 2)
        self.assertEqual(batch["node_slices"][1][0].item(), 4)

    def test_model_forward_and_backward(self):
        batch = self._batch()
        model = TemporalGAT(feature_dim=batch["node_feat"].shape[1],
                            hidden_dim=32, num_layers=2)
        outputs = model(batch)
        self.assertEqual(outputs["graph_logits"].shape, (2,))
        self.assertEqual(outputs["node_logits"].shape, (8,))
        self.assertTrue((outputs["graph_prob"] >= 0).all())
        self.assertTrue((outputs["graph_prob"] <= 1).all())

        loss = compute_loss(outputs, batch)
        self.assertTrue(torch.isfinite(loss).item())
        loss.backward()  # gradients must flow

    def test_dataset_filters_unlabeled(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            for i, (label, attack) in enumerate([("normal", False), ("attack", True), (None, False)]):
                graph = _make_graph(f"g{i}", label, attack)
                if label is None:
                    graph.pop("label")
                with open(Path(tmp) / f"g{i}.json", "w", encoding="utf-8") as fh:
                    json.dump(graph, fh)
            dataset = CausalGraphDataset(list(Path(tmp).glob("*.json")))
            self.assertEqual(len(dataset), 2)


if __name__ == "__main__":
    unittest.main()
