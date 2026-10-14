import json
import tempfile
import unittest
from pathlib import Path

import torch

from models.production_gat.dataset import FEATURE_DIM, EDGE_FEATURE_DIM, assert_label_free, fit_ood_profile, ood_score, row_to_sample
from models.production_gat.model import RelationGATRouter


def row(sample_id="s1", label="allow"):
    return {
        "input": {
            "schema_version": "production-graph-v1",
            "current_action": "n1",
            "context": {"task_mode": "new_task", "task_family": "read_only", "active_capability_count": 1},
            "graph": {
                "directed": True,
                "original_node_count": 2,
                "original_edge_count": 1,
                "projection_truncated": False,
                "nodes": [
                    {"id": "n0", "kind": "intent", "sequence_offset": -1, "in_degree": 0, "out_degree": 1, "current_action": False, "active_intent": True, "active_capability": False, "tool_family": "none", "tool_bucket": 0, "auth_state": "unknown", "sink_effect": "none", "source_class": "none", "confidentiality": "none", "integrity": "none", "transformation_count": 0, "opaque_transform": False, "capability_action": "none", "capability_resource": "none", "capability_effect": "none"},
                    {"id": "n1", "kind": "action", "sequence_offset": 0, "in_degree": 1, "out_degree": 0, "current_action": True, "active_intent": False, "active_capability": False, "tool_family": "read", "tool_bucket": 1, "auth_state": "authorized", "sink_effect": "none", "source_class": "none", "confidentiality": "none", "integrity": "none", "transformation_count": 0, "opaque_transform": False, "capability_action": "none", "capability_resource": "none", "capability_effect": "none"},
                ],
                "edges": [{"source": "n0", "target": "n1", "kind": "governs", "basis": "observed", "confidence": 1, "sequence_offset": 0, "argument_binding": False, "match_kind": "none"}],
            },
        },
        "label": {"source": "policy_weak_label", "policy_outcome": label, "deterministic_block": label == "block"},
        "metadata": {"sample_id": sample_id, "session_key": f"session-{sample_id}", "run_id": f"run-{sample_id}"},
    }


class ProductionGATTest(unittest.TestCase):
    def test_tensor_dimensions_and_ood_profile_are_label_free(self):
        sample = row_to_sample(row(label="block"))
        self.assertEqual(sample.node_features.shape[1], FEATURE_DIM)
        self.assertEqual(sample.edge_features.shape[1], EDGE_FEATURE_DIM)
        profile = fit_ood_profile([sample])
        self.assertGreaterEqual(ood_score(sample, profile), 0.0)
        self.assertNotIn("block", json.dumps({"node_features": sample.node_features.tolist(), "edge_features": sample.edge_features.tolist()}))

    def test_forward_and_backward(self):
        samples = [row_to_sample(row("a", "allow")), row_to_sample(row("b", "block"))]
        model = RelationGATRouter(hidden_dim=16, layers=2)
        outputs = model(samples)
        self.assertEqual(outputs["graph_logits"].shape, (2,))
        self.assertTrue(torch.isfinite(outputs["graph_logits"]).all())
        loss = torch.nn.functional.binary_cross_entropy_with_logits(outputs["graph_logits"], torch.tensor([0.0, 1.0]))
        loss.backward()

    def test_checkpoint_input_has_no_decision_fields(self):
        sample = row_to_sample(row(label="block"))
        serialized = json.dumps({"node_features": sample.node_features.tolist(), "edge_features": sample.edge_features.tolist()})
        self.assertNotIn("decision", serialized)
        self.assertNotIn("block", serialized)

    def test_rejects_label_fields_inside_input(self):
        value = row(label="block")
        value["input"]["graph"]["nodes"][0]["decision"] = "deny"
        with self.assertRaisesRegex(ValueError, "label leakage"):
            assert_label_free(value["input"])
        with self.assertRaisesRegex(ValueError, "label leakage"):
            row_to_sample(value)


if __name__ == "__main__":
    unittest.main()
