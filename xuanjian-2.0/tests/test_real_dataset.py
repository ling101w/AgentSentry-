import unittest

from models.temporal_gat.train_real import best_f1_threshold, stratified_group_folds
from scripts.build_real_dataset import is_verified, tool_signature

import numpy as np


def graph(calls):
    nodes = [{"node_id": "intent_1", "node_type": "intent"}]
    nodes += [
        {"node_id": f"call_{i}", "node_type": "tool_call", "tool_name": name, "parameters": params}
        for i, (name, params) in enumerate(calls, start=1)
    ]
    return {"nodes": nodes, "edges": []}


class VerificationTests(unittest.TestCase):
    def test_candidate_and_ambiguous_records_are_rejected(self):
        self.assertFalse(is_verified({"trajectory_label": "attack", "annotation_notes": "CANDIDATE — verify"}))
        self.assertFalse(is_verified({"trajectory_label": "ambiguous", "annotation_notes": ""}))

    def test_replay_record_needs_injection_outcome(self):
        base = {"trajectory_label": "normal", "annotation_notes": "ok"}
        self.assertFalse(is_verified({**base, "injection_replay": {"injection_outcome": None}}))
        self.assertTrue(is_verified({**base, "injection_replay": {"injection_outcome": "refused"}}))
        self.assertTrue(is_verified({**base, "injection_replay": None}))


class SignatureTests(unittest.TestCase):
    def test_identical_calls_share_signature(self):
        a = graph([("write", {"path": "notes/standup.md", "content": "x"})])
        b = graph([("write", {"content": "x", "path": "notes/standup.md"})])
        self.assertEqual(tool_signature(a), tool_signature(b))

    def test_different_params_split_signature(self):
        a = graph([("read", {"path": "/root/xuanjian_replay/rp_1_note.txt"})])
        b = graph([("read", {"path": "/root/xuanjian_replay/rp_2_note.txt"})])
        self.assertNotEqual(tool_signature(a), tool_signature(b))


class FoldTests(unittest.TestCase):
    def rows(self):
        rows = [{"group_id": "dup", "label": "normal"} for _ in range(4)]
        rows += [{"group_id": f"n{i}", "label": "normal"} for i in range(6)]
        rows += [{"group_id": f"a{i}", "label": "attack"} for i in range(10)]
        return rows

    def test_groups_never_straddle_folds(self):
        rows = self.rows()
        folds = stratified_group_folds(rows, 5, seed=3)
        dup_folds = {f for f, fold in enumerate(folds) for i in fold if rows[i]["group_id"] == "dup"}
        self.assertEqual(len(dup_folds), 1)
        self.assertEqual(sorted(i for fold in folds for i in fold), list(range(len(rows))))

    def test_attacks_spread_across_folds(self):
        rows = self.rows()
        folds = stratified_group_folds(rows, 5, seed=3)
        self.assertTrue(all(sum(rows[i]["label"] == "attack" for i in fold) == 2 for fold in folds))

    def test_threshold_maximizes_f1(self):
        labels = np.array([0, 0, 1, 1])
        probs = np.array([0.1, 0.4, 0.35, 0.8])
        self.assertEqual(best_f1_threshold(labels, probs), 0.35)


if __name__ == "__main__":
    unittest.main()
