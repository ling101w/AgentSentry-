"""Dataset: load CausalGraph JSON files into model-ready tensors.

Node features are fully structural (trust, sensitivity, control weight,
tool/task/entity vocabularies) - no text embeddings required, so the
pipeline runs on CPU with numpy + torch only.

Feature vector layout (dim = 24 + tool_vocab + task_vocab):
  [0:4]   node type one-hot            (intent / tool_call / observation / entity)
  [4]     trust_score                  (observation only, else 0)
  [5]     sensitivity_score            (entity only, else 0)
  [6]     auth_level                   (tool_call only, else 0)
  [7]     authorized flag              (tool_call only, else 0)
  [8]     source == user flag
  [9]     source == observation flag
  [10]    source == system flag
  [11:15] trust label one-hot          (high/medium/low/untrusted)
  [15]    normalized time offset       (node ts - graph min ts) / span
  [16]    in-degree / 8                (clipped)
  [17]    out-degree / 8               (clipped)
  [18:20] sum/max incoming control_influence weight
  [20:21] sum incoming data_dependency weight
  [21:23] min/mean outgoing control_influence weight
  [23]    has metadata flag
  [24:]   tool_name one-hot            (tool_call only, vocab from train set)
  [... ]  task_type one-hot            (intent only, vocab from train set)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch

NODE_TYPES = ("intent", "tool_call", "observation", "entity")
EDGE_TYPES = (
    "intent_drives",
    "control_influence",
    "data_dependency",
    "call_sequence",
    "data_derivation",
)
TRUST_LABELS = ("high", "medium", "low", "untrusted")
BASE_FEATURE_DIM = 24


def load_graph_files(paths: List[Path]) -> List[Dict[str, Any]]:
    """Load raw CausalGraph JSON dicts from disk."""
    graphs = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            graphs.append(json.load(fh))
    return graphs


def build_vocabularies(graphs: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """Collect sorted tool_name / task_type vocabularies from a graph list.

    Appends an <<OOV>> sentinel as a fallback bucket for unseen tokens at
    inference time so that real-world tools not in the training vocabulary
    are not mapped to an all-zero feature (which caused the model to default
    to "normal" on WSL data — a known distributional collapse).
    """
    tools = sorted({
        n.get("tool_name", "")
        for g in graphs
        for n in g["nodes"]
        if n["node_type"] == "tool_call" and n.get("tool_name")
    })
    tasks = sorted({
        n.get("task_type", "")
        for g in graphs
        for n in g["nodes"]
        if n["node_type"] == "intent" and n.get("task_type")
    })
    tools.append("<<OOV>>")
    tasks.append("<<OOV>>")
    return tools, tasks


def _clip(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def graph_to_tensors(
    graph: Dict[str, Any],
    tool_vocab: List[str],
    task_vocab: List[str],
) -> Dict[str, Any]:
    """Convert one CausalGraph dict into tensors for the model.

    Returns dict with:
      node_feat    float (N, D)
      edge_index   long  (2, E)
      edge_type    long  (E,)   index into EDGE_TYPES
      edge_weight  float (E,)
      node_label   float (N,)   1 for ground-truth anomaly nodes
      graph_label  float        1 for attack graphs
      meta         dict with ids for explainability
    """
    nodes = graph["nodes"]
    edges = graph.get("edges", [])
    node_index = {n["node_id"]: i for i, n in enumerate(nodes)}
    n_nodes = len(nodes)

    tool_index = {t: i for i, t in enumerate(tool_vocab)}
    task_index = {t: i for i, t in enumerate(task_vocab)}
    feat_dim = BASE_FEATURE_DIM + len(tool_vocab) + len(task_vocab)

    timestamps = [float(n.get("timestamp", 0.0)) for n in nodes]
    t_min = min(timestamps) if timestamps else 0.0
    t_span = (max(timestamps) - t_min) or 1.0

    in_edges: Dict[int, List[Dict[str, Any]]] = {}
    out_edges: Dict[int, List[Dict[str, Any]]] = {}
    for e in edges:
        src = node_index.get(e["source"])
        dst = node_index.get(e["target"])
        if src is None or dst is None:
            continue
        in_edges.setdefault(dst, []).append(e)
        out_edges.setdefault(src, []).append(e)

    gt_anomaly = set(graph.get("ground_truth_anomaly_nodes") or [])
    graph_label = 1.0 if str(graph.get("label", "unknown")).lower() in {
        "attack", "malicious", "positive"
    } else 0.0

    feat = np.zeros((n_nodes, feat_dim), dtype=np.float32)
    node_label = np.zeros(n_nodes, dtype=np.float32)

    for i, node in enumerate(nodes):
        ntype = node["node_type"]
        row = feat[i]

        if ntype in NODE_TYPES:
            row[NODE_TYPES.index(ntype)] = 1.0

        trust_score = float(node.get("trust_score", 0.0) or 0.0)
        row[4] = _clip(trust_score)
        row[5] = _clip(float(node.get("sensitivity_score", 0.0) or 0.0))
        row[6] = _clip(float(node.get("auth_level", 0.0) or 0.0))
        row[7] = 1.0 if node.get("authorized", True) else 0.0

        source = str(node.get("source", "") or "").lower()
        if source == "user":
            row[8] = 1.0
        elif source == "observation":
            row[9] = 1.0
        elif source == "system":
            row[10] = 1.0

        trust_label = str(node.get("trust_label", "") or "").lower()
        if trust_label in TRUST_LABELS:
            row[11 + TRUST_LABELS.index(trust_label)] = 1.0

        row[15] = _clip((timestamps[i] - t_min) / t_span)

        row[16] = _clip(len(in_edges.get(i, [])) / 8.0)
        row[17] = _clip(len(out_edges.get(i, [])) / 8.0)

        inc_ctrl = [e.get("weight", 1.0) for e in in_edges.get(i, [])
                    if e["type"] == "control_influence"]
        if inc_ctrl:
            row[18] = _clip(sum(inc_ctrl))
            row[19] = _clip(max(inc_ctrl))
        inc_dep = [e.get("weight", 1.0) for e in in_edges.get(i, [])
                   if e["type"] == "data_dependency"]
        row[20] = _clip(sum(inc_dep))

        out_ctrl = [e.get("weight", 1.0) for e in out_edges.get(i, [])
                    if e["type"] == "control_influence"]
        if out_ctrl:
            row[21] = _clip(min(out_ctrl))
            row[22] = _clip(sum(out_ctrl) / len(out_ctrl))

        row[23] = 1.0 if node.get("metadata") else 0.0

        if ntype == "tool_call":
            t_name = node.get("tool_name", "<<OOV>>")
            t_idx = tool_index.get(t_name, tool_index.get("<<OOV>>", 0))
            row[BASE_FEATURE_DIM + t_idx] = 1.0
        elif ntype == "intent":
            k_name = node.get("task_type", "<<OOV>>")
            k_idx = task_index.get(k_name, task_index.get("<<OOV>>", 0))
            row[BASE_FEATURE_DIM + len(tool_vocab) + k_idx] = 1.0

        if node["node_id"] in gt_anomaly:
            node_label[i] = 1.0

    edge_src, edge_dst, edge_type, edge_weight = [], [], [], []
    for e in edges:
        src = node_index.get(e["source"])
        dst = node_index.get(e["target"])
        if src is None or dst is None:
            continue
        etype = e["type"] if e["type"] in EDGE_TYPES else "data_dependency"
        edge_src.append(src)
        edge_dst.append(dst)
        edge_type.append(EDGE_TYPES.index(etype))
        edge_weight.append(_clip(float(e.get("weight", 1.0))))

    if edge_src:
        edge_index = torch.tensor([edge_src, edge_dst], dtype=torch.long)
        edge_type_t = torch.tensor(edge_type, dtype=torch.long)
        edge_weight_t = torch.tensor(edge_weight, dtype=torch.float32)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        edge_type_t = torch.zeros((0,), dtype=torch.long)
        edge_weight_t = torch.zeros((0,), dtype=torch.float32)

    return {
        "node_feat": torch.from_numpy(feat),
        "edge_index": edge_index,
        "edge_type": edge_type_t,
        "edge_weight": edge_weight_t,
        "node_label": torch.from_numpy(node_label),
        "graph_label": torch.tensor(graph_label, dtype=torch.float32),
        "meta": {
            "graph_id": graph.get("graph_id", ""),
            "label": graph.get("label", "unknown"),
            "attack_type": graph.get("attack_type"),
            "node_ids": [n["node_id"] for n in nodes],
        },
    }


class CausalGraphDataset(torch.utils.data.Dataset):
    """PyTorch dataset over CausalGraph JSON files.

    Vocabularies (tool / task) are built from the full graph list so train
    and eval splits share one consistent feature space.
    """

    def __init__(self, graph_files: List[Path], skip_unlabeled: bool = True,
                 tool_vocab: Optional[List[str]] = None,
                 task_vocab: Optional[List[str]] = None):
        self.graph_files = list(graph_files)
        self.raw_graphs = load_graph_files(self.graph_files)
        if skip_unlabeled:
            self.raw_graphs = [
                g for g in self.raw_graphs
                if str(g.get("label", "")).lower() in {"normal", "attack"}
                or str(g.get("label", "")).lower() in {"malicious", "positive"}
            ]
        if tool_vocab is not None and task_vocab is not None:
            self.tool_vocab, self.task_vocab = list(tool_vocab), list(task_vocab)
        else:
            self.tool_vocab, self.task_vocab = build_vocabularies(self.raw_graphs)
        self.samples = [
            graph_to_tensors(g, self.tool_vocab, self.task_vocab)
            for g in self.raw_graphs
        ]

    @property
    def feature_dim(self) -> int:
        return BASE_FEATURE_DIM + len(self.tool_vocab) + len(self.task_vocab)

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        return self.samples[idx]


def collate_graphs(batch: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Batch multiple graphs into one disconnected big graph.

    Node/edge tensors are offset so graphs never share edges; graph-level
    labels and node slices are kept for loss computation.
    """
    node_feats, edge_indices, edge_types, edge_weights = [], [], [], []
    node_labels, graph_labels, node_slices, metas = [], [], [], []
    offset = 0
    for sample in batch:
        n = sample["node_feat"].shape[0]
        node_feats.append(sample["node_feat"])
        edge_indices.append(sample["edge_index"] + offset)
        edge_types.append(sample["edge_type"])
        edge_weights.append(sample["edge_weight"])
        node_labels.append(sample["node_label"])
        graph_labels.append(sample["graph_label"])
        node_slices.append(torch.arange(offset, offset + n))
        metas.append(sample["meta"])
        offset += n

    return {
        "node_feat": torch.cat(node_feats, dim=0),
        "edge_index": torch.cat(edge_indices, dim=1) if edge_indices else torch.zeros((2, 0), dtype=torch.long),
        "edge_type": torch.cat(edge_types) if edge_types else torch.zeros((0,), dtype=torch.long),
        "edge_weight": torch.cat(edge_weights) if edge_weights else torch.zeros((0,), dtype=torch.float32),
        "node_label": torch.cat(node_labels),
        "graph_label": torch.stack(graph_labels),
        "node_slices": node_slices,
        "meta": metas,
        "num_graphs": len(batch),
    }
