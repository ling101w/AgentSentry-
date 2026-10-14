"""Temporal GAT model package for XuanJian 2.0."""

from .dataset import CausalGraphDataset, load_graph_files, graph_to_tensors, build_vocabularies
from .model import TemporalGAT, compute_loss
from .explain import explain_graph, layer2_paths, layer3_trace

__all__ = [
    "CausalGraphDataset",
    "load_graph_files",
    "graph_to_tensors",
    "build_vocabularies",
    "TemporalGAT",
    "compute_loss",
    "explain_graph",
    "layer2_paths",
    "layer3_trace",
]
