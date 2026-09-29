"""Small relation-aware GAT for production-graph-v1 shadow scoring."""

from __future__ import annotations

from typing import Sequence

import torch
import torch.nn as nn
import torch.nn.functional as F

from .dataset import EDGE_FEATURE_DIM, FEATURE_DIM, ProductionGraphSample


class RelationGATLayer(nn.Module):
    def __init__(self, hidden_dim: int, edge_dim: int):
        super().__init__()
        self.node_proj = nn.Linear(hidden_dim, hidden_dim, bias=False)
        self.edge_proj = nn.Linear(edge_dim, hidden_dim, bias=False)
        self.attention = nn.Linear(hidden_dim * 3, 1, bias=False)
        self.norm = nn.LayerNorm(hidden_dim)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_features: torch.Tensor) -> torch.Tensor:
        if edge_index.shape[1] == 0:
            return self.norm(x)
        src, dst = edge_index[0], edge_index[1]
        projected = self.node_proj(x)
        edge_context = self.edge_proj(edge_features)
        scores = self.attention(torch.cat([projected[src], projected[dst], edge_context], dim=1)).squeeze(1)
        alpha = segment_softmax(scores, dst, x.shape[0])
        messages = (projected[src] + edge_context) * alpha.unsqueeze(1)
        aggregated = torch.zeros_like(x)
        aggregated.index_add_(0, dst, messages)
        return self.norm(x + F.dropout(F.relu(aggregated), p=0.1, training=self.training))


class RelationGATRouter(nn.Module):
    def __init__(self, hidden_dim: int = 48, layers: int = 2):
        super().__init__()
        self.input = nn.Sequential(nn.Linear(FEATURE_DIM, hidden_dim), nn.LayerNorm(hidden_dim), nn.ReLU())
        self.layers = nn.ModuleList([RelationGATLayer(hidden_dim, EDGE_FEATURE_DIM) for _ in range(layers)])
        self.gate = nn.Linear(hidden_dim, 1)
        self.head = nn.Sequential(nn.Linear(hidden_dim * 2, hidden_dim), nn.ReLU(), nn.Dropout(0.1), nn.Linear(hidden_dim, 1))
        self.node_head = nn.Linear(hidden_dim, 1)

    def encode(self, sample: ProductionGraphSample) -> torch.Tensor:
        x = self.input(sample.node_features)
        for layer in self.layers:
            x = layer(x, sample.edge_index, sample.edge_features)
        return x

    def forward_sample(self, sample: ProductionGraphSample) -> dict:
        hidden = self.encode(sample)
        weights = torch.softmax(self.gate(hidden).squeeze(-1), dim=0).unsqueeze(1)
        pooled = (hidden * weights).sum(dim=0)
        pooled = torch.cat([pooled, hidden.max(dim=0).values], dim=0)
        graph_logit = self.head(pooled).squeeze()
        return {"graph_logit": graph_logit, "graph_prob": torch.sigmoid(graph_logit), "node_prob": torch.sigmoid(self.node_head(hidden).squeeze(-1))}

    def forward(self, samples: Sequence[ProductionGraphSample]) -> dict:
        outputs = [self.forward_sample(sample) for sample in samples]
        return {
            "graph_logits": torch.stack([output["graph_logit"] for output in outputs]),
            "graph_prob": torch.stack([output["graph_prob"] for output in outputs]),
            "node_prob": [output["node_prob"] for output in outputs],
        }


def segment_softmax(scores: torch.Tensor, groups: torch.Tensor, size: int) -> torch.Tensor:
    maxima = torch.full((size,), -torch.inf, device=scores.device)
    maxima.scatter_reduce_(0, groups, scores, reduce="amax", include_self=True)
    exp_scores = torch.exp(scores - maxima[groups])
    totals = torch.zeros(size, device=scores.device)
    totals.index_add_(0, groups, exp_scores)
    return exp_scores / totals[groups].clamp_min(1e-8)
