"""TemporalGAT: heterogeneous graph attention with edge-type awareness.

Design (per the implementation plan, stage 3):
  - one attention head per edge type (5 types), each with its own
    projection matrices, so intent_drives and control_influence are
    never forced to share parameters;
  - temporal encoding: the normalized time offset feature is expanded
    with sinusoidal bases before the first layer;
  - message passing over incoming edges: node h_v is updated with a
    weighted combination of per-type attended neighbor messages;
  - outputs: node-level anomaly logits + graph-level anomaly score via
    attention pooling (top-k style gated mean).

Pure PyTorch (no PyG dependency), works on batched disconnected graphs
produced by collate_graphs().
"""

from __future__ import annotations

import math

import torch
import torch.nn as nn
import torch.nn.functional as F

NUM_EDGE_TYPES = 5
TEMPORAL_BASIS = 8


class TemporalEncoder(nn.Module):
    """Expand scalar time offset (feat[15]) with sinusoidal bases."""

    def __init__(self, time_index: int = 15):
        super().__init__()
        self.time_index = time_index
        frequencies = torch.logspace(0, 3, TEMPORAL_BASIS // 2) / 100.0
        self.register_buffer("frequencies", frequencies)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        t = x[:, self.time_index : self.time_index + 1] * 10.0
        angles = t * self.frequencies.view(1, -1)
        enc = torch.cat([torch.sin(angles), torch.cos(angles)], dim=1)
        return torch.cat([x, enc], dim=1)


class EdgeTypeAttention(nn.Module):
    """Attention message passing restricted to one edge type."""

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.lin_src = nn.Linear(in_dim, out_dim, bias=False)
        self.lin_dst = nn.Linear(in_dim, out_dim, bias=False)
        self.lin_msg = nn.Linear(in_dim, out_dim, bias=False)
        self.attention = nn.Parameter(torch.empty(1, out_dim))
        nn.init.xavier_uniform_(self.attention)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_weight: torch.Tensor,
    ) -> torch.Tensor:
        """edge_index: (2, E) pointing src -> dst; aggregates at dst."""
        n_nodes = x.shape[0]
        out_dim = self.lin_msg.out_features
        if edge_index.shape[1] == 0:
            return torch.zeros(n_nodes, out_dim, device=x.device)

        src, dst = edge_index[0], edge_index[1]
        alpha_src = self.lin_src(x[src])
        alpha_dst = self.lin_dst(x[dst])
        scores = (alpha_src + alpha_dst) * self.attention
        scores = F.leaky_relu(scores, negative_slope=0.2).sum(dim=-1)
        scores = scores + (edge_weight - 0.5) * 2.0

        # segment softmax per destination node (numerically stable)
        dst_max = torch.full((n_nodes,), -1e9, device=x.device)
        dst_max.scatter_reduce_(0, dst, scores, reduce="amax", include_self=True)
        exp_scores = torch.exp(scores - dst_max[dst])
        dst_sum = torch.zeros(n_nodes, device=x.device)
        dst_sum.index_add_(0, dst, exp_scores)
        alpha = exp_scores / dst_sum[dst].clamp(min=1e-12)  # (E,)

        weighted = self.lin_msg(x[src]) * (edge_weight * alpha).unsqueeze(1)
        aggregated = torch.zeros(n_nodes, out_dim, device=x.device)
        aggregated.index_add_(0, dst, weighted)
        return aggregated


class TemporalGAT(nn.Module):
    """Heterogeneous temporal graph attention network for anomaly detection."""

    def __init__(self, feature_dim: int, hidden_dim: int = 64, num_layers: int = 3, dropout: float = 0.1):
        super().__init__()
        self.temporal = TemporalEncoder()
        in_dim = feature_dim + TEMPORAL_BASIS
        self.input_proj = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
        )

        self.edge_attentions = nn.ModuleList()
        self.edge_gates = nn.ParameterList()
        self.layer_norms = nn.ModuleList()
        for _ in range(num_layers):
            self.edge_attentions.append(
                nn.ModuleList([EdgeTypeAttention(hidden_dim, hidden_dim) for _ in range(NUM_EDGE_TYPES)])
            )
            # learned mixing weights over the 5 edge types
            self.edge_gates.append(nn.Parameter(torch.zeros(NUM_EDGE_TYPES)))
            self.layer_norms.append(nn.LayerNorm(hidden_dim))

        self.dropout = nn.Dropout(dropout)

        # node-level anomaly head
        self.node_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
        )
        # graph-level gating for attention pooling
        self.graph_gate = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
        )
        self.graph_head = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
        )

    def encode(self, node_feat, edge_index, edge_type, edge_weight) -> torch.Tensor:
        x = self.temporal(node_feat)
        h = self.input_proj(x)

        for layer in range(len(self.edge_attentions)):
            messages = []
            for etype in range(NUM_EDGE_TYPES):
                mask = edge_type == etype
                sub_index = edge_index[:, mask]
                sub_weight = edge_weight[mask]
                messages.append(self.edge_attentions[layer][etype](h, sub_index, sub_weight))
            gates = torch.softmax(self.edge_gates[layer], dim=0)
            aggregated = sum(gates[t] * messages[t] for t in range(NUM_EDGE_TYPES))
            h = self.layer_norms[layer](h + self.dropout(aggregated))

        return h

    def forward(self, batch: dict) -> dict:
        h = self.encode(batch["node_feat"], batch["edge_index"], batch["edge_type"], batch["edge_weight"])

        node_logits = self.node_head(h).squeeze(-1)  # (N,)

        # graph-level: gated attention pooling per graph
        gate_scores = self.graph_gate(h).squeeze(-1)
        graph_logits = []
        for nodes in batch["node_slices"]:
            hs = h[nodes]
            gs = gate_scores[nodes]
            weights = torch.softmax(gs, dim=0).unsqueeze(1)
            pooled = (hs * weights).sum(dim=0)
            pooled = torch.cat([pooled, hs.max(dim=0).values], dim=0)
            graph_logits.append(self.graph_head(pooled).squeeze(-1))
        graph_logits = torch.stack(graph_logits)  # (G,)

        return {
            "node_logits": node_logits,
            "graph_logits": graph_logits,
            "node_prob": torch.sigmoid(node_logits),
            "graph_prob": torch.sigmoid(graph_logits),
        }


def compute_loss(
    outputs: dict,
    batch: dict,
    alpha: float = 0.5,
    beta: float = 0.5,
) -> torch.Tensor:
    """Multi-task loss: node-level BCE + graph-level BCE."""
    node_logits = outputs["node_logits"]
    node_label = batch["node_label"]

    # weight positives higher: anomalies are rare
    num_pos = node_label.sum()
    num_neg = node_label.numel() - num_pos
    pos_weight = (num_neg / num_pos.clamp(min=1.0)).clamp(max=20.0) if num_pos > 0 else torch.tensor(1.0)

    node_loss = F.binary_cross_entropy_with_logits(
        node_logits, node_label, pos_weight=pos_weight
    )
    graph_loss = F.binary_cross_entropy_with_logits(
        outputs["graph_logits"], batch["graph_label"]
    )
    return alpha * node_loss + beta * graph_loss
