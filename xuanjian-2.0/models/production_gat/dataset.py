"""Tensorization for the label-free AgentSentry production-graph-v1 contract."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence

import torch

NODE_KINDS = ("intent", "capability", "action", "data", "sink")
TOOL_FAMILIES = ("read", "write", "network", "delivery", "execution", "memory", "agent", "other", "none")
AUTH_STATES = ("authorized", "unauthorized", "unknown")
SINK_EFFECTS = ("external", "persistent", "execution", "sensitive_read", "write", "unknown", "none")
SOURCE_CLASSES = ("user", "system", "workspace", "tool_result", "external", "memory", "webhook", "agent", "unknown", "none")
CONFIDENTIALITY = ("public", "internal", "secret", "none")
INTEGRITY = ("trusted", "untrusted", "tainted", "none")
EDGE_KINDS = ("declares", "governs", "authorizes", "constrains", "requests", "consumes", "produces", "derives", "targets")
EDGE_BASES = ("observed", "decoded", "conservative")
MATCH_KINDS = ("exact", "encoded_exact", "substring", "encoded_substring", "fuzzy", "encoded_fuzzy", "semantic", "none", "other")
FEATURE_DIM = 5 + 9 + 3 + 7 + 10 + 4 + 4 + 16
EDGE_FEATURE_DIM = 9 + 3 + 9 + 3
FORBIDDEN_INPUT_KEYS = {
    "decision", "status", "verdict", "risk", "risk_score", "sentry_score",
    "score", "label", "findings", "violations", "judge", "judge_output",
    "recommended_action", "attack_paths", "path_verdict",
}


@dataclass
class ProductionGraphSample:
    node_features: torch.Tensor
    edge_index: torch.Tensor
    edge_features: torch.Tensor
    graph_label: float
    sample_id: str
    session_key: str
    run_id: str
    metadata: Dict[str, Any]


def load_production_rows(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc
            validate_row(row, path, line_number)
            rows.append(row)
    if not rows:
        raise ValueError(f"no graph rows found in {path}")
    return rows


def validate_row(row: Dict[str, Any], path: Path | str = "row", line_number: int = 0) -> None:
    if not isinstance(row, dict) or not isinstance(row.get("input"), dict):
        raise ValueError(f"{path}:{line_number}: missing input envelope")
    graph = row["input"].get("graph")
    if row["input"].get("schema_version") != "production-graph-v1" or not isinstance(graph, dict):
        raise ValueError(f"{path}:{line_number}: unsupported graph schema")
    assert_label_free(row["input"])
    if not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        raise ValueError(f"{path}:{line_number}: malformed graph")
    if graph.get("directed") is not True or not graph["nodes"]:
        raise ValueError(f"{path}:{line_number}: graph must be directed and non-empty")
    if len(graph["nodes"]) > 40 or len(graph["edges"]) > 40:
        raise ValueError(f"{path}:{line_number}: graph projection exceeds limits")
    label = row.get("label")
    if not isinstance(label, dict) or label.get("source") != "policy_weak_label":
        raise ValueError(f"{path}:{line_number}: missing weak-label envelope")


def rows_to_samples(rows: Sequence[Dict[str, Any]]) -> List[ProductionGraphSample]:
    return [row_to_sample(row) for row in rows]


def row_to_sample(row: Dict[str, Any]) -> ProductionGraphSample:
    validate_row(row)
    graph = row["input"]["graph"]
    nodes = graph["nodes"]
    node_index = {node["id"]: index for index, node in enumerate(nodes)}
    node_features = torch.tensor([node_features_for(node) for node in nodes], dtype=torch.float32)
    edge_rows: List[List[float]] = []
    edge_pairs: List[List[int]] = []
    for edge in graph["edges"]:
        if edge["source"] not in node_index or edge["target"] not in node_index:
            continue
        edge_pairs.append([node_index[edge["source"]], node_index[edge["target"]]])
        edge_rows.append(edge_features_for(edge))
    edge_index = torch.tensor(edge_pairs, dtype=torch.long).t().contiguous() if edge_pairs else torch.zeros((2, 0), dtype=torch.long)
    edge_features = torch.tensor(edge_rows, dtype=torch.float32) if edge_rows else torch.zeros((0, EDGE_FEATURE_DIM), dtype=torch.float32)
    outcome = str(row["label"].get("policy_outcome", "allow"))
    label = 0.0 if outcome == "allow" else 1.0
    metadata = dict(row.get("metadata") or {})
    metadata.update({"policy_outcome": outcome, "deterministic_block": bool(row["label"].get("deterministic_block", False))})
    return ProductionGraphSample(
        node_features=node_features,
        edge_index=edge_index,
        edge_features=edge_features,
        graph_label=label,
        sample_id=str(metadata.get("sample_id", "")),
        session_key=str(metadata.get("session_key", "")),
        run_id=str(metadata.get("run_id", "")),
        metadata=metadata,
    )


class ProductionGraphDataset(torch.utils.data.Dataset):
    def __init__(self, rows_or_samples: Sequence[Dict[str, Any] | ProductionGraphSample]):
        self.samples = [item if isinstance(item, ProductionGraphSample) else row_to_sample(item) for item in rows_or_samples]

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, index: int) -> ProductionGraphSample:
        return self.samples[index]


def node_features_for(node: Dict[str, Any]) -> List[float]:
    output: List[float] = []
    output.extend(one_hot(node.get("kind"), NODE_KINDS))
    output.extend(one_hot(node.get("tool_family"), TOOL_FAMILIES))
    output.extend(one_hot(node.get("auth_state"), AUTH_STATES))
    output.extend(one_hot(node.get("sink_effect"), SINK_EFFECTS))
    output.extend(one_hot(node.get("source_class"), SOURCE_CLASSES))
    output.extend(one_hot(node.get("confidentiality"), CONFIDENTIALITY))
    output.extend(one_hot(node.get("integrity"), INTEGRITY))
    output.extend([
        clip(float(node.get("sequence_offset", 0)) / 100.0),
        clip(float(node.get("in_degree", 0)) / 16.0),
        clip(float(node.get("out_degree", 0)) / 16.0),
        1.0 if node.get("current_action") else 0.0,
        1.0 if node.get("active_intent") else 0.0,
        1.0 if node.get("active_capability") else 0.0,
        clip(float(node.get("tool_bucket", 0)) / 255.0),
        clip(float(node.get("transformation_count", 0)) / 32.0),
        1.0 if node.get("opaque_transform") else 0.0,
        hash_float(node.get("capability_action", "none")),
        hash_float(node.get("capability_resource", "none")),
        hash_float(node.get("capability_effect", "none")),
        1.0 if node.get("kind") == "action" else 0.0,
        1.0 if node.get("kind") == "data" else 0.0,
        1.0 if node.get("kind") == "sink" else 0.0,
        1.0 if node.get("kind") == "capability" else 0.0,
    ])
    if len(output) != FEATURE_DIM:
        raise ValueError(f"unexpected node feature dimension {len(output)} != {FEATURE_DIM}")
    return output


def edge_features_for(edge: Dict[str, Any]) -> List[float]:
    output = one_hot(edge.get("kind"), EDGE_KINDS)
    output.extend(one_hot(edge.get("basis"), EDGE_BASES))
    output.extend(one_hot(edge.get("match_kind"), MATCH_KINDS))
    output.extend([
        clip(float(edge.get("confidence", 0.0))),
        1.0 if edge.get("argument_binding") else 0.0,
        clip(float(edge.get("sequence_offset", 0)) / 100.0),
    ])
    if len(output) != EDGE_FEATURE_DIM:
        raise ValueError(f"unexpected edge feature dimension {len(output)} != {EDGE_FEATURE_DIM}")
    return output


def sample_signature(sample: ProductionGraphSample) -> torch.Tensor:
    """Return label-free graph statistics used for conservative OOD gating."""
    node_mean = sample.node_features.mean(dim=0)
    if sample.edge_features.shape[0]:
        edge_mean = sample.edge_features.mean(dim=0)
    else:
        edge_mean = torch.zeros(EDGE_FEATURE_DIM, dtype=torch.float32)
    structural = torch.tensor([
        min(float(sample.node_features.shape[0]), 40.0) / 40.0,
        min(float(sample.edge_features.shape[0]), 40.0) / 40.0,
        min(float(sample.edge_features.shape[1]), 24.0) / 24.0,
    ], dtype=torch.float32)
    return torch.cat([node_mean, edge_mean, structural])


def fit_ood_profile(samples: Sequence[ProductionGraphSample]) -> Dict[str, List[float]]:
    if not samples:
        raise ValueError("cannot fit an OOD profile without samples")
    matrix = torch.stack([sample_signature(sample) for sample in samples])
    mean = matrix.mean(dim=0)
    std = matrix.std(dim=0, unbiased=False).clamp_min(0.05)
    return {"mean": mean.tolist(), "std": std.tolist()}


def ood_score(sample: ProductionGraphSample, profile: Dict[str, List[float]]) -> float:
    signature = sample_signature(sample)
    mean = torch.tensor(profile["mean"], dtype=torch.float32)
    std = torch.tensor(profile["std"], dtype=torch.float32).clamp_min(0.05)
    return float(torch.mean(torch.abs((signature - mean) / std)).item())


def assert_label_free(value: Any, path: str = "input") -> None:
    """Reject outcome/evaluator fields before tensorization."""
    if isinstance(value, list):
        for index, item in enumerate(value):
            assert_label_free(item, f"{path}[{index}]")
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        if str(key).lower() in FORBIDDEN_INPUT_KEYS:
            raise ValueError(f"label leakage field is forbidden at {path}.{key}")
        assert_label_free(item, f"{path}.{key}")


def one_hot(value: Any, vocabulary: Sequence[str]) -> List[float]:
    return [1.0 if value == item else 0.0 for item in vocabulary]


def hash_float(value: Any) -> float:
    digest = hashlib.sha256(str(value).encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") / 4_294_967_295.0


def clip(value: float, minimum: float = -1.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))
