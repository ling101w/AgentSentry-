"""Benchmark CPU inference for the production-graph-v1 shadow router."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from statistics import mean, median

import numpy as np
import torch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.production_gat.dataset import load_production_rows, rows_to_samples
from models.production_gat.model import RelationGATRouter


def main() -> None:
    args = parse_args()
    checkpoint = torch.load(Path(args.checkpoint), map_location="cpu", weights_only=False)
    model = RelationGATRouter(hidden_dim=int(checkpoint.get("hidden_dim", 48)), layers=int(checkpoint.get("layers", 2)))
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    samples = rows_to_samples(load_production_rows(Path(args.input)))
    for _ in range(args.warmup):
        with torch.no_grad():
            model.forward_sample(samples[0])
    times = []
    with torch.no_grad():
        for sample in samples:
            started = time.perf_counter()
            model.forward_sample(sample)
            times.append((time.perf_counter() - started) * 1000.0)
    summary = {
        "schema_version": "production-gat-latency-v1",
        "device": "cpu",
        "rows": len(times),
        "model_parameters": sum(parameter.numel() for parameter in model.parameters()),
        "warmup": args.warmup,
        "latency_ms": {
            "mean": mean(times),
            "median": median(times),
            "p95": float(np.percentile(times, 95)),
            "p99": float(np.percentile(times, 99)),
            "max": max(times),
        },
        "profile": {
            "nodes_mean": mean(sample.node_features.shape[0] for sample in samples),
            "edges_mean": mean(sample.edge_features.shape[0] for sample in samples),
            "nodes_max": max(sample.node_features.shape[0] for sample in samples),
            "edges_max": max(sample.edge_features.shape[0] for sample in samples),
        },
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--warmup", type=int, default=10)
    return parser.parse_args()


if __name__ == "__main__":
    main()
