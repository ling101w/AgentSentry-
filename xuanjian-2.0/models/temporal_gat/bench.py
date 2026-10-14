"""Inference latency benchmark for TemporalGAT.

Measures end-to-end latency on the full synthetic dataset: per-graph and
per-batch statistics, throughput, and a CSV per-graph breakdown.

Usage (from xuanjian-2.0 project root):
    python -m models.temporal_gat.bench \
        --checkpoint checkpoints_v2/best_model.pth \
        --vocab checkpoints_v2/vocab.json \
        --data data/synthetic_v2 \
        --output benchmarks/latency_v2.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from statistics import mean, median, stdev

import numpy as np
import torch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.temporal_gat.dataset import (  # noqa: E402
    BASE_FEATURE_DIM,
    build_vocabularies,
    collate_graphs,
    graph_to_tensors,
    load_graph_files,
)
from models.temporal_gat.model import TemporalGAT  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=str, required=True)
    parser.add_argument("--vocab", type=str, required=True)
    parser.add_argument("--data", type=str, required=True,
                        help="Directory of CausalGraph JSON files")
    parser.add_argument("--output", type=str, default="benchmarks/latency.csv",
                        help="CSV output path (created alongside a JSON summary)")
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--num-layers", type=int, default=3)
    parser.add_argument("--batch-sizes", type=str, default="1,4,8,16,32",
                        help="Comma-separated batch sizes to sweep")
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--runs", type=int, default=3,
                        help="Number of timing runs per batch size (median kept)")
    return parser.parse_args()


def load_graphs(data_dir: Path) -> list:
    files = sorted(
        p for p in data_dir.glob("*.json")
        if not p.name.endswith("_meta.json")
    )
    return load_graph_files(files)


@torch.no_grad()
def time_batch(
    model: TemporalGAT,
    batch: dict,
    device: torch.device,
    runs: int,
    warmup: int,
) -> list[float]:
    for _ in range(warmup):
        _ = model({k: (v.to(device) if torch.is_tensor(v) else v) for k, v in batch.items()})
    times = []
    for _ in range(runs):
        if device.type == "cuda":
            torch.cuda.synchronize()
        t0 = time.perf_counter()
        _ = model({k: (v.to(device) if torch.is_tensor(v) else v) for k, v in batch.items()})
        if device.type == "cuda":
            torch.cuda.synchronize()
        times.append((time.perf_counter() - t0) * 1000.0)
    return times


def main() -> None:
    args = parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    batch_sizes = [int(x) for x in args.batch_sizes.split(",")]

    vocab_blob = json.loads(Path(args.vocab).read_text(encoding="utf-8"))
    tool_vocab = list(vocab_blob["tool_vocab"])
    task_vocab = list(vocab_blob["task_vocab"])
    feature_dim = BASE_FEATURE_DIM + len(tool_vocab) + len(task_vocab)

    model = TemporalGAT(
        feature_dim=feature_dim,
        hidden_dim=args.hidden_dim,
        num_layers=args.num_layers,
    ).to(device)
    state = torch.load(Path(args.checkpoint), map_location=device)
    model.load_state_dict(state)
    model.eval()

    data_dir = PROJECT_ROOT / args.data
    graphs = load_graphs(data_dir)
    print(f"[data] {len(graphs)} graphs from {data_dir} | device={device} | model params={sum(p.numel() for p in model.parameters()):,}")

    samples = [graph_to_tensors(g, tool_vocab, task_vocab) for g in graphs]
    node_counts = [s["node_feat"].shape[0] for s in samples]
    edge_counts = [s["edge_index"].shape[1] for s in samples]
    print(f"[profile] nodes/graph: mean={mean(node_counts):.1f} median={median(node_counts):.0f} "
          f"min={min(node_counts)} max={max(node_counts)}")
    print(f"[profile] edges/graph: mean={mean(edge_counts):.1f} median={median(edge_counts):.0f} "
          f"min={min(edge_counts)} max={max(edge_counts)}")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path = out_path.with_suffix(".json")

    rows: list[dict] = []
    sweep_results: dict[int, dict] = {}

    for bs in batch_sizes:
        print(f"\n[batch_size={bs}]")
        # Collect batches
        batches_meta: list[tuple] = []
        for start in range(0, len(samples), bs):
            chunk = samples[start:start + bs]
            batch = collate_graphs(chunk)
            sizes = [s["node_feat"].shape[0] for s in chunk]
            batches_meta.append((batch, sizes))

        batch_times: list[float] = []
        graph_times: list[float] = []
        for batch, sizes in batches_meta:
            times = time_batch(model, batch, device, args.runs, args.warmup)
            med_ms = median(times)
            batch_times.append(med_ms)
            for sz in sizes:
                graph_times.append(med_ms / len(sizes))

        # Per-batch stats
        avg_batch = mean(batch_times)
        med_batch = median(batch_times)
        std_batch = stdev(batch_times) if len(batch_times) > 1 else 0.0
        throughput = bs / (med_batch / 1000.0) if med_batch > 0 else 0.0

        # Per-graph stats
        avg_graph = mean(graph_times)
        med_graph = median(graph_times)
        std_graph = stdev(graph_times) if len(graph_times) > 1 else 0.0

        sweep_results[bs] = {
            "batch_size": bs,
            "num_batches": len(batch_times),
            "batch_ms_avg": round(avg_batch, 4),
            "batch_ms_med": round(med_batch, 4),
            "batch_ms_std": round(std_batch, 4),
            "batch_ms_p95": round(float(np.percentile(batch_times, 95)), 4),
            "batch_ms_p99": round(float(np.percentile(batch_times, 99)), 4),
            "graphs_per_sec": round(throughput, 1),
            "graph_ms_avg": round(avg_graph, 4),
            "graph_ms_med": round(med_graph, 4),
            "graph_ms_std": round(std_graph, 4),
        }
        print(f"  batch  : avg={avg_batch:.3f}ms  med={med_batch:.3f}ms  p95={sweep_results[bs]['batch_ms_p95']:.3f}ms  std={std_batch:.3f}ms")
        print(f"  graph  : avg={avg_graph:.4f}ms  med={med_graph:.4f}ms  p95={float(np.percentile(graph_times, 95)):.4f}ms  graphs/s={throughput:.1f}")

        for i, (batch, sizes) in enumerate(batches_meta):
            rows.append({
                "batch_size": bs,
                "batch_index": i,
                "batch_ms": round(median(batch_times), 4),
                "num_graphs_in_batch": len(sizes),
                "total_nodes": sum(sizes),
                "total_edges": batch["edge_index"].shape[1],
            })

    # Write CSV
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n[csv] {out_path}")

    summary = {
        "device": str(device),
        "model_params": sum(p.numel() for p in model.parameters()),
        "hidden_dim": args.hidden_dim,
        "num_layers": args.num_layers,
        "checkpoint": args.checkpoint,
        "data_dir": str(data_dir),
        "num_graphs": len(graphs),
        "profile": {
            "nodes_per_graph": {
                "mean": round(mean(node_counts), 2),
                "median": round(median(node_counts), 1),
                "min": min(node_counts),
                "max": max(node_counts),
            },
            "edges_per_graph": {
                "mean": round(mean(edge_counts), 2),
                "median": round(median(edge_counts), 1),
                "min": min(edge_counts),
                "max": max(edge_counts),
            },
        },
        "sweep": sweep_results,
        "recommendation": (
            "small-batch" if (
                sweep_results.get(1, {}).get("graph_ms_avg", 999)
                < sweep_results.get(32, {}).get("graph_ms_avg", 0)
            ) else "large-batch"
        ),
    }
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    print(f"[summary] {summary_path}")

    print("\n===== sweep summary =====")
    print(f"{'bs':>4} {'batch_ms_med':>12} {'graph_ms_med':>12} {'graphs/s':>10}")
    print("-" * 42)
    for bs in batch_sizes:
        r = sweep_results[bs]
        print(f"{bs:>4} {r['batch_ms_med']:>12.4f} {r['graph_ms_med']:>12.4f} {r['graphs_per_sec']:>10.1f}")


if __name__ == "__main__":
    main()
