"""End-to-end detection: score graphs and produce Layer 2/3 explanations.

Single entry point that:
  1. Loads a trained TemporalGAT checkpoint + saved vocabularies
  2. Batches input graphs (JSONL or per-file JSON) and runs inference
  3. Emits a verdict + path ranking + control-influence back-trace for
     every graph
  4. Writes a JSON report to --output

Designed to replace ad-hoc infer.py + manual graph traversal when an
analyst wants a single artifact they can paste into a security ticket.

Usage (from xuanjian-2.0 project root):
    python -m models.temporal_gat.detect \
        --checkpoint checkpoints_v2/best_model.pth \
        --vocab checkpoints_v2/vocab.json \
        --input data/openclaw/wsl_sessions_scripted.jsonl \
        --output checkpoints_v2/wsl_detect_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Iterable, List

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
from models.temporal_gat.explain import explain_graph  # noqa: E402
from models.temporal_gat.model import TemporalGAT  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=str, required=True)
    parser.add_argument("--vocab", type=str, required=True,
                        help="Path to vocab.json saved alongside the checkpoint")
    parser.add_argument("--input", type=str, required=True,
                        help="JSONL file or directory of graph JSONs")
    parser.add_argument("--output", type=str, required=True)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--num-layers", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--risk-threshold", type=float, default=0.5)
    parser.add_argument("--latency", action="store_true",
                        help="Also emit per-batch timing into the report")
    return parser.parse_args()


def load_graph_dicts(input_path: Path) -> List[dict]:
    if input_path.suffix == ".jsonl":
        with open(input_path, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]
    return load_graph_files(sorted(input_path.glob("*.json")))


@torch.no_grad()
def main() -> None:
    args = parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    vocab_blob = json.loads(Path(args.vocab).read_text(encoding="utf-8"))
    tool_vocab = list(vocab_blob["tool_vocab"])
    task_vocab = list(vocab_blob["task_vocab"])
    feature_dim = BASE_FEATURE_DIM + len(tool_vocab) + len(task_vocab)
    print(f"[vocab] tools={len(tool_vocab)} tasks={len(task_vocab)} feature_dim={feature_dim}")

    model = TemporalGAT(
        feature_dim=feature_dim,
        hidden_dim=args.hidden_dim,
        num_layers=args.num_layers,
    ).to(device)
    state = torch.load(Path(args.checkpoint), map_location=device)
    model.load_state_dict(state)
    model.eval()

    graphs = load_graph_dicts(Path(args.input))
    print(f"[input] {len(graphs)} graphs from {args.input}")
    samples = [graph_to_tensors(g, tool_vocab, task_vocab) for g in graphs]

    reports: List[dict] = []
    batch_latencies_ms: List[float] = []

    for start in range(0, len(samples), args.batch_size):
        chunk = samples[start:start + args.batch_size]
        batch = collate_graphs(chunk)
        batch_dev = {k: (v.to(device) if torch.is_tensor(v) else v) for k, v in batch.items()}
        if args.latency:
            torch.cuda.synchronize() if device.type == "cuda" else None
            t0 = time.perf_counter()
        outputs = model(batch_dev)
        if args.latency:
            torch.cuda.synchronize() if device.type == "cuda" else None
            batch_latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        graph_probs = outputs["graph_prob"].cpu().tolist()
        node_probs = outputs["node_prob"].cpu().tolist()

        offset = 0
        for sample, meta, gprob in zip(chunk, batch["meta"], graph_probs):
            n = sample["node_feat"].shape[0]
            sample_node_probs = node_probs[offset:offset + n]
            offset += n
            # Rebuild a graph slice for explain() — we need the source dict
            source_graph = next(
                (g for g in graphs if g.get("graph_id") == meta["graph_id"]),
                {"graph_id": meta.get("graph_id"), "nodes": [], "edges": []},
            )
            explanation = explain_graph(
                source_graph,
                sample_node_probs,
                gprob,
                risk_threshold=args.risk_threshold,
            )
            explanation["label_in_file"] = meta.get("label", "unknown")
            explanation["attack_type_in_file"] = meta.get("attack_type")
            reports.append(explanation)

    flagged = sum(1 for r in reports if r["verdict"] == "flagged")
    print(f"\n[verdict] flagged={flagged}/{len(reports)}  "
          f"threshold={args.risk_threshold}")
    if batch_latencies_ms:
        per_graph = sum(batch_latencies_ms) / max(len(reports), 1)
        print(f"[latency] batches={len(batch_latencies_ms)} "
              f"total_ms={sum(batch_latencies_ms):.1f} "
              f"ms/graph={per_graph:.3f}")
    print("\n===== top-5 flagged (by graph_risk) =====")
    for r in sorted(reports, key=lambda x: x["graph_risk"], reverse=True)[:5]:
        top_node = r["top_nodes"][0] if r["top_nodes"] else {}
        trace_roots = [t.get("root", {}).get("node_id") for t in r["traces"] if t.get("root")]
        print(
            f"  risk={r['graph_risk']:.4f} {r['graph_id'][:48]:<48} "
            f"top_node={top_node.get('node_id')} traces_root={trace_roots}"
        )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "checkpoint": args.checkpoint,
        "vocab_size": {"tools": len(tool_vocab), "tasks": len(task_vocab)},
        "risk_threshold": args.risk_threshold,
        "input": args.input,
        "summary": {
            "total_graphs": len(reports),
            "flagged": flagged,
            "with_root_attribution": sum(
                1 for r in reports
                if any(t.get("root") for t in r["traces"])
            ),
        },
        "latency": (
            {
                "batches": len(batch_latencies_ms),
                "total_ms": round(sum(batch_latencies_ms), 3),
                "ms_per_graph": round(
                    sum(batch_latencies_ms) / max(len(reports), 1), 4
                ),
            }
            if batch_latencies_ms
            else None
        ),
        "reports": reports,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    print(f"\n[saved] {out_path}")


if __name__ == "__main__":
    main()
