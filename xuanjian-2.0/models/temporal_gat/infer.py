"""Inference: score unlabeled causal graphs with a trained TemporalGAT.

Usage (from xuanjian-2.0 project root):
    python -m models.temporal_gat.infer \
        --checkpoint checkpoints_v2/best_model.pth \
        --train-data data/synthetic_v2 \
        --input data/openclaw/wsl_sessions_scripted.jsonl

Vocabularies (tool / task one-hot) are rebuilt from the training data so the
feature space matches the checkpoint. Input may be a JSONL file (one graph
per line) or a directory of graph JSON files. Output: per-graph risk score
and top anomalous nodes, printed and saved as JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.temporal_gat.dataset import (  # noqa: E402
    BASE_FEATURE_DIM,
    CausalGraphDataset,
    build_vocabularies,
    collate_graphs,
    graph_to_tensors,
    load_graph_files,
)
from models.temporal_gat.model import TemporalGAT  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score graphs with trained TemporalGAT")
    parser.add_argument("--checkpoint", type=str, required=True)
    parser.add_argument("--train-data", type=str, default="data/synthetic_v2",
                        help="Training graph directory (rebuilds feature vocabularies)")
    parser.add_argument("--input", type=str, required=True,
                        help="JSONL file or directory of graph JSONs to score")
    parser.add_argument("--output", type=str, default=None,
                        help="Optional path for JSON results")
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--num-layers", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=32)
    return parser.parse_args()


def load_input_graphs(input_path: Path) -> list:
    graphs = []
    if input_path.suffix == ".jsonl":
        with open(input_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    graphs.append(json.loads(line))
    else:
        files = sorted(p for p in input_path.glob("*.json") if not p.name.endswith("_meta.json"))
        graphs = load_graph_files(files)
    return graphs


@torch.no_grad()
def main() -> None:
    args = parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # 1. rebuild vocabularies from training data
    train_dir = PROJECT_ROOT / args.train_data
    train_files = sorted(p for p in train_dir.glob("*.json") if not p.name.endswith("_meta.json"))
    train_graphs = load_graph_files(train_files)
    tool_vocab, task_vocab = build_vocabularies(train_graphs)
    feature_dim = BASE_FEATURE_DIM + len(tool_vocab) + len(task_vocab)
    print(f"[vocab] tools={len(tool_vocab)} tasks={len(task_vocab)} feature_dim={feature_dim}")

    # 2. load model
    model = TemporalGAT(
        feature_dim=feature_dim,
        hidden_dim=args.hidden_dim,
        num_layers=args.num_layers,
    ).to(device)
    state = torch.load(PROJECT_ROOT / args.checkpoint, map_location=device)
    model.load_state_dict(state)
    model.eval()

    # 3. convert input graphs (no label filtering - these are unlabeled)
    graphs = load_input_graphs(PROJECT_ROOT / args.input)
    print(f"[input] {len(graphs)} graphs to score")
    samples = [graph_to_tensors(g, tool_vocab, task_vocab) for g in graphs]

    # 4. batch inference
    results = []
    for start in range(0, len(samples), args.batch_size):
        chunk = samples[start:start + args.batch_size]
        batch = collate_graphs(chunk)
        batch = {k: (v.to(device) if torch.is_tensor(v) else v) for k, v in batch.items()}
        outputs = model(batch)
        graph_probs = outputs["graph_prob"].cpu().tolist()
        node_probs = outputs["node_prob"].cpu().tolist()

        offset = 0
        for sample, meta, gprob in zip(chunk, batch["meta"], graph_probs):
            n = sample["node_feat"].shape[0]
            probs = node_probs[offset:offset + n]
            offset += n
            top = sorted(
                zip(meta["node_ids"], probs), key=lambda kv: kv[1], reverse=True
            )[:3]
            results.append({
                "graph_id": meta["graph_id"],
                "risk_score": round(gprob, 4),
                "label_in_file": meta.get("label", "unknown"),
                "attack_type_in_file": meta.get("attack_type"),
                "top_nodes": [{"node_id": nid, "prob": round(p, 4)} for nid, p in top],
            })

    # 5. report
    scores = [r["risk_score"] for r in results]
    flagged = [r for r in results if r["risk_score"] >= 0.5]
    print(f"\n[risk distribution] min={min(scores):.4f} max={max(scores):.4f} "
          f"mean={sum(scores)/len(scores):.4f} median={sorted(scores)[len(scores)//2]:.4f}")
    print(f"[flagged at 0.5] {len(flagged)}/{len(results)} graphs")

    results.sort(key=lambda r: r["risk_score"], reverse=True)
    print("\n===== top-10 highest risk =====")
    for r in results[:10]:
        top_str = ", ".join(f"{t['node_id']}={t['prob']:.2f}" for t in r["top_nodes"][:2])
        print(f"  {r['risk_score']:.4f}  {r['graph_id'][:48]:<48}  [{top_str}]")

    if args.output:
        out_path = PROJECT_ROOT / args.output
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        print(f"\n[saved] detailed results -> {out_path}")


if __name__ == "__main__":
    main()
