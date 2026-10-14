"""Training / evaluation entry point for TemporalGAT.

Usage (from xuanjian-2.0 project root):
    python -m models.temporal_gat.train --data data/synthetic --epochs 60
    python -m models.temporal_gat.train --data data/synthetic --eval-only --checkpoint checkpoints/best_model.pth

Stratified split by graph label (normal/attack). Metrics: Acc / Precision /
Recall / F1 / AUC at both graph level and node level.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader, Subset

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.temporal_gat.dataset import (  # noqa: E402
    CausalGraphDataset,
    collate_graphs,
)
from models.temporal_gat.model import TemporalGAT, compute_loss  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train TemporalGAT on causal graphs")
    parser.add_argument("--data", type=str, default="data/synthetic",
                        help="Directory containing CausalGraph JSON files")
    parser.add_argument("--output", type=str, default="checkpoints")
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--num-layers", type=int, default=3)
    parser.add_argument("--lr", type=float, default=2e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--train-ratio", type=float, default=0.7)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--eval-only", action="store_true")
    parser.add_argument("--checkpoint", type=str, default=None)
    return parser.parse_args()


def stratified_split(dataset: CausalGraphDataset, train_ratio: float, val_ratio: float, seed: int):
    labels = [s["meta"]["label"] for s in dataset.samples]
    by_label = {}
    for idx, label in enumerate(labels):
        by_label.setdefault(label, []).append(idx)

    rng = random.Random(seed)
    train_idx, val_idx, test_idx = [], [], []
    for label, indices in sorted(by_label.items()):
        rng.shuffle(indices)
        n = len(indices)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)
        train_idx.extend(indices[:n_train])
        val_idx.extend(indices[n_train:n_train + n_val])
        test_idx.extend(indices[n_train + n_val:])
    return sorted(train_idx), sorted(val_idx), sorted(test_idx)


def roc_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Rank-based AUC, no sklearn dependency."""
    y_true = np.asarray(y_true, dtype=np.float64)
    y_score = np.asarray(y_score, dtype=np.float64)
    if len(np.unique(y_true)) < 2:
        return float("nan")
    order = np.argsort(y_score)
    ranks = np.empty_like(order, dtype=np.float64)
    ranks[order] = np.arange(1, len(y_score) + 1)
    # average ranks for ties
    sorted_scores = y_score[order]
    i = 0
    while i < len(sorted_scores):
        j = i
        while j + 1 < len(sorted_scores) and sorted_scores[j + 1] == sorted_scores[i]:
            j += 1
        if j > i:
            avg = (i + j + 2) / 2.0
            ranks[order[i:j + 1]] = avg
        i = j + 1
    pos = y_true == 1
    n_pos = pos.sum()
    n_neg = (~pos).sum()
    return float((ranks[pos].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> dict:
    pred = (y_prob >= threshold).astype(int)
    y_true = y_true.astype(int)
    tp = int(((pred == 1) & (y_true == 1)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    tn = int(((pred == 0) & (y_true == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / max(len(y_true), 1)
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "auc": roc_auc(y_true, y_prob),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


@torch.no_grad()
def evaluate(model, loader, device) -> dict:
    model.eval()
    graph_probs, graph_labels = [], []
    node_probs, node_labels = [], []
    total_loss = 0.0
    n_batches = 0
    for batch in loader:
        batch = {k: (v.to(device) if torch.is_tensor(v) else v) for k, v in batch.items()}
        outputs = model(batch)
        loss = compute_loss(outputs, batch)
        total_loss += loss.item()
        n_batches += 1
        graph_probs.extend(outputs["graph_prob"].cpu().numpy().tolist())
        graph_labels.extend(batch["graph_label"].cpu().numpy().tolist())
        node_probs.extend(outputs["node_prob"].cpu().numpy().tolist())
        node_labels.extend(batch["node_label"].cpu().numpy().tolist())

    graph_probs = np.array(graph_probs)
    graph_labels = np.array(graph_labels)
    node_probs = np.array(node_probs)
    node_labels = np.array(node_labels)
    return {
        "loss": total_loss / max(n_batches, 1),
        "graph": binary_metrics(graph_labels, graph_probs),
        "node": binary_metrics(node_labels, node_probs),
    }


def main() -> None:
    args = parse_args()
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    random.seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    data_dir = PROJECT_ROOT / args.data
    graph_files = sorted(p for p in data_dir.glob("*.json") if not p.name.endswith("_meta.json"))
    if not graph_files:
        print(f"[ERROR] no graph JSON files under {data_dir}")
        sys.exit(1)
    print(f"[data] {len(graph_files)} graphs from {data_dir}")

    dataset = CausalGraphDataset(graph_files)
    print(f"[data] tool vocab: {len(dataset.tool_vocab)}, task vocab: {len(dataset.task_vocab)}, "
          f"feature dim: {dataset.feature_dim}")
    print(f"[data] label distribution: "
          f"{ {k: sum(1 for s in dataset.samples if s['meta']['label'] == k) for k in set(s['meta']['label'] for s in dataset.samples)} }")

    train_idx, val_idx, test_idx = stratified_split(dataset, args.train_ratio, args.val_ratio, args.seed)
    print(f"[split] train={len(train_idx)} val={len(val_idx)} test={len(test_idx)}")

    train_loader = DataLoader(Subset(dataset, train_idx), batch_size=args.batch_size,
                              shuffle=True, collate_fn=collate_graphs)
    val_loader = DataLoader(Subset(dataset, val_idx), batch_size=args.batch_size,
                            shuffle=False, collate_fn=collate_graphs)
    test_loader = DataLoader(Subset(dataset, test_idx), batch_size=args.batch_size,
                             shuffle=False, collate_fn=collate_graphs)

    model = TemporalGAT(
        feature_dim=dataset.feature_dim,
        hidden_dim=args.hidden_dim,
        num_layers=args.num_layers,
    ).to(device)
    print(f"[model] parameters: {sum(p.numel() for p in model.parameters()):,} on {device}")

    output_dir = PROJECT_ROOT / args.output
    output_dir.mkdir(parents=True, exist_ok=True)
    ckpt_path = Path(args.checkpoint) if args.checkpoint else output_dir / "best_model.pth"

    if args.eval_only:
        model.load_state_dict(torch.load(ckpt_path, map_location=device))
        metrics = evaluate(model, test_loader, device)
        print(json.dumps(metrics, indent=2, ensure_ascii=False))
        return

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs)

    best_val_f1 = -1.0
    history = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        train_loss = 0.0
        n_batches = 0
        for batch in train_loader:
            batch = {k: (v.to(device) if torch.is_tensor(v) else v) for k, v in batch.items()}
            optimizer.zero_grad()
            outputs = model(batch)
            loss = compute_loss(outputs, batch)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            optimizer.step()
            train_loss += loss.item()
            n_batches += 1
        scheduler.step()

        val_metrics = evaluate(model, val_loader, device)
        history.append({
            "epoch": epoch,
            "train_loss": train_loss / max(n_batches, 1),
            "val_loss": val_metrics["loss"],
            "val_graph_f1": val_metrics["graph"]["f1"],
            "val_graph_auc": val_metrics["graph"]["auc"],
        })
        marker = ""
        if val_metrics["graph"]["f1"] > best_val_f1:
            best_val_f1 = val_metrics["graph"]["f1"]
            torch.save(model.state_dict(), ckpt_path)
            marker = "  <- saved"
        if epoch % 5 == 0 or epoch == 1 or epoch == args.epochs:
            print(f"epoch {epoch:3d} | train_loss {history[-1]['train_loss']:.4f} "
                  f"| val_loss {val_metrics['loss']:.4f} "
                  f"| val graph F1 {val_metrics['graph']['f1']:.3f} "
                  f"| AUC {val_metrics['graph']['auc']:.3f}{marker}")

    print(f"\n[best] val graph F1 = {best_val_f1:.3f}, checkpoint -> {ckpt_path}")

    vocab_path = output_dir / "vocab.json"
    with open(vocab_path, "w", encoding="utf-8") as fh:
        json.dump({"tool_vocab": dataset.tool_vocab, "task_vocab": dataset.task_vocab},
                  fh, ensure_ascii=False, indent=2)
    print(f"[saved] vocab -> {vocab_path}")

    model.load_state_dict(torch.load(ckpt_path, map_location=device))
    test_metrics = evaluate(model, test_loader, device)
    print("\n===== test metrics =====")
    print(f"graph-level: acc={test_metrics['graph']['accuracy']:.3f} "
          f"P={test_metrics['graph']['precision']:.3f} R={test_metrics['graph']['recall']:.3f} "
          f"F1={test_metrics['graph']['f1']:.3f} AUC={test_metrics['graph']['auc']:.3f}")
    print(f"node-level:  acc={test_metrics['node']['accuracy']:.3f} "
          f"P={test_metrics['node']['precision']:.3f} R={test_metrics['node']['recall']:.3f} "
          f"F1={test_metrics['node']['f1']:.3f} AUC={test_metrics['node']['auc']:.3f}")

    results = {
        "best_val_graph_f1": best_val_f1,
        "test": test_metrics,
        "history": history,
        "config": vars(args),
    }
    results_path = output_dir / "training_results.json"
    with open(results_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    print(f"[saved] results -> {results_path}")


if __name__ == "__main__":
    main()
