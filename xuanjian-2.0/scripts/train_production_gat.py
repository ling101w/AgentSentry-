"""Train and calibrate the production-graph-v1 shadow router."""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import numpy as np
import torch
import torch.nn.functional as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.production_gat.dataset import FEATURE_DIM, ProductionGraphSample, fit_ood_profile, load_production_rows, ood_score, rows_to_samples
from models.production_gat.model import RelationGATRouter


def main() -> None:
    args = parse_args()
    seed_everything(args.seed)
    root = Path(__file__).resolve().parents[1]
    rows = load_production_rows((root / args.input).resolve() if not Path(args.input).is_absolute() else Path(args.input))
    samples = rows_to_samples(rows)
    splits = group_split(samples, args.train_ratio, args.val_ratio, args.seed)
    model = RelationGATRouter(hidden_dim=args.hidden_dim, layers=args.layers)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    train = [samples[index] for index in splits["train"]]
    val = [samples[index] for index in splits["val"]]
    test = [samples[index] for index in splits["test"]]
    for split_name, split_samples in (("train", train), ("val", val), ("test", test)):
        if not split_samples or len({sample.graph_label for sample in split_samples}) < 2:
            raise ValueError(f"{split_name} split must contain both weak-label classes")
    history = []
    best_state = None
    best_val = -1.0
    for epoch in range(1, args.epochs + 1):
        model.train()
        random.shuffle(train)
        losses = []
        for offset in range(0, len(train), args.batch_size):
            batch = train[offset:offset + args.batch_size]
            logits = model(batch)["graph_logits"]
            labels = torch.tensor([sample.graph_label for sample in batch], dtype=torch.float32)
            pos = labels.sum().clamp_min(1.0)
            neg = (labels.numel() - labels.sum()).clamp_min(1.0)
            loss = F.binary_cross_entropy_with_logits(logits, labels, pos_weight=(neg / pos).clamp_max(10.0))
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 2.0)
            optimizer.step()
            losses.append(float(loss.item()))
        val_scores = score(model, val)
        threshold = calibrate_threshold(val_scores["labels"], val_scores["probs"], args.recall_floor)
        val_metrics = binary_metrics(val_scores["labels"], val_scores["probs"], threshold)
        history.append({"epoch": epoch, "train_loss": float(np.mean(losses)), "threshold": threshold, "val": val_metrics})
        if val_metrics["f1"] > best_val:
            best_val = val_metrics["f1"]
            best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
    val_scores = score(model, val)
    threshold = calibrate_threshold(val_scores["labels"], val_scores["probs"], args.recall_floor)
    test_scores = score(model, test)
    ood_profile = fit_ood_profile(train)
    validation_ood = [ood_score(sample, ood_profile) for sample in val]
    test_ood = [ood_score(sample, ood_profile) for sample in test]
    ood_threshold = float(np.percentile(validation_ood, 95)) if validation_ood else 3.0
    output = {
        "schema_version": "production-gat-training-v1",
        "input": str(args.input),
        "seed": args.seed,
        "model": {"type": "relation_gat_router", "hidden_dim": args.hidden_dim, "layers": args.layers, "parameters": sum(parameter.numel() for parameter in model.parameters())},
        "dataset": {"rows": len(samples), "sessions": len(set(sample.session_key for sample in samples)), "splits": {key: len(value) for key, value in splits.items()}},
        "label_definition": "policy_outcome != allow; weak label only",
        "calibration": {
            "threshold": threshold,
            "recall_floor": args.recall_floor,
            "validation": binary_metrics(val_scores["labels"], val_scores["probs"], threshold),
            "ood_threshold": ood_threshold,
        },
        "test": binary_metrics(test_scores["labels"], test_scores["probs"], threshold),
        "ood": {
            "validation_p95": ood_threshold,
            "validation_max": max(validation_ood, default=0.0),
            "test_max": max(test_ood, default=0.0),
            "test_fallback_rate": sum(value > ood_threshold for value in test_ood) / max(len(test_ood), 1),
        },
        "history": history,
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    checkpoint_path = Path(args.checkpoint)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save({
        "state_dict": model.state_dict(),
        "threshold": threshold,
        "ood_threshold": ood_threshold,
        "ood_profile": ood_profile,
        "schema_version": "production-gat-checkpoint-v1",
        "feature_dim": FEATURE_DIM,
        "hidden_dim": args.hidden_dim,
        "layers": args.layers,
    }, checkpoint_path)
    print(json.dumps(output, indent=2, ensure_ascii=False))


def group_split(samples: Sequence[ProductionGraphSample], train_ratio: float, val_ratio: float, seed: int) -> Dict[str, List[int]]:
    groups: Dict[str, List[int]] = defaultdict(list)
    for index, sample in enumerate(samples):
        groups[sample.session_key or sample.run_id or sample.sample_id].append(index)
    group_items = list(groups.items())
    random.Random(seed).shuffle(group_items)
    positives = [key for key, indexes in group_items if any(samples[index].graph_label for index in indexes)]
    negatives = [key for key, indexes in group_items if not any(samples[index].graph_label for index in indexes)]
    rng = random.Random(seed + 1)
    rng.shuffle(positives)
    rng.shuffle(negatives)

    def split_keys(keys: List[str]) -> Tuple[List[str], List[str], List[str]]:
        if not keys:
            return [], [], []
        train_end = max(1, int(len(keys) * train_ratio)) if len(keys) > 2 else 1
        val_count = max(1, int(len(keys) * val_ratio)) if len(keys) > 2 else 0
        val_end = min(len(keys), train_end + val_count)
        if val_end >= len(keys) and len(keys) > 1:
            val_end = len(keys) - 1
        if train_end >= val_end and len(keys) > 2:
            train_end = max(1, val_end - 1)
        return keys[:train_end], keys[train_end:val_end], keys[val_end:]

    pos_split = split_keys(positives)
    neg_split = split_keys(negatives)
    split_keys_by_name = {
        "train": pos_split[0] + neg_split[0],
        "val": pos_split[1] + neg_split[1],
        "test": pos_split[2] + neg_split[2],
    }
    return {name: sorted(index for key in keys for index in groups[key]) for name, keys in split_keys_by_name.items()}


def score(model: RelationGATRouter, samples: Sequence[ProductionGraphSample]) -> Dict[str, np.ndarray]:
    model.eval()
    with torch.no_grad():
        probabilities = model(list(samples))["graph_prob"].cpu().numpy() if samples else np.array([])
    return {"labels": np.array([sample.graph_label for sample in samples], dtype=np.int64), "probs": probabilities}


def calibrate_threshold(labels: np.ndarray, probabilities: np.ndarray, recall_floor: float) -> float:
    candidates = sorted(set([0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9] + [float(value) for value in probabilities]))
    valid = [(threshold, binary_metrics(labels, probabilities, threshold)) for threshold in candidates]
    meeting = [item for item in valid if item[1]["recall"] >= recall_floor]
    pool = meeting or valid
    return max(pool, key=lambda item: (item[1]["f1"], -item[0]))[0]


def binary_metrics(labels: np.ndarray, probabilities: np.ndarray, threshold: float) -> Dict[str, float | int]:
    predictions = (probabilities >= threshold).astype(np.int64)
    tp = int(((predictions == 1) & (labels == 1)).sum())
    fp = int(((predictions == 1) & (labels == 0)).sum())
    fn = int(((predictions == 0) & (labels == 1)).sum())
    tn = int(((predictions == 0) & (labels == 0)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)
    return {"threshold": threshold, "precision": precision, "recall": recall, "f1": f1, "accuracy": (tp + tn) / max(len(labels), 1), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="../reports/graph-learning/production-graph-pilot-20260915.jsonl")
    parser.add_argument("--output", default="../reports/graph-learning/production-gat-training-20260916.json")
    parser.add_argument("--checkpoint", default="checkpoints/production_gat_router.pth")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--hidden-dim", type=int, default=48)
    parser.add_argument("--layers", type=int, default=2)
    parser.add_argument("--lr", type=float, default=2e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--train-ratio", type=float, default=0.7)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--recall-floor", type=float, default=0.95)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


if __name__ == "__main__":
    main()
