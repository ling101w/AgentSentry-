"""Grouped cross-validation of TemporalGAT on the real-session dataset.

The real set is ~100 graphs, so a single 70/15/15 split gives a test set of
a dozen graphs and metrics that swing with the seed. This script instead runs
stratified group k-fold (split key = `group_id` from build_real_dataset) and
reports pooled out-of-fold predictions, repeated over several seeds.

Per fold: test = fold k, val = fold k+1, train = the rest. The tool/task
vocabulary is fitted on the train fold only, the checkpoint is picked by val
AUC and the decision threshold is calibrated on val (max F1).

Two baselines run on the same folds so the GNN has to beat something:
* `size_only`    graph node count used directly as the score (no training)
* `bag_of_tools` logistic regression on per-tool call counts + size stats

Slices reported on pooled OOF predictions:
* `all`          every graph
* `replay_only`  replay sessions only: manifested attacks vs injected-but-
                 refused/no-effect sessions. Both come from the same replay
                 harness, so origin cannot be used as a shortcut here.

Usage (from xuanjian-2.0 project root):
    python -m models.temporal_gat.train_real --data data/real/real_graphs.v1.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Sequence

import numpy as np
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.temporal_gat.dataset import build_vocabularies, collate_graphs, graph_to_tensors  # noqa: E402
from models.temporal_gat.model import TemporalGAT, compute_loss  # noqa: E402
from models.temporal_gat.train import binary_metrics, roc_auc  # noqa: E402

MODELS = ("temporal_gat", "bag_of_tools", "size_only")
SLICES = ("all", "replay_only")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Grouped CV for TemporalGAT on real sessions")
    parser.add_argument("--data", type=str, default="data/real/real_graphs.v1.jsonl")
    parser.add_argument("--output", type=str, default="checkpoints_real")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seeds", type=int, nargs="+", default=[7, 17, 29])
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--num-layers", type=int, default=3)
    parser.add_argument("--lr", type=float, default=2e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    return parser.parse_args()


def load_rows(path: Path) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def is_attack(row: Dict[str, Any]) -> float:
    return 1.0 if row["label"] == "attack" else 0.0


def stratified_group_folds(rows: Sequence[Dict[str, Any]], k: int, seed: int) -> List[List[int]]:
    """Assign whole groups to folds, balancing attack groups and normal groups separately."""
    groups: Dict[str, List[int]] = defaultdict(list)
    for idx, row in enumerate(rows):
        groups[row["group_id"]].append(idx)
    rng = random.Random(seed)
    folds: List[List[int]] = [[] for _ in range(k)]
    for label in ("attack", "normal"):
        members = [g for g, idxs in groups.items() if rows[idxs[0]]["label"] == label]
        rng.shuffle(members)
        members.sort(key=lambda g: -len(groups[g]))  # stable: big clusters placed first
        counts = [0] * k
        for g in members:
            target = min(range(k), key=lambda f: (counts[f], rng.random()))
            folds[target].extend(groups[g])
            counts[target] += len(groups[g])
    return [sorted(f) for f in folds]


def best_f1_threshold(labels: np.ndarray, probs: np.ndarray) -> float:
    best_t, best_f1 = 0.5, -1.0
    for t in np.unique(probs):
        f1 = binary_metrics(labels, probs, float(t))["f1"]
        if f1 > best_f1:
            best_t, best_f1 = float(t), f1
    return best_t


@torch.no_grad()
def predict(model: TemporalGAT, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    model.eval()
    graph_probs, node_probs = [], []
    for offset in range(0, len(samples), 16):
        batch = collate_graphs(samples[offset:offset + 16])
        out = model(batch)
        graph_probs.extend(out["graph_prob"].tolist())
        for sl in batch["node_slices"]:
            node_probs.append(out["node_prob"][sl].tolist())
    return {"graph": np.array(graph_probs), "node": node_probs}


def train_gat(train_s, val_s, feature_dim: int, args, seed: int) -> TemporalGAT:
    torch.manual_seed(seed)
    model = TemporalGAT(feature_dim=feature_dim, hidden_dim=args.hidden_dim, num_layers=args.num_layers)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    loader = DataLoader(train_s, batch_size=args.batch_size, shuffle=True, collate_fn=collate_graphs,
                        generator=torch.Generator().manual_seed(seed))
    val_labels = np.array([float(s["graph_label"]) for s in val_s])
    best_auc, best_state = -1.0, None
    for _ in range(args.epochs):
        model.train()
        for batch in loader:
            optimizer.zero_grad()
            loss = compute_loss(model(batch), batch)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            optimizer.step()
        auc = roc_auc(val_labels, predict(model, val_s)["graph"])
        auc = -1.0 if np.isnan(auc) else auc
        if auc > best_auc:
            best_auc = auc
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
    model.load_state_dict(best_state)
    return model


def bag_features(rows: Sequence[Dict[str, Any]], tools: List[str]) -> torch.Tensor:
    index = {t: i for i, t in enumerate(tools)}
    feats = np.zeros((len(rows), len(tools) + 3), dtype=np.float32)
    for r, row in enumerate(rows):
        for node in row["nodes"]:
            if node["node_type"] == "tool_call":
                feats[r, index.get(node.get("tool_name"), index["<<OOV>>"])] += 1.0
        feats[r, -3] = len(row["nodes"])
        feats[r, -2] = len(row.get("edges", []))
        feats[r, -1] = sum(1 for e in row.get("edges", []) if e["type"] == "control_influence")
    return torch.from_numpy(np.log1p(feats))


def train_bag(train_rows, eval_sets, tools: List[str]) -> List[np.ndarray]:
    """L2 logistic regression; returns probabilities for each rows list in eval_sets."""
    x = bag_features(train_rows, tools)
    mu, sd = x.mean(0), x.std(0).clamp_min(1e-6)
    x = (x - mu) / sd
    y = torch.tensor([is_attack(r) for r in train_rows])
    w = torch.zeros(x.shape[1], requires_grad=True)
    b = torch.zeros(1, requires_grad=True)
    opt = torch.optim.LBFGS([w, b], max_iter=200)

    def closure():
        opt.zero_grad()
        loss = F.binary_cross_entropy_with_logits(x @ w + b, y) + 1e-2 * (w ** 2).sum()
        loss.backward()
        return loss

    opt.step(closure)
    with torch.no_grad():
        return [torch.sigmoid(((bag_features(rs, tools) - mu) / sd) @ w + b).numpy() for rs in eval_sets]


def run_seed(rows, args, seed: int) -> Dict[str, Any]:
    folds = stratified_group_folds(rows, args.folds, seed)
    n = len(rows)
    oof = {name: np.zeros(n) for name in MODELS}
    oof_pred = {name: np.zeros(n) for name in MODELS}
    node_hit3 = []
    for k in range(args.folds):
        v = (k + 1) % args.folds
        test_idx, val_idx = folds[k], folds[v]
        train_idx = [i for f, fold in enumerate(folds) if f not in (k, v) for i in fold]
        train_rows, val_rows, test_rows = ([rows[i] for i in idxs] for idxs in (train_idx, val_idx, test_idx))
        tools, tasks = build_vocabularies(train_rows)
        train_s, val_s, test_s = ([graph_to_tensors(r, tools, tasks) for r in rs] for rs in (train_rows, val_rows, test_rows))
        val_y = np.array([is_attack(r) for r in val_rows])

        scores = {}
        model = train_gat(train_s, val_s, train_s[0]["node_feat"].shape[1], args, seed + k)
        test_out = predict(model, test_s)
        scores["temporal_gat"] = (predict(model, val_s)["graph"], test_out["graph"])
        scores["bag_of_tools"] = tuple(train_bag(train_rows, [val_rows, test_rows], tools))
        scores["size_only"] = tuple(np.array([len(r["nodes"]) for r in rs], dtype=float) for rs in (val_rows, test_rows))
        for name, (val_p, test_p) in scores.items():
            oof[name][test_idx] = test_p
            oof_pred[name][test_idx] = (test_p >= best_f1_threshold(val_y, val_p)).astype(float)

        for local, row in enumerate(test_rows):
            if row["ground_truth_anomaly_nodes"]:
                ids = [nd["node_id"] for nd in row["nodes"]]
                top3 = {ids[j] for j in np.argsort(test_out["node"][local])[::-1][:3]}
                node_hit3.append(row["ground_truth_anomaly_nodes"][0] in top3)

    labels = np.array([is_attack(r) for r in rows])
    masks = {"all": np.ones(n, dtype=bool), "replay_only": np.array([r["origin"] == "replay" for r in rows])}
    result: Dict[str, Any] = {"seed": seed, "node_top3_hit": float(np.mean(node_hit3)) if node_hit3 else None}
    for name in MODELS:
        result[name] = {}
        for slice_name, mask in masks.items():
            if len(np.unique(labels[mask])) < 2:
                result[name][slice_name] = None
                continue
            metrics = binary_metrics(labels[mask], oof_pred[name][mask], 0.5)
            metrics["auc"] = roc_auc(labels[mask], oof[name][mask])
            result[name][slice_name] = metrics
    return result


def summarize(per_seed: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name in MODELS:
        out[name] = {}
        for slice_name in SLICES:
            runs = [r[name][slice_name] for r in per_seed if r[name][slice_name]]
            out[name][slice_name] = {
                metric: {"mean": float(np.mean([r[metric] for r in runs])), "std": float(np.std([r[metric] for r in runs]))}
                for metric in ("auc", "f1", "precision", "recall")
            } if runs else None
    hits = [r["node_top3_hit"] for r in per_seed if r["node_top3_hit"] is not None]
    out["temporal_gat_node_top3_hit"] = float(np.mean(hits)) if hits else None
    return out


def main() -> None:
    args = parse_args()
    rows = load_rows(PROJECT_ROOT / args.data)
    labels = Counter(f"{r['label']}/{r['origin']}" for r in rows)
    print(f"[data] {len(rows)} graphs, {len({r['group_id'] for r in rows})} groups, {dict(labels)}")
    if len({r["label"] for r in rows}) < 2:
        print("[ERROR] dataset has a single class; verify the replay annotations first")
        sys.exit(1)

    per_seed = []
    for seed in args.seeds:
        result = run_seed(rows, args, seed)
        per_seed.append(result)
        print(f"[seed {seed}] " + " | ".join(
            f"{name} AUC={result[name]['all']['auc']:.3f} F1={result[name]['all']['f1']:.3f}" for name in MODELS
        ) + f" | node top3={result['node_top3_hit']}")

    summary = summarize(per_seed)
    output_dir = PROJECT_ROOT / args.output
    output_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": "temporal-gat-real-cv-v1",
        "data": args.data,
        "graphs": len(rows),
        "groups": len({r["group_id"] for r in rows}),
        "label_origin": dict(labels),
        "config": vars(args),
        "summary": summary,
        "per_seed": per_seed,
    }
    report_path = output_dir / "cv_results.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"[saved] {report_path}")


if __name__ == "__main__":
    main()
