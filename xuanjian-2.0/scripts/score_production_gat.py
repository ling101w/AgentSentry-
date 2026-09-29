"""Score production-graph-v1 rows with the offline shadow router.

The output is advisory only. Samples outside the training distribution are
marked ``judge_fallback`` and must remain on the deterministic/Judge path.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.production_gat.dataset import load_production_rows, ood_score, rows_to_samples
from models.production_gat.model import RelationGATRouter


def main() -> None:
    args = parse_args()
    checkpoint = torch.load(Path(args.checkpoint), map_location="cpu", weights_only=False)
    model = RelationGATRouter(hidden_dim=int(checkpoint.get("hidden_dim", 48)), layers=int(checkpoint.get("layers", 2)))
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    rows = load_production_rows(Path(args.input))
    samples = rows_to_samples(rows)
    threshold = float(args.threshold if args.threshold is not None else checkpoint["threshold"])
    ood_threshold = float(args.ood_threshold if args.ood_threshold is not None else checkpoint.get("ood_threshold", 3.0))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle, torch.no_grad():
        for sample in samples:
            probability = float(model.forward_sample(sample)["graph_prob"].item())
            distance = ood_score(sample, checkpoint["ood_profile"])
            route = "judge_fallback" if distance > ood_threshold else ("shadow_review" if probability >= threshold else "shadow_allow")
            handle.write(json.dumps({
                "schema_version": "production-gat-score-v1",
                "sample_id": sample.sample_id,
                "session_key": sample.session_key,
                "graph_probability": probability,
                "threshold": threshold,
                "ood_score": distance,
                "ood_threshold": ood_threshold,
                "route": route,
            }, ensure_ascii=False) + "\n")
    print(json.dumps({"output": str(output_path), "rows": len(samples), "threshold": threshold, "ood_threshold": ood_threshold}, ensure_ascii=False))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--ood-threshold", type=float, default=None)
    return parser.parse_args()


if __name__ == "__main__":
    main()
