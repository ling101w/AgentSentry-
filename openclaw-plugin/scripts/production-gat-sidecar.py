"""JSONL stdin/stdout sidecar for the production-gat shadow router."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> None:
    args = parse_args()
    project_root = Path(args.project_root).resolve() if args.project_root else Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(project_root))
    try:
        import torch
        from models.production_gat.dataset import ood_score, row_to_sample
        from models.production_gat.model import RelationGATRouter
        checkpoint = torch.load(Path(args.checkpoint), map_location="cpu", weights_only=False)
        model = RelationGATRouter(hidden_dim=int(checkpoint.get("hidden_dim", 48)), layers=int(checkpoint.get("layers", 2)))
        model.load_state_dict(checkpoint["state_dict"])
        model.eval()
    except Exception as exc:
        print(json.dumps({"ready": False, "error": f"sidecar initialization failed: {exc}"}), flush=True)
        return

    print(json.dumps({"ready": True, "model_version": str(checkpoint.get("schema_version", "production-gat-checkpoint-v1"))}), flush=True)
    with torch.no_grad():
        for line in sys.stdin:
            request = None
            try:
                request = json.loads(line)
                graph_input = request["input"]
                sample = row_to_sample({
                    "input": graph_input,
                    "label": {"source": "policy_weak_label", "policy_outcome": "allow"},
                    "metadata": {"sample_id": str(request.get("id", "sidecar"))},
                })
                output = model.forward_sample(sample)
                probability = float(output["graph_prob"].item())
                distance = ood_score(sample, checkpoint["ood_profile"])
                threshold = float(checkpoint.get("threshold", 0.6))
                ood_threshold = float(checkpoint.get("ood_threshold", 3.0))
                route = "judge_fallback" if distance > ood_threshold else "shadow_review" if probability >= threshold else "shadow_allow"
                response = {"id": request.get("id", ""), "ok": True, "model_version": str(checkpoint.get("schema_version", "production-gat-checkpoint-v1")), "graph_probability": probability, "threshold": threshold, "ood_score": distance, "ood_threshold": ood_threshold, "route": route}
            except Exception as exc:
                response = {"id": request.get("id", "") if isinstance(request, dict) else "", "ok": False, "error": str(exc)[:300]}
            print(json.dumps(response), flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--project-root", default="")
    return parser.parse_args()


if __name__ == "__main__":
    main()
