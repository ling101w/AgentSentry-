"""Generate a diversified synthetic dataset (v2).

Wraps the deterministic base templates with the randomization layer in
diversify.py, then writes records in the same schema as run.py.

Usage (from xuanjian-2.0 project root):
    python -m data.synthetic.generate_v2 --num-normal 800 --num-attack 200 --seed 42 --clean
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import random  # noqa: E402

from data.synthetic.diversify import diversify  # noqa: E402
from data.synthetic.generator import SyntheticDataGenerator  # noqa: E402
from run import infer_attack_type, write_dataset_record  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate diversified synthetic dataset")
    parser.add_argument("--num-normal", type=int, default=800)
    parser.add_argument("--num-attack", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", type=str, default=str(PROJECT_ROOT / "data" / "synthetic"))
    parser.add_argument("--clean", action="store_true",
                        help="Remove old normal_*/attack_* files before generating")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.num_normal < 0 or args.num_attack < 0:
        raise SystemExit("sample counts must be non-negative")

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)
    if args.clean:
        old_files = [
            *glob.glob(os.path.join(output_dir, "normal_*.json")),
            *glob.glob(os.path.join(output_dir, "attack_*.json")),
        ]
        for old_file in old_files:
            os.remove(old_file)
        if old_files:
            print(f"cleaned {len(old_files)} old files")

    rng = random.Random(args.seed)
    generator = SyntheticDataGenerator(seed=args.seed)

    normal_templates = [
        generator.generate_normal_email_summary,
        generator.generate_normal_file_processing,
        generator.generate_normal_calendar_management,
        generator.generate_normal_web_search,
        generator.generate_normal_code_review,
    ]
    attack_templates = [
        generator.generate_attack_ipi_email_exfil,
        generator.generate_attack_data_exfiltration,
        generator.generate_attack_privilege_escalation,
        generator.generate_attack_memory_poisoning,
    ]

    graph_ids = set()
    stats = {"normal": {"nodes": [], "edges": []}, "attack": {"nodes": [], "edges": []}}
    attack_type_counts: dict = {}

    def emit(graph, label: str, index: int) -> None:
        if graph.graph_id in graph_ids:
            raise SystemExit(f"duplicate graph_id: {graph.graph_id}")
        graph_ids.add(graph.graph_id)
        filepath = os.path.join(output_dir, f"{label}_{index:03d}.json")
        write_dataset_record(graph, label, filepath)
        stats[label]["nodes"].append(len(graph.nodes))
        stats[label]["edges"].append(len(graph.edges))
        if label == "attack":
            at = infer_attack_type(graph)
            attack_type_counts[at] = attack_type_counts.get(at, 0) + 1

    print(f"generating {args.num_normal} normal + {args.num_attack} attack graphs (seed={args.seed})")
    for i in range(args.num_normal):
        base = normal_templates[i % len(normal_templates)](f"normal_{i:03d}")
        emit(diversify(base, rng, "normal"), "normal", i)

    for i in range(args.num_attack):
        base = attack_templates[i % len(attack_templates)](f"attack_{i:03d}")
        emit(diversify(base, rng, "attack"), "attack", i)

    def summarize(label: str) -> str:
        nodes = stats[label]["nodes"]
        edges = stats[label]["edges"]
        return (f"{label}: {len(nodes)} graphs | nodes {min(nodes)}~{max(nodes)} "
                f"(avg {sum(nodes) // len(nodes)}) | edges {min(edges)}~{max(edges)}")

    print(summarize("normal"))
    print(summarize("attack"))
    print(f"attack types: {attack_type_counts}")
    print(f"total: {len(graph_ids)} unique graph_ids -> {output_dir}")


if __name__ == "__main__":
    main()
