"""Rebuild vocab.json for an existing checkpoint from its training data.

Run this once per checkpoint that was trained before vocab persistence was
working (or whose vocab.json was lost). It reads the CausalGraph JSONs
from the same directory the checkpoint was trained on, rebuilds the
tool/task vocabularies, and writes them next to the checkpoint.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.temporal_gat.dataset import build_vocabularies, load_graph_files  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=str, required=True,
                        help="Training data directory containing CausalGraph JSON files")
    parser.add_argument("--output", type=str, required=True,
                        help="Path to write vocab.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    data_path = PROJECT_ROOT / args.data
    files = sorted(p for p in data_path.glob("*.json") if not p.name.endswith("_meta.json"))
    print(f"[data] {len(files)} graphs from {data_path}")

    graphs = load_graph_files(files)
    tool_vocab, task_vocab = build_vocabularies(graphs)
    print(f"[vocab] tools={len(tool_vocab)} tasks={len(task_vocab)}")

    output_path = PROJECT_ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"tool_vocab": tool_vocab, "task_vocab": task_vocab}
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"[saved] {output_path}")


if __name__ == "__main__":
    main()
