"""Convert OpenClaw/AgentSentry trajectory logs to causal-graph JSONL."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.openclaw_graph_builder import export_jsonl, load_trajectories


def convert(
    input_path: str | Path,
    output_path: str | Path,
    *,
    include_empty: bool = False,
) -> int:
    trajectories = load_trajectories(input_path)
    loaded_count = len(trajectories)
    if not include_empty:
        trajectories = [
            trajectory
            for trajectory in trajectories
            if any(event.event_type == "tool_call" for event in trajectory.events)
        ]
    count = export_jsonl(trajectories, output_path)
    skipped = loaded_count - len(trajectories)
    print(f"Converted {len(trajectories)} trajectories")
    if skipped:
        print(f"Skipped {skipped} empty trajectories (use --include-empty to keep them)")
    print(f"Wrote {output_path}")
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="OpenClaw JSON/JSONL input path")
    parser.add_argument("output", help="causal graph JSONL output path")
    parser.add_argument(
        "--include-empty",
        action="store_true",
        help="also export sessions without tool calls",
    )
    args = parser.parse_args()
    convert(args.input, args.output, include_empty=args.include_empty)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
