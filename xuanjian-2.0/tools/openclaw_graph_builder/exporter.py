"""Export normalized OpenClaw trajectories as graph JSON or JSONL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from core.graph import CausalGraph

from .graph_builder import OpenClawGraphBuilder
from .parser import OpenClawTrajectory


def graph_record(graph: CausalGraph, trajectory: OpenClawTrajectory) -> dict:
    """Return a self-contained graph record with provenance metadata."""
    record = graph.to_dict()
    record.update(
        {
            "schema_version": "2.0",
            "label": trajectory.label,
            "attack_type": trajectory.attack_type,
            "source": trajectory.metadata.get("source", ""),
        }
    )
    return record


def export_jsonl(
    trajectories: Iterable[OpenClawTrajectory],
    output_path: str | Path,
    *,
    builder: OpenClawGraphBuilder | None = None,
) -> int:
    """Write one graph record per line and reject duplicate graph IDs."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    graph_builder = builder or OpenClawGraphBuilder()
    graph_ids: set[str] = set()
    count = 0
    with output.open("w", encoding="utf-8") as handle:
        for trajectory in trajectories:
            graph = graph_builder.build(trajectory)
            if graph.graph_id in graph_ids:
                raise ValueError(f"duplicate graph_id in input: {graph.graph_id}")
            graph_ids.add(graph.graph_id)
            handle.write(
                json.dumps(graph_record(graph, trajectory), ensure_ascii=False) + "\n"
            )
            count += 1
    return count
