from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ..sources import SOURCE_SPECS, SourceSpec
from . import agentdojo, injecagent, mcpsecbench, memorygraft, msb, redteamcua


Loader = Callable[[Path, SourceSpec, Mapping[str, Any]], list[dict[str, Any]]]

ADAPTERS: dict[str, Loader] = {
    "redteamcua": redteamcua.load,
    "msb": msb.load,
    "mcpsecbench": mcpsecbench.load,
    "memorygraft": memorygraft.load,
    "agentdojo": agentdojo.load,
    "injecagent": injecagent.load,
}

_LOADERS_WITH_REPORT = {
    "redteamcua": redteamcua.load_with_report,
    "msb": msb.load_with_report,
    "mcpsecbench": mcpsecbench.load_with_report,
    "memorygraft": memorygraft.load_with_report,
    "agentdojo": agentdojo.load_with_report,
    "injecagent": injecagent.load_with_report,
}


def load_all(
    benchmark_root: Path,
    metadata_by_dataset: Mapping[str, Mapping[str, Any]],
    selected: Sequence[str] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = Path(benchmark_root)
    selected_keys = _selected_keys(selected)
    records: list[dict[str, Any]] = []
    reports: list[dict[str, Any]] = []
    for spec in SOURCE_SPECS:
        if selected_keys and spec.key not in selected_keys:
            continue
        source_root = root / spec.directory
        metadata = _metadata_for(spec, metadata_by_dataset)
        loaded, report = _LOADERS_WITH_REPORT[spec.key](source_root, spec, metadata)
        records.extend(loaded)
        reports.append(report)
    return records, reports


def _selected_keys(selected: Sequence[str]) -> set[str]:
    if not selected:
        return set()
    aliases: dict[str, str] = {}
    for spec in SOURCE_SPECS:
        for value in (spec.key, spec.dataset, spec.directory, *spec.registry_aliases):
            aliases[value.strip().casefold()] = spec.key
    resolved: set[str] = set()
    unknown: list[str] = []
    for value in selected:
        key = aliases.get(str(value).strip().casefold())
        if key is None:
            unknown.append(str(value))
        else:
            resolved.add(key)
    if unknown:
        raise ValueError(f"unknown dataset selector(s): {', '.join(sorted(unknown))}")
    return resolved


def _metadata_for(
    spec: SourceSpec,
    metadata_by_dataset: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    aliases = (spec.dataset, spec.dataset.casefold(), spec.key, spec.key.casefold(), spec.directory, spec.directory.casefold())
    for alias in aliases:
        value = metadata_by_dataset.get(alias)
        if isinstance(value, Mapping):
            return value
    folded = {str(key).casefold(): value for key, value in metadata_by_dataset.items()}
    for alias in aliases:
        value = folded.get(alias.casefold())
        if isinstance(value, Mapping):
            return value
    return {}


__all__ = ["ADAPTERS", "load_all"]
