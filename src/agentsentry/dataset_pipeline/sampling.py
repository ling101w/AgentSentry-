from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from collections.abc import Mapping
from typing import Any

from .io import normalize_text
from .split import constraint_groups


def balance_attack_ratio(
    records: list[dict[str, Any]],
    *,
    max_attack_ratio: float = 0.80,
    seed: str = "agentsentry-balance-v1",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not 0 < max_attack_ratio < 1:
        raise ValueError("max_attack_ratio must be between 0 and 1")
    attacks = [record for record in records if _attack(record)]
    benign = [record for record in records if not _attack(record)]
    if not benign:
        selected = sorted(records, key=_record_id)
        return selected, _report(records, selected, max_attack_ratio, seed, "no_benign_available")

    attack_limit = int(max_attack_ratio * len(benign) / (1 - max_attack_ratio))
    if len(attacks) <= attack_limit:
        selected = sorted(records, key=_record_id)
        return selected, _report(records, selected, max_attack_ratio, seed, "already_within_limit")

    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    component_by_id = constraint_groups(attacks)
    for record in attacks:
        by_group[component_by_id[_record_id(record)]].append(record)
    representatives = [
        min(group, key=lambda record: _rank(seed, f"representative:{_record_id(record)}"))
        for group in by_group.values()
    ]
    representatives.sort(key=lambda record: _rank(seed, f"group:{component_by_id[_record_id(record)]}"))
    selected_attacks = representatives[:attack_limit]
    selected_ids = {_record_id(record) for record in selected_attacks}

    if len(selected_attacks) < attack_limit:
        remaining = [record for record in attacks if _record_id(record) not in selected_ids]
        remaining.sort(key=lambda record: _rank(seed, f"fill:{_record_id(record)}"))
        selected_attacks.extend(remaining[: attack_limit - len(selected_attacks)])

    selected = sorted([*benign, *selected_attacks], key=_record_id)
    return selected, _report(records, selected, max_attack_ratio, seed, "downsampled_attack")


def _report(
    source: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    max_attack_ratio: float,
    seed: str,
    status: str,
) -> dict[str, Any]:
    source_attacks = sum(_attack(record) for record in source)
    selected_attacks = sum(_attack(record) for record in selected)
    selected_benign = len(selected) - selected_attacks
    by_source = Counter(_dataset(record) or "unknown" for record in selected)
    return {
        "status": status,
        "seed": seed,
        "max_attack_ratio": max_attack_ratio,
        "input_records": len(source),
        "input_attack": source_attacks,
        "input_benign": len(source) - source_attacks,
        "output_records": len(selected),
        "output_attack": selected_attacks,
        "output_benign": selected_benign,
        "output_attack_ratio": round(selected_attacks / len(selected), 6) if selected else 0,
        "by_source": dict(sorted(by_source.items())),
        "policy": "retain all benign; cover attack groups first; fill deterministically by stable hash",
    }


def _rank(seed: str, value: str) -> str:
    return hashlib.sha256(f"{seed}\x1f{value}".encode("utf-8")).hexdigest()


def _attack(record: Mapping[str, Any]) -> bool:
    labels = record.get("labels")
    return isinstance(labels, Mapping) and labels.get("attack") is True


def _dataset(record: Mapping[str, Any]) -> str:
    source = record.get("source")
    return normalize_text(source.get("dataset")) if isinstance(source, Mapping) else ""


def _record_id(record: Mapping[str, Any]) -> str:
    return normalize_text(record.get("id"))
