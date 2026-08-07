from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from collections.abc import Mapping
from typing import Any

from .io import normalize_text


def split_records(
    records: list[dict[str, Any]],
    *,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    seed: str = "agentsentry-v1",
    holdout_source: str = "InjecAgent",
    include_invalid: bool = False,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]], dict[str, Any]]:
    if not 0 < train_ratio < 1:
        raise ValueError("train_ratio must be between 0 and 1")
    if not 0 <= val_ratio < 1 or train_ratio + val_ratio >= 1:
        raise ValueError("val_ratio must be non-negative and train_ratio + val_ratio must be below 1")

    eligible = [record for record in records if include_invalid or _status(record) == "valid"]
    excluded_invalid = len(records) - len(eligible)
    component_by_id = constraint_groups(eligible)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in eligible:
        grouped[component_by_id[normalize_text(record.get("id"))]].append(record)

    ratios = {
        "train": train_ratio,
        "val": val_ratio,
        "test": 1 - train_ratio - val_ratio,
    }
    targets = {name: max(0.0, len(eligible) * ratio) for name, ratio in ratios.items()}
    splits: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": []}
    ordered_groups = sorted(
        grouped.items(),
        key=lambda item: (-len(item[1]), _stable_rank(seed, item[0])),
    )
    for group_key, members in ordered_groups:
        candidates = [name for name, ratio in ratios.items() if ratio > 0]
        selected = min(
            candidates,
            key=lambda name: (
                (len(splits[name]) + len(members)) / targets[name] if targets[name] else float("inf"),
                _stable_rank(seed, f"{group_key}:{name}"),
            ),
        )
        splits[selected].extend(members)

    for rows in splits.values():
        rows.sort(key=lambda item: normalize_text(item.get("id")))

    sources = sorted({_dataset(record) for record in eligible if _dataset(record)})
    resolved_holdout = _resolve_holdout(sources, holdout_source)
    cross_test = [record for record in eligible if _dataset(record) == resolved_holdout]
    holdout_groups = {
        component_by_id[normalize_text(record.get("id"))]
        for record in cross_test
    }
    cross_candidates = [record for record in eligible if _dataset(record) != resolved_holdout]
    cross_train = [
        record
        for record in cross_candidates
        if component_by_id[normalize_text(record.get("id"))] not in holdout_groups
    ]
    cross = {"train": cross_train, "test": cross_test}
    for rows in cross.values():
        rows.sort(key=lambda item: normalize_text(item.get("id")))

    leakage = _group_leakage(splits)
    report = {
        "input_records": len(records),
        "eligible_records": len(eligible),
        "excluded_invalid": excluded_invalid,
        "seed": seed,
        "ratios": ratios,
        "group_count": len(grouped),
        "counts": {name: len(rows) for name, rows in splits.items()},
        "distribution": {name: _distribution(rows) for name, rows in splits.items()},
        "group_leakage": leakage,
        "cross_dataset": {
            "holdout_source": resolved_holdout,
            "train_records": len(cross["train"]),
            "test_records": len(cross["test"]),
            "train_sources": sorted({_dataset(item) for item in cross["train"]}),
            "test_sources": sorted({_dataset(item) for item in cross["test"]}),
            "excluded_train_overlap": len(cross_candidates) - len(cross_train),
        },
    }
    if leakage:
        raise RuntimeError(f"split leakage detected for groups: {', '.join(leakage[:5])}")
    return splits, cross, report


def split_group(record: Mapping[str, Any]) -> str:
    quality = _mapping(record.get("quality"))
    provenance = _mapping(record.get("provenance"))
    duplicate_group = normalize_text(quality.get("duplicate_group"))
    if duplicate_group:
        return f"near:{duplicate_group}"
    template_id = normalize_text(provenance.get("template_id"))
    if template_id:
        return f"template:{_dataset(record)}:{template_id}"
    content_hash = normalize_text(quality.get("content_sha256"))
    if content_hash:
        return f"content:{content_hash}"
    return f"record:{normalize_text(record.get('id'))}"


def constraint_groups(records: list[dict[str, Any]]) -> dict[str, str]:
    parents: dict[str, str] = {}
    first_by_constraint: dict[str, str] = {}

    def find(value: str) -> str:
        parents.setdefault(value, value)
        while parents[value] != value:
            parents[value] = parents[parents[value]]
            value = parents[value]
        return value

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    for record in records:
        record_id = normalize_text(record.get("id"))
        if not record_id:
            continue
        parents[record_id] = record_id
        for constraint in _constraints(record):
            previous = first_by_constraint.get(constraint)
            if previous is None:
                first_by_constraint[constraint] = record_id
            else:
                union(record_id, previous)

    components: dict[str, list[str]] = defaultdict(list)
    for record_id in parents:
        components[find(record_id)].append(record_id)
    result: dict[str, str] = {}
    for members in components.values():
        ordered = sorted(members)
        component = f"component:{hashlib.sha256('|'.join(ordered).encode('utf-8')).hexdigest()[:16]}"
        for record_id in ordered:
            result[record_id] = component
    return result


def _constraints(record: Mapping[str, Any]) -> list[str]:
    quality = _mapping(record.get("quality"))
    provenance = _mapping(record.get("provenance"))
    constraints: list[str] = []
    duplicate_group = normalize_text(quality.get("duplicate_group"))
    if duplicate_group:
        constraints.append(f"near:{duplicate_group}")
    template_id = normalize_text(provenance.get("template_id"))
    if template_id:
        constraints.append(f"template:{_dataset(record)}:{template_id}")
    content_hash = normalize_text(quality.get("content_sha256"))
    if content_hash:
        constraints.append(f"content:{content_hash}")
    if not constraints:
        constraints.append(f"record:{normalize_text(record.get('id'))}")
    return constraints


def _group_leakage(splits: Mapping[str, list[dict[str, Any]]]) -> list[str]:
    all_records = [record for records in splits.values() for record in records]
    component_by_id = constraint_groups(all_records)
    group_splits: dict[str, set[str]] = defaultdict(set)
    for split_name, records in splits.items():
        for record in records:
            group_splits[component_by_id[normalize_text(record.get("id"))]].add(split_name)
    return sorted(group for group, names in group_splits.items() if len(names) > 1)


def _distribution(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_source = Counter(_dataset(record) or "unknown" for record in records)
    by_label = Counter("attack" if _attack(record) else "benign" for record in records)
    return {
        "by_source": dict(sorted(by_source.items())),
        "by_label": dict(sorted(by_label.items())),
    }


def _resolve_holdout(sources: list[str], requested: str) -> str:
    for source in sources:
        if source.casefold() == requested.casefold():
            return source
    if not sources:
        return ""
    available = ", ".join(sources)
    raise ValueError(f"unknown holdout source {requested!r}; available sources: {available}")


def _stable_rank(seed: str, value: str) -> str:
    return hashlib.sha256(f"{seed}\x1f{value}".encode("utf-8")).hexdigest()


def _dataset(record: Mapping[str, Any]) -> str:
    return normalize_text(_mapping(record.get("source")).get("dataset"))


def _attack(record: Mapping[str, Any]) -> bool:
    return _mapping(record.get("labels")).get("attack") is True


def _status(record: Mapping[str, Any]) -> str:
    return normalize_text(_mapping(record.get("quality")).get("status"))


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}
