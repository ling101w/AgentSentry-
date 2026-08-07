from __future__ import annotations

import copy
import hashlib
import re
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from .io import canonical_json, canonical_whitespace, normalize_text, sha256_text


SIMHASH_BITS = 64


def deduplicate_records(
    records: list[dict[str, Any]],
    *,
    near_distance: int = 6,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    annotated = [copy.deepcopy(item) for item in records]
    similarity_by_id: dict[str, str] = {}
    exact_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    content_labels: dict[str, set[tuple[Any, ...]]] = defaultdict(set)

    for record in annotated:
        payload = canonical_content(record)
        content_hash = sha256_text(payload)
        quality = _quality(record)
        quality["hash_input_version"] = "content-v1"
        quality["content_sha256"] = content_hash
        labels = _mapping(record.get("labels"))
        source = _mapping(record.get("source"))
        agentsentry = _mapping(record.get("agentsentry"))
        label_key = (
            labels.get("attack") is True,
            normalize_text(labels.get("threat_primary")),
            tuple(sorted(normalize_text(value) for value in labels.get("threat_secondary", []))),
            normalize_text(labels.get("attack_type")),
        )
        exact_groups[
            (
                content_hash,
                normalize_text(source.get("dataset")),
                *label_key,
                normalize_text(agentsentry.get("scenario")),
                canonical_whitespace(agentsentry.get("command")),
                normalize_text(agentsentry.get("expectation")),
                normalize_text(agentsentry.get("tool")),
                normalize_text(agentsentry.get("target")),
                agentsentry.get("reset_session") is True,
            )
        ].append(record)
        content_labels[content_hash].add(label_key)
        similarity_by_id[normalize_text(record.get("id"))] = similarity_content(record)

    label_conflict_hashes = {key for key, labels in content_labels.items() if len(labels) > 1}
    exact_removed: list[str] = []
    for exact_key, group in exact_groups.items():
        content_hash = str(exact_key[0])
        ordered = sorted(group, key=lambda item: normalize_text(item.get("id")))
        representative = normalize_text(ordered[0].get("id"))
        for index, record in enumerate(ordered):
            quality = _quality(record)
            quality["duplicate_exact"] = index > 0
            quality["duplicate_of"] = representative if index > 0 else ""
            if index > 0:
                exact_removed.append(normalize_text(record.get("id")))
            if content_hash in label_conflict_hashes:
                warnings = quality.setdefault("warnings", [])
                if "duplicate_content_label_conflict" not in warnings:
                    warnings.append("duplicate_content_label_conflict")

    near_groups = _near_duplicate_groups(
        [record for record in annotated if not _quality(record).get("duplicate_exact")],
        similarity_by_id,
        near_distance,
    )
    for members in near_groups:
        group_id = f"dup_{sha256_text('|'.join(sorted(members)))[:12]}"
        for record in annotated:
            if normalize_text(record.get("id")) in members:
                _quality(record)["duplicate_group"] = group_id

    cleaned = [record for record in annotated if not _quality(record).get("duplicate_exact")]
    report = {
        "input_records": len(records),
        "output_records": len(cleaned),
        "exact_duplicates_removed": len(exact_removed),
        "exact_duplicate_ids": sorted(exact_removed),
        "near_duplicate_groups": len(near_groups),
        "near_duplicate_records": sum(len(group) for group in near_groups),
        "near_distance": near_distance,
        "label_conflict_groups": len(label_conflict_hashes),
        "policy": {
            "exact": (
                "remove only within one source when content, all labels, and the executable "
                "scenario/command/expectation/tool/target/reset projection agree"
            ),
            "near": "mark a duplicate_group across labels and retain every variant",
        },
    }
    return annotated, cleaned, report


def canonical_content(record: Mapping[str, Any]) -> str:
    content = _mapping(record.get("content"))
    fields = {
        "user_instruction": canonical_whitespace(content.get("user_instruction")),
        "attacker_instruction": canonical_whitespace(content.get("attacker_instruction")),
        "tool_response": canonical_whitespace(content.get("tool_response")),
        "tool_name": canonical_whitespace(content.get("tool_name")),
        "trajectory": _canonicalize_value(content.get("trajectory")) if isinstance(content.get("trajectory"), list) else [],
    }
    if not any(fields[field] for field in fields if field != "trajectory") and not fields["trajectory"]:
        agentsentry = _mapping(record.get("agentsentry"))
        fields["user_instruction"] = canonical_whitespace(agentsentry.get("command"))
    return canonical_json(fields)


def similarity_content(record: Mapping[str, Any]) -> str:
    content = _mapping(record.get("content"))
    values = [
        canonical_whitespace(content.get(field))
        for field in ("user_instruction", "attacker_instruction", "tool_response", "tool_name")
    ]
    values.extend(_flatten_text(content.get("trajectory")))
    if not any(values):
        values.append(canonical_whitespace(_mapping(record.get("agentsentry")).get("command")))
    return "\n".join(value for value in values if value)


def _near_duplicate_groups(
    records: list[dict[str, Any]],
    payload_by_id: Mapping[str, str],
    max_distance: int,
) -> list[set[str]]:
    if not 0 <= max_distance <= SIMHASH_BITS:
        raise ValueError(f"near_distance must be between 0 and {SIMHASH_BITS}")
    parents: dict[str, str] = {}
    fingerprints: dict[str, int] = {}
    buckets: dict[tuple[int, int], list[str]] = defaultdict(list)
    seen: list[str] = []
    band_count = min(SIMHASH_BITS, max_distance + 1)

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
        fingerprint = simhash(payload_by_id.get(record_id, ""))
        fingerprints[record_id] = fingerprint
        parents[record_id] = record_id
        candidates: set[str] = set(seen) if max_distance == SIMHASH_BITS else set()
        for band, band_value in _band_values(fingerprint, band_count):
            candidates.update(buckets[(band, band_value)])
        for other in candidates:
            if hamming_distance(fingerprint, fingerprints[other]) <= max_distance:
                union(record_id, other)
        for band, band_value in _band_values(fingerprint, band_count):
            buckets[(band, band_value)].append(record_id)
        seen.append(record_id)

    grouped: dict[str, set[str]] = defaultdict(set)
    for record_id in parents:
        grouped[find(record_id)].add(record_id)
    return sorted(
        (members for members in grouped.values() if len(members) > 1),
        key=lambda members: sorted(members)[0],
    )


def _band_values(fingerprint: int, band_count: int) -> list[tuple[int, int]]:
    values: list[tuple[int, int]] = []
    for band in range(band_count):
        start = (SIMHASH_BITS * band) // band_count
        end = (SIMHASH_BITS * (band + 1)) // band_count
        width = end - start
        values.append((band, (fingerprint >> start) & ((1 << width) - 1)))
    return values


def simhash(value: str) -> int:
    tokens = _tokens(value)
    if not tokens:
        return 0
    weights = [0] * SIMHASH_BITS
    for token in tokens:
        digest = int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest()[:8], "big")
        for bit in range(SIMHASH_BITS):
            weights[bit] += 1 if digest & (1 << bit) else -1
    fingerprint = 0
    for bit, weight in enumerate(weights):
        if weight >= 0:
            fingerprint |= 1 << bit
    return fingerprint


def hamming_distance(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def _tokens(value: str) -> list[str]:
    text = canonical_whitespace(value)
    words = re.findall(r"[\w]+", text, flags=re.UNICODE)
    compact = re.sub(r"\s+", "", text)
    ngrams = [compact[index : index + 4] for index in range(max(0, len(compact) - 3))]
    return words + ngrams


def _canonicalize_value(value: Any) -> Any:
    if isinstance(value, str):
        return canonical_whitespace(value)
    if isinstance(value, Mapping):
        return {str(key): _canonicalize_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_canonicalize_value(item) for item in value]
    return value


def _flatten_text(value: Any) -> list[str]:
    if isinstance(value, str):
        normalized = canonical_whitespace(value)
        return [normalized] if normalized else []
    if isinstance(value, Mapping):
        result: list[str] = []
        for item in value.values():
            result.extend(_flatten_text(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_flatten_text(item))
        return result
    if value is None:
        return []
    return [canonical_whitespace(value)]


def _quality(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("quality")
    if not isinstance(value, dict):
        value = {}
        record["quality"] = value
    return value


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}
