from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..io import normalize_text, sha256_file
from ..sources import SourceSpec


MISSING = object()
COMMAND_ENVELOPE_SCHEMA = "agentsentry.command-envelope.v1"


@dataclass
class AdapterContext:
    root: Path
    spec: SourceSpec
    metadata: Mapping[str, Any]
    errors: list[dict[str, str]] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)
    _files_by_path: dict[str, dict[str, Any]] = field(default_factory=dict)
    _hashes: dict[Path, str] = field(default_factory=dict)

    def relative(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def track_file(self, path: Path, raw_format: str) -> dict[str, Any]:
        relative = self.relative(path)
        entry = self._files_by_path.get(relative)
        if entry is None:
            entry = {
                "path": relative,
                "format": raw_format,
                "sha256": self.file_hash(path) if path.is_file() else "",
                "objects": 0,
                "errors": 0,
            }
            self._files_by_path[relative] = entry
            self.files.append(entry)
        return entry

    def file_hash(self, path: Path) -> str:
        if path not in self._hashes:
            self._hashes[path] = sha256_file(path) if path.is_file() else ""
        return self._hashes[path]

    def error(self, path: Path, locator: str, error: object) -> None:
        relative = self.relative(path)
        entry = self._files_by_path.get(relative)
        if entry is not None:
            entry["errors"] += 1
        self.errors.append(
            {
                "path": relative,
                "locator": locator,
                "error": str(error),
            }
        )

    def source_fields(self, path: Path) -> dict[str, str]:
        return {
            "version": metadata_text(self.metadata, "version", "commit"),
            "license_name": metadata_text(self.metadata, "license", "license_name"),
            "raw_path": self.relative(path),
            "raw_sha256": self.file_hash(path),
        }

    def report(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        if not self.root.exists():
            status = "missing"
        elif self.errors and records:
            status = "partial"
        elif self.errors:
            status = "error"
        else:
            status = "loaded"
        attack_records = sum(bool(item.get("labels", {}).get("attack")) for item in records)
        return {
            "key": self.spec.key,
            "dataset": self.spec.dataset,
            "status": status,
            "source_root": str(self.root),
            "records": len(records),
            "attack_records": attack_records,
            "benign_records": len(records) - attack_records,
            "files": self.files,
            "errors": self.errors,
            "metadata": json_safe(dict(self.metadata)),
        }


def metadata_text(metadata: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = metadata.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, Mapping):
            for nested_key in ("spdx", "name", "id", "value"):
                nested = value.get(nested_key)
                if nested is not None and nested != "":
                    return str(nested)
        return str(value)
    return ""


def read_json(ctx: AdapterContext, path: Path) -> Any:
    entry = ctx.track_file(path, "json")
    if not path.is_file():
        ctx.error(path, "$", "required file is missing")
        return MISSING
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        ctx.error(path, "$", f"unable to read UTF-8 JSON: {exc}")
        return MISSING
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        ctx.error(path, f"line {exc.lineno}, column {exc.colno}", f"invalid JSON: {exc.msg}")
        return MISSING
    entry["objects"] = len(value) if isinstance(value, list) else 1
    return value


def read_jsonl(ctx: AdapterContext, path: Path) -> list[tuple[int, dict[str, Any]]]:
    entry = ctx.track_file(path, "jsonl")
    if not path.is_file():
        ctx.error(path, "$", "required file is missing")
        return []
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError) as exc:
        ctx.error(path, "$", f"unable to read UTF-8 JSONL: {exc}")
        return []
    rows: list[tuple[int, dict[str, Any]]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            ctx.error(path, f"line {line_number}", f"invalid JSON: {exc.msg}")
            continue
        if not isinstance(value, dict):
            ctx.error(path, f"line {line_number}", "expected a JSON object")
            continue
        rows.append((line_number, value))
    entry["objects"] = len(rows)
    return rows


def object_rows(
    ctx: AdapterContext,
    path: Path,
    value: Any,
    *,
    locator: str = "$",
) -> list[tuple[int, dict[str, Any]]]:
    if value is MISSING:
        return []
    if not isinstance(value, list):
        ctx.error(path, locator, "expected a JSON array")
        return []
    rows: list[tuple[int, dict[str, Any]]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            ctx.error(path, f"{locator}[{index}]", "expected a JSON object")
            continue
        rows.append((index, item))
    return rows


def json_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def command_envelope(
    user_instruction: Any,
    *,
    untrusted_inputs: Sequence[Mapping[str, Any]] = (),
) -> str:
    normalized_untrusted: list[dict[str, str]] = []
    for index, item in enumerate(untrusted_inputs):
        text = normalize_text(item.get("text"))
        kind = normalize_text(item.get("kind"))
        if not kind:
            raise ValueError(f"untrusted input {index} is missing kind")
        normalized_untrusted.append(
            {
                "kind": kind,
                "origin": normalize_text(item.get("origin")),
                "text": text,
                "tool_name": normalize_text(item.get("tool_name")),
            }
        )
    return json.dumps(
        {
            "schema": COMMAND_ENVELOPE_SCHEMA,
            "trusted_input": {
                "kind": "user_instruction",
                "text": normalize_text(user_instruction),
            },
            "untrusted_inputs": normalized_untrusted,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def set_mapping(
    record: dict[str, Any],
    *,
    synthetic_wrapper: bool,
    transforms: tuple[str, ...] = (),
) -> dict[str, Any]:
    provenance = record.setdefault("provenance", {})
    provenance["mapping_synthetic_wrapper"] = synthetic_wrapper
    provenance["transforms"] = list(transforms)
    return record


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        return [json_safe(item) for item in sorted(value, key=lambda item: repr(item))]
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return str(value)


def slug(value: object) -> str:
    text = str(value).strip().casefold()
    pieces: list[str] = []
    separator = False
    for character in text:
        if character.isalnum():
            pieces.append(character)
            separator = False
        elif pieces and not separator:
            pieces.append("_")
            separator = True
    return "".join(pieces).strip("_") or "unknown"
