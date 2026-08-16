from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .io import sha256_file


SNAPSHOT_SCHEMA_VERSION = "agentsentry.regression_snapshot.v1"


class RegressionSnapshotError(RuntimeError):
    pass


def verify_regression_snapshot(dataset_root: Path, manifest_path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RegressionSnapshotError(f"regression snapshot manifest is missing: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise RegressionSnapshotError(f"invalid regression snapshot manifest: {exc}") from exc
    if not isinstance(manifest, Mapping) or manifest.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        raise RegressionSnapshotError("unsupported regression snapshot manifest schema")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise RegressionSnapshotError("regression snapshot manifest contains no artifacts")

    checked: list[dict[str, Any]] = []
    problems: list[str] = []
    for entry in artifacts:
        if not isinstance(entry, Mapping):
            problems.append("malformed artifact entry")
            continue
        relative = str(entry.get("path") or "")
        path = dataset_root / relative
        expected_lines = entry.get("lines")
        expected_bytes = entry.get("bytes")
        expected_sha256 = str(entry.get("sha256") or "")
        if not path.is_file():
            problems.append(f"missing artifact: {relative}")
            continue
        actual_lines = _line_count(path)
        actual_bytes = path.stat().st_size
        actual_sha256 = sha256_file(path)
        if actual_lines != expected_lines:
            problems.append(f"{relative}: lines {actual_lines} != {expected_lines}")
        if actual_bytes != expected_bytes:
            problems.append(f"{relative}: bytes {actual_bytes} != {expected_bytes}")
        if actual_sha256 != expected_sha256:
            problems.append(f"{relative}: SHA-256 {actual_sha256} != {expected_sha256}")
        checked.append(
            {
                "path": relative,
                "lines": actual_lines,
                "bytes": actual_bytes,
                "sha256": actual_sha256,
            }
        )
    if problems:
        raise RegressionSnapshotError("regression snapshot drift: " + "; ".join(problems))
    return {
        "snapshot_id": str(manifest.get("snapshot_id") or ""),
        "verified": True,
        "artifacts": checked,
    }


def _line_count(path: Path) -> int:
    count = 0
    last = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            count += chunk.count(b"\n")
            last = chunk[-1:]
    return count + (1 if path.stat().st_size and last != b"\n" else 0)
