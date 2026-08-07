from __future__ import annotations

import subprocess
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .io import read_json, tree_sha256
from .sources import SOURCE_BY_KEY


SAFE_MANIFEST_STATUSES = frozenset({"downloaded", "audited", "updated", "up_to_date"})


class DatasetBuildError(RuntimeError):
    pass


def build_normalized_dataset(
    benchmark_root: Path,
    *,
    manifest_path: Path | None = None,
    selected: tuple[str, ...] = (),
    allow_partial: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from .adapters import load_all

    manifest_problems = _manifest_problems(manifest_path)
    metadata = metadata_from_manifest(manifest_path)
    records, source_reports = load_all(
        benchmark_root=benchmark_root,
        metadata_by_dataset=metadata,
        selected=selected,
    )
    records.sort(key=lambda item: str(item.get("id", "")))
    id_counts = Counter(str(item.get("id", "")) for item in records)
    duplicate_ids = sorted(key for key, count in id_counts.items() if key and count > 1)
    for source_report in source_reports:
        source_report["raw_integrity"] = _audit_raw_source(source_report)
    report = {
        "benchmark_root": str(benchmark_root),
        "manifest_path": str(manifest_path) if manifest_path else "",
        "record_count": len(records),
        "duplicate_ids": duplicate_ids,
        "manifest_problems": manifest_problems,
        "sources": source_reports,
    }
    problems = build_integrity_problems(report)
    report["integrity"] = {
        "ready": not problems,
        "allow_partial": allow_partial,
        "problems": problems,
    }
    if problems and not allow_partial:
        raise DatasetBuildError("incomplete benchmark build: " + "; ".join(problems))
    return records, report


def build_integrity_problems(report: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    manifest_problems = report.get("manifest_problems")
    if not isinstance(manifest_problems, list):
        problems.append("raw manifest audit is missing")
    else:
        problems.extend(str(problem) for problem in manifest_problems)
    sources = report.get("sources")
    if not isinstance(sources, list) or not sources:
        problems.append("no benchmark sources were requested")
        sources = []
    for source in sources:
        if not isinstance(source, dict):
            problems.append("malformed source report")
            continue
        dataset = str(source.get("dataset") or source.get("key") or "unknown")
        status = str(source.get("status") or "unknown")
        records = source.get("records")
        errors = source.get("errors")
        if status != "loaded":
            problems.append(f"{dataset}: status={status}")
        if not isinstance(records, int) or records <= 0:
            problems.append(f"{dataset}: no records")
        if isinstance(errors, list) and errors:
            problems.append(f"{dataset}: {len(errors)} parse error(s)")
        raw_integrity = source.get("raw_integrity")
        if not isinstance(raw_integrity, Mapping):
            problems.append(f"{dataset}: raw integrity audit is missing")
        else:
            raw_problems = raw_integrity.get("problems")
            if not isinstance(raw_problems, list):
                problems.append(f"{dataset}: malformed raw integrity audit")
            else:
                problems.extend(f"{dataset}: {problem}" for problem in raw_problems)
    duplicate_ids = report.get("duplicate_ids")
    if isinstance(duplicate_ids, list) and duplicate_ids:
        problems.append(f"{len(duplicate_ids)} duplicate record id(s)")
    if not report.get("record_count"):
        problems.append("build produced no records")
    return sorted(set(problems))


def _manifest_problems(path: Path | None) -> list[str]:
    if path is None or not path.is_file():
        return ["raw manifest is missing"]
    payload = read_json(path, {})
    if not isinstance(payload, Mapping):
        return ["raw manifest is not a JSON object"]
    problems: list[str] = []
    if payload.get("schema_version") != "agentsentry.raw_manifest.v1":
        problems.append("raw manifest schema_version is invalid")
    if not isinstance(payload.get("sources"), list):
        problems.append("raw manifest sources must be an array")
    return problems


def _audit_raw_source(source_report: Mapping[str, Any]) -> dict[str, Any]:
    key = str(source_report.get("key") or "")
    spec = SOURCE_BY_KEY.get(key)
    metadata = source_report.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    root = Path(str(source_report.get("source_root") or ""))
    problems: list[str] = []
    if spec is None:
        problems.append("unknown source specification")
    if not metadata:
        problems.append("manifest entry is missing")
    status = str(metadata.get("status") or "")
    if status not in SAFE_MANIFEST_STATUSES:
        problems.append(f"manifest status is not clean: {status or 'missing'}")
    if spec is not None:
        if str(metadata.get("dataset") or "") != spec.dataset:
            problems.append("manifest dataset does not match source specification")
        if str(metadata.get("directory") or "") != spec.directory:
            problems.append("manifest directory does not match source specification")
        if not _same_repository(str(metadata.get("url") or ""), spec.repo_url):
            problems.append("manifest URL does not match source specification")
    if not root.is_dir():
        problems.append("raw source directory is missing")
        actual_commit = ""
        actual_url = ""
        actual_tree = ""
    else:
        actual_commit = _git_output(root, "rev-parse", "HEAD")
        actual_url = _git_output(root, "remote", "get-url", "origin")
        actual_tree = tree_sha256(root)
    manifest_commit = str(metadata.get("commit") or "")
    manifest_url = str(metadata.get("url") or "")
    manifest_tree = str(metadata.get("tree_sha256") or metadata.get("sha256") or "")
    if not actual_commit:
        problems.append("unable to read raw Git commit")
    elif actual_commit != manifest_commit:
        problems.append("raw Git commit differs from manifest")
    if not actual_url:
        problems.append("unable to read raw Git origin URL")
    elif not _same_repository(actual_url, manifest_url):
        problems.append("raw Git origin URL differs from manifest")
    if not manifest_tree:
        problems.append("manifest tree SHA-256 is missing")
    elif actual_tree != manifest_tree:
        problems.append("raw tree SHA-256 differs from manifest")
    return {
        "ready": not problems,
        "manifest_status": status,
        "manifest_commit": manifest_commit,
        "actual_commit": actual_commit,
        "manifest_url": manifest_url,
        "actual_url": actual_url,
        "manifest_tree_sha256": manifest_tree,
        "actual_tree_sha256": actual_tree,
        "problems": problems,
    }


def _git_output(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
    except OSError:
        return ""
    return (result.stdout or "").strip() if result.returncode == 0 else ""


def _same_repository(left: str, right: str) -> bool:
    def normalize(value: str) -> str:
        normalized = value.strip().replace("\\", "/").rstrip("/").casefold()
        return normalized[:-4] if normalized.endswith(".git") else normalized

    return bool(normalize(left)) and normalize(left) == normalize(right)


def metadata_from_manifest(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    payload = read_json(path, {})
    rows = payload.get("sources", []) if isinstance(payload, dict) else []
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(rows, list):
        return result
    for row in rows:
        if not isinstance(row, dict):
            continue
        dataset = str(row.get("dataset", "")).strip()
        if dataset:
            result[dataset] = dict(row)
            result[dataset.casefold()] = dict(row)
    return result
