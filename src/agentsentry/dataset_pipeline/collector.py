from __future__ import annotations

import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .io import read_json, tree_sha256, write_json
from .sources import SOURCE_SPECS, SourceSpec, resolve_source


MANIFEST_SCHEMA_VERSION = "agentsentry.raw_manifest.v1"
DEFAULT_BENCHMARK_ROOT = Path("third_party/benchmarks")
DEFAULT_MANIFEST_PATH = Path("dataset/raw_manifest.json")
FAILED_STATUSES = frozenset({"error", "not_git", "audited_dirty", "refused_dirty", "url_mismatch"})

GitRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class CollectionError(RuntimeError):
    """Base class for safe benchmark collection failures."""


class GitCommandError(CollectionError):
    def __init__(self, command: Sequence[str], result: subprocess.CompletedProcess[str]) -> None:
        detail = (result.stderr or result.stdout or "unknown git error").strip()
        super().__init__(f"git command failed ({result.returncode}): {' '.join(command)}: {detail}")
        self.command = tuple(command)
        self.result = result


class DirtyRepositoryError(CollectionError):
    """Raised before an update would touch a modified raw benchmark checkout."""


def collect_benchmarks(
    *,
    root: str | Path = DEFAULT_BENCHMARK_ROOT,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
    update: bool = False,
    sources: Iterable[str | SourceSpec] | None = None,
    git_executable: str = "git",
    now: datetime | None = None,
    runner: GitRunner | None = None,
) -> dict[str, Any]:
    """Clone or audit the six supported raw benchmark repositories.

    Existing directories are read-only unless ``update`` is true. Even then,
    the worktree must be a clean Git repository and the update is restricted to
    fetch plus a fast-forward merge.
    """

    benchmark_root = Path(root)
    output_path = Path(manifest_path)
    selected = _resolve_specs(sources)
    generated_at = _timestamp(now)
    previous = _previous_sources(output_path)
    benchmark_root.mkdir(parents=True, exist_ok=True)

    def invoke(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command = [git_executable, *map(str, arguments)]
        if runner is not None:
            result = runner(command)
        else:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
        if result.returncode != 0:
            raise GitCommandError(command, result)
        return result

    entries: list[dict[str, Any]] = []
    for spec in selected:
        destination = benchmark_root / spec.directory
        old_entry = previous.get(spec.dataset, {})
        downloaded_at = str(old_entry.get("downloaded_at") or generated_at)
        status = "audited"
        error = ""

        if not destination.exists():
            try:
                invoke(
                    (
                        "clone",
                        "--depth",
                        "1",
                        "--no-tags",
                        spec.repo_url,
                        str(destination),
                    )
                )
                status = "downloaded"
                downloaded_at = generated_at
            except (CollectionError, OSError) as exc:
                status = "error"
                error = str(exc)
        elif not destination.is_dir():
            status = "error"
            error = f"benchmark destination is not a directory: {destination}"
        else:
            try:
                audit = _audit_repository(destination, invoke)
                if not audit["is_git"]:
                    status = "not_git"
                    error = f"existing benchmark directory is not a Git worktree: {destination}"
                elif update:
                    if audit["dirty"]:
                        raise DirtyRepositoryError(
                            f"refusing to update dirty raw benchmark repository: {destination}"
                        )
                    remote_url = audit["remote_url"]
                    if remote_url and not _same_repository(remote_url, spec.repo_url):
                        status = "url_mismatch"
                        error = (
                            f"refusing to update {destination}: origin is {remote_url!r}, "
                            f"expected {spec.repo_url!r}"
                        )
                    else:
                        before = audit["commit"]
                        shallow = (
                            _git_output(
                                invoke,
                                destination,
                                "rev-parse",
                                "--is-shallow-repository",
                            )
                            == "true"
                        )
                        fetch_arguments = ["-C", str(destination), "fetch", "--no-tags"]
                        if shallow:
                            # A depth-1 fetch hides the current commit from the
                            # fetched tip and makes a valid update look unrelated.
                            fetch_arguments.append("--unshallow")
                        fetch_arguments.append("origin")
                        invoke(fetch_arguments)
                        invoke(("-C", str(destination), "merge", "--ff-only", "FETCH_HEAD"))
                        after = _git_output(invoke, destination, "rev-parse", "HEAD")
                        status = "updated" if after != before else "up_to_date"
                else:
                    status = "audited_dirty" if audit["dirty"] else "audited"
            except DirtyRepositoryError as exc:
                status = "refused_dirty"
                error = str(exc)
            except (CollectionError, OSError) as exc:
                status = "error"
                error = str(exc)

        entry = _manifest_entry(
            spec,
            destination,
            status=status,
            downloaded_at=downloaded_at,
            invoke=invoke,
            previous=old_entry,
        )
        if error:
            entry["error"] = error
        entries.append(entry)

    if sources is not None:
        updated = {str(entry["dataset"]): entry for entry in entries}
        merged = {**previous, **updated}
        ordered_datasets = [spec.dataset for spec in SOURCE_SPECS]
        ordered_datasets.extend(dataset for dataset in merged if dataset not in ordered_datasets)
        entries = [dict(merged[dataset]) for dataset in ordered_datasets if dataset in merged]

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at": generated_at,
        "sources": entries,
    }
    write_json(output_path, manifest)
    return manifest


def collect_sources(**kwargs: Any) -> dict[str, Any]:
    """Compatibility alias for ``collect_benchmarks``."""

    return collect_benchmarks(**kwargs)


def _resolve_specs(values: Iterable[str | SourceSpec] | None) -> tuple[SourceSpec, ...]:
    if values is None:
        return SOURCE_SPECS
    selected: list[SourceSpec] = []
    seen: set[str] = set()
    for value in values:
        if isinstance(value, SourceSpec):
            spec = value
        else:
            spec = resolve_source(value)
            if spec is None:
                raise CollectionError(f"unknown benchmark source: {value}")
        if spec.key not in seen:
            selected.append(spec)
            seen.add(spec.key)
    if not selected:
        raise CollectionError("at least one benchmark source is required")
    return tuple(selected)


def _audit_repository(path: Path, invoke: GitRunner) -> dict[str, Any]:
    try:
        inside = _git_output(invoke, path, "rev-parse", "--is-inside-work-tree") == "true"
    except CollectionError:
        return {"is_git": False, "commit": "", "dirty": False, "remote_url": ""}
    commit = _git_output(invoke, path, "rev-parse", "HEAD")
    dirty = bool(_git_output(invoke, path, "status", "--porcelain", "--untracked-files=all"))
    try:
        remote_url = _git_output(invoke, path, "remote", "get-url", "origin")
    except CollectionError:
        remote_url = ""
    return {"is_git": inside, "commit": commit, "dirty": dirty, "remote_url": remote_url}


def _manifest_entry(
    spec: SourceSpec,
    path: Path,
    *,
    status: str,
    downloaded_at: str,
    invoke: GitRunner,
    previous: Mapping[str, Any],
) -> dict[str, Any]:
    commit = ""
    if path.is_dir():
        try:
            commit = _git_output(invoke, path, "rev-parse", "HEAD")
        except CollectionError:
            pass
    license_name = detect_license(path) if path.is_dir() else ""
    if not license_name:
        license_name = str(previous.get("license") or "NOASSERTION")
    tree_hash = tree_sha256(path) if path.is_dir() else ""
    return {
        "dataset": spec.dataset,
        "url": spec.repo_url,
        "directory": spec.directory,
        "commit": commit,
        "license": license_name,
        "raw_format": spec.raw_format,
        "sha256": tree_hash,
        "tree_sha256": tree_hash,
        "downloaded_at": downloaded_at,
        "status": status,
    }


def _git_output(invoke: GitRunner, path: Path, *arguments: str) -> str:
    result = invoke(("-C", str(path), *arguments))
    return (result.stdout or "").strip()


def detect_license(root: Path) -> str:
    """Return a conservative SPDX-like identifier from a repository license file."""

    if not root.is_dir():
        return ""
    candidates = sorted(
        (
            path
            for path in root.iterdir()
            if path.is_file()
            and (
                path.name.casefold().startswith("license")
                or path.name.casefold().startswith("copying")
                or path.name.casefold() == "unlicense"
            )
        ),
        key=lambda path: path.name.casefold(),
    )
    if not candidates:
        return ""
    try:
        text = candidates[0].read_text(encoding="utf-8", errors="replace")[:131072].casefold()
    except OSError:
        return ""
    if "apache license" in text and "version 2.0" in text:
        return "Apache-2.0"
    if "permission is hereby granted, free of charge" in text:
        return "MIT"
    if "mozilla public license" in text and "2.0" in text:
        return "MPL-2.0"
    if "gnu affero general public license" in text:
        return "AGPL-3.0-or-later"
    if "gnu lesser general public license" in text:
        return "LGPL"
    if "gnu general public license" in text:
        if "version 3" in text:
            return "GPL-3.0-or-later"
        if "version 2" in text:
            return "GPL-2.0-or-later"
        return "GPL"
    if "redistribution and use in source and binary forms" in text:
        if "neither the name" in text or "contributors may be used to endorse" in text:
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    if "this is free and unencumbered software released into the public domain" in text:
        return "Unlicense"
    return "UNKNOWN"


def _previous_sources(path: Path) -> dict[str, Mapping[str, Any]]:
    manifest = read_json(path, {})
    if not isinstance(manifest, Mapping):
        return {}
    values = manifest.get("sources", [])
    if not isinstance(values, list):
        return {}
    return {
        str(entry.get("dataset")): entry
        for entry in values
        if isinstance(entry, Mapping) and entry.get("dataset")
    }


def _timestamp(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _same_repository(left: str, right: str) -> bool:
    def normalize(value: str) -> str:
        normalized = value.strip().replace("\\", "/").rstrip("/").casefold()
        return normalized[:-4] if normalized.endswith(".git") else normalized

    return normalize(left) == normalize(right)
