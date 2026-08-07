from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsentry.dataset_pipeline.collector import collect_benchmarks
from agentsentry.dataset_pipeline.sources import SourceSpec


pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


def _git(*arguments: object, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *map(str, arguments)],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        shell=False,
    )
    return result.stdout.strip()


def _origin(tmp_path: Path) -> tuple[Path, SourceSpec]:
    origin = tmp_path / "origin"
    origin.mkdir()
    _git("init", "--initial-branch", "main", cwd=origin)
    _git("config", "user.email", "dataset-test@example.invalid", cwd=origin)
    _git("config", "user.name", "Dataset Test", cwd=origin)
    (origin / "LICENSE").write_text(
        "MIT License\n\nPermission is hereby granted, free of charge, to any person.\n",
        encoding="utf-8",
    )
    (origin / "cases.json").write_text('[{"id": 1}]\n', encoding="utf-8")
    _git("add", "LICENSE", "cases.json", cwd=origin)
    _git("commit", "-m", "initial", cwd=origin)
    spec = SourceSpec(
        key="fixture",
        dataset="FixtureBench",
        directory="FixtureBench",
        repo_url=origin.resolve().as_uri(),
        threat_primary="T2",
        raw_format="json",
    )
    return origin, spec


def test_collect_shallow_clone_then_audit_preserves_download_time(tmp_path: Path) -> None:
    origin, spec = _origin(tmp_path)
    root = tmp_path / "benchmarks"
    manifest_path = tmp_path / "dataset" / "raw_manifest.json"
    first_time = datetime(2026, 8, 7, 1, 2, 3, tzinfo=UTC)

    first = collect_benchmarks(
        root=root,
        manifest_path=manifest_path,
        sources=[spec],
        now=first_time,
    )

    entry = first["sources"][0]
    assert entry["status"] == "downloaded"
    assert entry["dataset"] == "FixtureBench"
    assert entry["url"] == spec.repo_url
    assert entry["commit"] == _git("rev-parse", "HEAD", cwd=origin)
    assert entry["license"] == "MIT"
    assert len(entry["tree_sha256"]) == 64
    assert entry["downloaded_at"] == "2026-08-07T01:02:03Z"
    assert (root / spec.directory / ".git" / "shallow").is_file()

    checkout = root / spec.directory
    (checkout / "cases.json").write_text('[{"id": 999}]\n', encoding="utf-8")
    second = collect_benchmarks(
        root=root,
        manifest_path=manifest_path,
        sources=[spec],
        now=datetime(2026, 8, 8, tzinfo=UTC),
    )
    second_entry = second["sources"][0]
    assert second_entry["status"] == "audited_dirty"
    assert second_entry["downloaded_at"] == entry["downloaded_at"]
    assert (checkout / "cases.json").read_text(encoding="utf-8") == '[{"id": 999}]\n'
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == second


def test_update_fast_forwards_clean_repo_and_refuses_dirty_raw(tmp_path: Path) -> None:
    origin, spec = _origin(tmp_path)
    root = tmp_path / "benchmarks"
    manifest_path = tmp_path / "raw_manifest.json"
    collect_benchmarks(root=root, manifest_path=manifest_path, sources=[spec])
    checkout = root / spec.directory

    (origin / "cases.json").write_text('[{"id": 2}]\n', encoding="utf-8")
    _git("add", "cases.json", cwd=origin)
    _git("commit", "-m", "second", cwd=origin)
    updated = collect_benchmarks(
        root=root,
        manifest_path=manifest_path,
        sources=[spec],
        update=True,
    )
    assert updated["sources"][0]["status"] == "updated"
    assert updated["sources"][0]["commit"] == _git("rev-parse", "HEAD", cwd=origin)
    assert (checkout / "cases.json").read_text(encoding="utf-8") == '[{"id": 2}]\n'

    (checkout / "cases.json").write_text("locally modified\n", encoding="utf-8")
    commit_before = _git("rev-parse", "HEAD", cwd=checkout)
    refused = collect_benchmarks(
        root=root,
        manifest_path=manifest_path,
        sources=[spec],
        update=True,
    )
    refused_entry = refused["sources"][0]
    assert refused_entry["status"] == "refused_dirty"
    assert "refusing to update dirty raw benchmark" in refused_entry["error"]
    assert _git("rev-parse", "HEAD", cwd=checkout) == commit_before
    assert (checkout / "cases.json").read_text(encoding="utf-8") == "locally modified\n"


def test_selected_collection_preserves_unselected_manifest_entries(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first_origin, first = _origin(first_root)
    second_origin, _ = _origin(second_root)
    second = SourceSpec(
        key="fixture-two",
        dataset="FixtureBenchTwo",
        directory="FixtureBenchTwo",
        repo_url=second_origin.resolve().as_uri(),
        threat_primary="T2",
        raw_format="json",
    )
    root = tmp_path / "benchmarks"
    manifest_path = tmp_path / "raw_manifest.json"
    collect_benchmarks(root=root, manifest_path=manifest_path, sources=[first, second])

    refreshed = collect_benchmarks(root=root, manifest_path=manifest_path, sources=[first])

    assert [entry["dataset"] for entry in refreshed["sources"]] == ["FixtureBench", "FixtureBenchTwo"]
    retained = refreshed["sources"][1]
    assert retained["commit"] == _git("rev-parse", "HEAD", cwd=second_origin)
    assert retained["url"] == second.repo_url
    assert first_origin.is_dir()
