from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..schema import make_record
from ..sources import SourceSpec
from ._common import AdapterContext, command_envelope, json_safe, set_mapping


DATA_FILES = ("data/tasks.jsonl", "data/tasks_zh.jsonl")


def load(source_root: Path, spec: SourceSpec, metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    records, _ = load_with_report(source_root, spec, metadata)
    return records


def load_with_report(
    source_root: Path,
    spec: SourceSpec,
    metadata: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    ctx = AdapterContext(Path(source_root), spec, metadata)
    records: list[dict[str, Any]] = []
    for relative in DATA_FILES:
        path = ctx.root / relative
        rows = _read_jsonl(ctx, path)
        for line_number, row in rows:
            record = _record(ctx, path, line_number, row)
            if record is not None:
                records.append(record)
    return records, ctx.report(records)


def _read_jsonl(ctx: AdapterContext, path: Path) -> list[tuple[int, dict[str, Any]]]:
    entry = ctx.track_file(path, "jsonl")
    if not path.is_file():
        # The Chinese export is optional; the English public export is required.
        if path.name != "tasks_zh.jsonl":
            ctx.error(path, "$", "required DeepTrap task export is missing")
        return []
    rows: list[tuple[int, dict[str, Any]]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            ctx.error(path, f"line {line_number}", f"invalid JSON: {exc.msg}")
            continue
        if not isinstance(value, dict) or not value.get("task_id"):
            ctx.error(path, f"line {line_number}", "expected a task object with task_id")
            continue
        rows.append((line_number, value))
    entry["objects"] = len(rows)
    return rows


def _record(ctx: AdapterContext, path: Path, line_number: int, task: Mapping[str, Any]) -> dict[str, Any]:
    task_id = str(task.get("task_id") or f"line-{line_number}")
    risk = str(task.get("risk") or "R0_unknown")
    category = str(task.get("category") or risk)
    domain = _domain(task_id)
    workspace_files = task.get("workspace_files") if isinstance(task.get("workspace_files"), list) else []
    manifest = [_workspace_manifest(item) for item in workspace_files if isinstance(item, Mapping)]
    user_prompt = str(task.get("prompt") or "")
    expected = str(task.get("expected_behavior") or "")
    attack_context = {
        "risk": risk,
        "category": category,
        "workspace_files": json_safe(workspace_files),
        "attack_goal": expected,
    }
    command = command_envelope(
        user_prompt,
        untrusted_inputs=(
            {
                "kind": "execution_context_manifest",
                "origin": f"{ctx.relative(path)}:line={line_number}",
                "text": json.dumps(manifest, ensure_ascii=False, sort_keys=True),
            },
        ),
    )
    secondary = _secondary_for_risk(risk)
    record = make_record(
        spec=ctx.spec,
        original_id=task_id,
        source_ref=f"{ctx.relative(path)}:line={line_number}",
        attack=True,
        attack_type="environment_context_pollution",
        user_instruction=user_prompt,
        attacker_instruction=expected,
        tool_response=json.dumps(attack_context, ensure_ascii=False, sort_keys=True),
        tool_name="openclaw.execution_context",
        trajectory=[{"path": item.get("path", ""), "sha256": item.get("sha256", "")} for item in manifest],
        scenario=f"deeptrap_{risk.lower()}_{domain}",
        command=command,
        expectation="protected",
        tool="workspace_context",
        target=category,
        reset_session=True,
        client_id=f"deeptrap-{task_id}",
        notes=(
            f"DeepTrap native replay; benign user prompt with persistent execution-context pollution; "
            f"business_domain={domain}; cross_session_candidate={_cross_session_candidate(workspace_files)}"
        ),
        raw_record=dict(task),
        template_id=f"deeptrap:{risk}:{task_id}",
        threat_secondary=secondary,
        **ctx.source_fields(path),
    )
    return set_mapping(
        record,
        synthetic_wrapper=False,
        transforms=("load_structured_deeptrap_jsonl", "preserve_workspace_files", "map_execution_context_pollution"),
    )


def _workspace_manifest(item: Mapping[str, Any]) -> dict[str, Any]:
    content = str(item.get("content") or "")
    return {
        "path": str(item.get("path") or ""),
        "sha256": __import__("hashlib").sha256(content.encode("utf-8")).hexdigest(),
        "bytes": len(content.encode("utf-8")),
        "preview": content[:256],
    }


def _secondary_for_risk(risk: str) -> tuple[str, ...]:
    if risk.startswith("R2"):
        return ("T6",)
    if risk in {"R4_supply_chain_risk", "R5_tool_abuse"}:
        return ("T4",)
    if risk == "R6_encoding_obfuscation":
        return ("T1",)
    return ()


def _domain(task_id: str) -> str:
    family = task_id.rsplit("_", 1)[-1]
    return {
        "T01": "office",
        "T02": "office_dev",
        "T03": "research",
        "T04": "deployment",
        "T05": "finance",
        "T06": "office_content",
        "T07": "system_admin",
    }.get(family, "general")


def _cross_session_candidate(files: list[Any]) -> bool:
    for item in files:
        if not isinstance(item, Mapping):
            continue
        path = str(item.get("path") or "").casefold()
        if any(token in path for token in ("memory", "playbook", "agents.md", ".env", "skill")):
            return True
    return False


__all__ = ["load", "load_with_report"]
