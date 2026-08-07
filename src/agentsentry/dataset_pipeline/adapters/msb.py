from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..schema import make_record
from ..sources import SourceSpec
from ._common import AdapterContext, command_envelope, json_text, read_jsonl, set_mapping, slug


def load(source_root: Path, spec: SourceSpec, metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    records, _ = load_with_report(source_root, spec, metadata)
    return records


def load_with_report(
    source_root: Path,
    spec: SourceSpec,
    metadata: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    ctx = AdapterContext(Path(source_root), spec, metadata)
    records = _load(ctx)
    return records, ctx.report(records)


def _load(ctx: AdapterContext) -> list[dict[str, Any]]:
    if not ctx.root.exists():
        return []
    agent_path = ctx.root / "data" / "agent_task.jsonl"
    attack_path = ctx.root / "data" / "attack_task.jsonl"
    type_path = ctx.root / "data" / "attack_type.jsonl"
    agents = read_jsonl(ctx, agent_path)
    attacks = read_jsonl(ctx, attack_path)
    attack_types = _attack_types(ctx, type_path, read_jsonl(ctx, type_path))

    records: list[dict[str, Any]] = []
    for agent_line, agent in agents:
        tasks = agent.get("task_tool")
        if not isinstance(tasks, list):
            ctx.error(agent_path, f"line {agent_line}.task_tool", "expected a JSON array")
            continue
        for task_index, task in enumerate(tasks):
            task_locator = f"line {agent_line}.task_tool[{task_index}]"
            if not isinstance(task, dict):
                ctx.error(agent_path, task_locator, "expected a JSON object")
                continue
            user_instruction = json_text(task.get("task"))
            tool_name = json_text(task.get("tool"))
            if not user_instruction:
                ctx.error(agent_path, f"{task_locator}.task", "missing task")
            records.append(
                _benign_record(
                    ctx,
                    agent_path,
                    agent_line,
                    task_index,
                    agent,
                    task,
                    user_instruction,
                    tool_name,
                )
            )
            for attack_line, attack in attacks:
                for type_line, type_index, attack_type in attack_types:
                    records.append(
                        _attack_record(
                            ctx,
                            paths=(agent_path, attack_path, type_path),
                            indices=(agent_line, task_index, attack_line, type_line, type_index),
                            agent=agent,
                            task=task,
                            attack=attack,
                            attack_type=attack_type,
                            user_instruction=user_instruction,
                            tool_name=tool_name,
                        )
                    )
    return records


def _attack_types(
    ctx: AdapterContext,
    path: Path,
    rows: list[tuple[int, dict[str, Any]]],
) -> list[tuple[int, int, str]]:
    values: list[tuple[int, int, str]] = []
    for line_number, row in rows:
        raw = row.get("attack_type")
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            ctx.error(path, f"line {line_number}.attack_type", "expected a string or JSON array")
            continue
        for index, item in enumerate(raw):
            value = json_text(item)
            if not value:
                ctx.error(path, f"line {line_number}.attack_type[{index}]", "empty attack type")
                continue
            values.append((line_number, index, value))
    return values


def _benign_record(
    ctx: AdapterContext,
    path: Path,
    agent_line: int,
    task_index: int,
    agent: dict[str, Any],
    task: dict[str, Any],
    user_instruction: str,
    tool_name: str,
) -> dict[str, Any]:
    agent_name = json_text(agent.get("agent_name")) or f"line-{agent_line}"
    original_id = f"agent-line:{agent_line}:task:{task_index}:benign"
    source_ref = f"data/agent_task.jsonl#line={agent_line}/task_tool/{task_index}"
    command = command_envelope(user_instruction)
    raw_record = {
        "agent": agent,
        "task": task,
        "source_index": {"agent_line": agent_line, "task_index": task_index},
    }
    record = make_record(
        spec=ctx.spec,
        original_id=original_id,
        source_ref=source_ref,
        attack=False,
        attack_type="mcp_benign_task",
        user_instruction=user_instruction,
        tool_name=tool_name,
        scenario="manual",
        command=command,
        expectation="allow",
        tool="read_file",
        target="README.md",
        notes=f"MSB normal task for agent {agent_name}; upstream tool: {tool_name}",
        raw_record=raw_record,
        template_id=f"msb:benign:{slug(agent_name)}:{slug(tool_name)}",
        **ctx.source_fields(path),
    )
    return set_mapping(
        record,
        synthetic_wrapper=True,
        transforms=(
            "encode_command_trust_envelope",
            "map_upstream_tool_to_local_read_file",
        ),
    )


def _attack_record(
    ctx: AdapterContext,
    *,
    paths: tuple[Path, Path, Path],
    indices: tuple[int, int, int, int, int],
    agent: dict[str, Any],
    task: dict[str, Any],
    attack: dict[str, Any],
    attack_type: str,
    user_instruction: str,
    tool_name: str,
) -> dict[str, Any]:
    agent_path, attack_path, type_path = paths
    agent_line, task_index, attack_line, type_line, type_index = indices
    attack_name = json_text(attack.get("attack_task"))
    implementation = json_text(attack.get("implementation"))
    if not attack_name:
        ctx.error(attack_path, f"line {attack_line}.attack_task", "missing attack_task")
        attack_name = f"attack-line-{attack_line}"
    if not implementation:
        ctx.error(attack_path, f"line {attack_line}.implementation", "missing implementation")
    original_id = (
        f"agent-line:{agent_line}:task:{task_index}:attack-line:{attack_line}:"
        f"type-line:{type_line}:type:{type_index}"
    )
    source_ref = (
        f"data/agent_task.jsonl#line={agent_line}/task_tool/{task_index} + "
        f"data/attack_task.jsonl#line={attack_line} + "
        f"data/attack_type.jsonl#line={type_line}/attack_type/{type_index}"
    )
    command = command_envelope(
        user_instruction,
        untrusted_inputs=(
            {
                "kind": "mcp_attack_payload",
                "origin": f"data/attack_task.jsonl#line={attack_line}",
                "tool_name": tool_name,
                "text": implementation,
            },
        ),
    )
    raw_record = {
        "agent": agent,
        "task": task,
        "attack": attack,
        "attack_type": attack_type,
        "source_index": {
            "agent_line": agent_line,
            "task_index": task_index,
            "attack_line": attack_line,
            "attack_type_line": type_line,
            "attack_type_index": type_index,
        },
        "source_hashes": {
            "data/agent_task.jsonl": ctx.file_hash(agent_path),
            "data/attack_task.jsonl": ctx.file_hash(attack_path),
            "data/attack_type.jsonl": ctx.file_hash(type_path),
        },
    }
    record = make_record(
        spec=ctx.spec,
        original_id=original_id,
        source_ref=source_ref,
        attack=True,
        attack_type=f"mcp_{attack_type}",
        user_instruction=user_instruction,
        attacker_instruction=implementation,
        tool_response=implementation,
        tool_name=tool_name,
        trajectory=[{"type": "tool_response", "tool_name": tool_name, "content": implementation}],
        scenario=_scenario(attack_type, attack_name),
        command=command,
        expectation="protected",
        notes=json_text({"attack_task": attack_name, "upstream_tool": tool_name}),
        raw_record=raw_record,
        template_id=f"msb:{slug(attack_type)}:{slug(attack_name)}",
        **ctx.source_fields(attack_path),
    )
    return set_mapping(
        record,
        synthetic_wrapper=True,
        transforms=(
            "compose_msb_cartesian_case",
            "encode_command_trust_envelope",
            "map_tool_attack_to_command_lab_scenario",
        ),
    )


def _scenario(attack_type: str, attack_task: str) -> str:
    text = f"{attack_type} {attack_task}".casefold()
    if any(
        word in text
        for word in ("out_of_scope", "tool_transfer", "name_overlap", "preference_manipulation")
    ):
        return "malicious_skill"
    if any(word in text for word in ("false_error", "simulated_user")):
        return "external_email_hidden"
    if "remote_control" in text:
        return "gateway_hijack"
    if "modify" in text:
        return "memory_poison"
    return "external_web_hidden"
