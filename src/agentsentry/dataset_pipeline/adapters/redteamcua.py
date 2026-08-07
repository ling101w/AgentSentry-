from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..schema import make_record
from ..sources import SourceSpec
from ._common import AdapterContext, command_envelope, json_text, object_rows, read_json, set_mapping, slug


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
    benign_files = sorted((ctx.root / "goals" / "benign").glob("*.json"), key=lambda path: path.name)
    adversarial_files = sorted((ctx.root / "goals" / "adv").glob("*.json"), key=lambda path: path.name)
    if not benign_files:
        ctx.error(ctx.root / "goals" / "benign", "$", "no benign JSON files found")
    if not adversarial_files:
        ctx.error(ctx.root / "goals" / "adv", "$", "no adversarial JSON files found")

    benign_by_key: dict[str, list[tuple[Path, int, dict[str, Any], str]]] = {}
    records: list[dict[str, Any]] = []
    for path in benign_files:
        rows = object_rows(ctx, path, read_json(ctx, path))
        key = _file_key(path.name)
        mapped: list[tuple[Path, int, dict[str, Any], str]] = []
        for index, item in rows:
            instruction = _user_instruction(item)
            if not instruction:
                ctx.error(path, f"$[{index}].instruction", "unable to extract a user instruction")
            mapped.append((path, index, item, instruction))
            records.append(_benign_record(ctx, path, index, item, instruction))
        benign_by_key[key] = mapped

    for path in adversarial_files:
        rows = object_rows(ctx, path, read_json(ctx, path))
        paired_rows = benign_by_key.get(_file_key(path.name), [])
        if not paired_rows:
            ctx.error(path, "$", "no matching benign task file found")
        for item_index, item in rows:
            paired = _paired_benign(paired_rows, item_index)
            user_instruction = paired[3] if paired is not None else ""
            injections = item.get("injection_contents")
            if not isinstance(injections, list) or not injections:
                ctx.error(path, f"$[{item_index}].injection_contents", "expected a non-empty JSON array")
                injections = [None]
            for injection_index, injection in enumerate(injections):
                if not isinstance(injection, dict):
                    ctx.error(
                        path,
                        f"$[{item_index}].injection_contents[{injection_index}]",
                        "expected a JSON object",
                    )
                records.append(
                    _attack_record(
                        ctx,
                        path,
                        item_index,
                        item,
                        injection_index,
                        injection,
                        paired,
                        user_instruction,
                    )
                )
    return records


def _benign_record(
    ctx: AdapterContext,
    path: Path,
    index: int,
    item: dict[str, Any],
    instruction: str,
) -> dict[str, Any]:
    platform = json_text(item.get("platform")) or _platform(path.name)
    original_id = item.get("id") if item.get("id") not in (None, "") else f"{path.name}:{index}"
    source_ref = f"goals/benign/{path.name}#/{index}"
    command = command_envelope(instruction)
    record = make_record(
        spec=ctx.spec,
        original_id=original_id,
        source_ref=source_ref,
        attack=False,
        attack_type="benign_web_os_task",
        user_instruction=instruction,
        scenario="manual",
        command=command,
        expectation="allow",
        tool="read_file",
        target="README.md",
        notes=f"RTC-Bench benign task for {platform}",
        raw_record=item,
        template_id=f"redteamcua:benign:{slug(platform)}:{slug(item.get('type', 'task'))}",
        **ctx.source_fields(path),
    )
    return set_mapping(
        record,
        synthetic_wrapper=True,
        transforms=(
            "select_declared_instruction_variant",
            "encode_command_trust_envelope",
            "map_benign_task_to_local_read_file",
        ),
    )


def _attack_record(
    ctx: AdapterContext,
    path: Path,
    item_index: int,
    item: dict[str, Any],
    injection_index: int,
    injection: Any,
    paired: tuple[Path, int, dict[str, Any], str] | None,
    user_instruction: str,
) -> dict[str, Any]:
    injection_text = _injection_text(injection)
    if not injection_text:
        ctx.error(
            path,
            f"$[{item_index}].injection_contents[{injection_index}]",
            "unable to extract injected content",
        )
    category = json_text(item.get("category")) or "adversarial"
    description = json_text(item.get("description"))
    platform = _platform(path.name)
    variant = _injection_variant(injection)
    item_id = item.get("id") if item.get("id") not in (None, "") else item_index
    original_id = f"{item_id}:injection:{injection_index}"
    attack_source_ref = f"goals/adv/{path.name}#/{item_index}/injection_contents/{injection_index}"
    source_ref = attack_source_ref
    if paired is not None:
        paired_path, paired_index, _, _ = paired
        source_ref += f" + goals/benign/{paired_path.name}#/{paired_index}"
    action = injection.get("action") if isinstance(injection, Mapping) else None
    tool_name = json_text(action.get("type")) if isinstance(action, Mapping) else ""
    command = command_envelope(
        user_instruction,
        untrusted_inputs=(
            {
                "kind": "external_content",
                "origin": attack_source_ref,
                "tool_name": tool_name,
                "text": injection_text,
            },
        ),
    )
    raw_record: dict[str, Any] = {"adversarial": item}
    if paired is not None:
        paired_path, paired_index, paired_item, _ = paired
        raw_record["paired_benign"] = paired_item
        raw_record["source_hashes"] = {
            f"goals/adv/{path.name}": ctx.file_hash(path),
            f"goals/benign/{paired_path.name}": ctx.file_hash(paired_path),
        }
    record = make_record(
        spec=ctx.spec,
        original_id=original_id,
        source_ref=source_ref,
        attack=True,
        attack_type=category,
        user_instruction=user_instruction,
        attacker_instruction=injection_text,
        tool_response=injection_text,
        tool_name=tool_name,
        scenario=_scenario(platform, category, description),
        command=command,
        expectation="protected",
        notes=json_text({"description": description, "injection_variant": variant}),
        raw_record=raw_record,
        template_id=f"redteamcua:{slug(platform)}:{slug(category)}:{slug(variant)}",
        **ctx.source_fields(path),
    )
    return set_mapping(
        record,
        synthetic_wrapper=True,
        transforms=(
            "pair_adversarial_goal_with_benign_task",
            "encode_command_trust_envelope",
            "map_external_content_to_command_lab_scenario",
        ),
    )


def _file_key(filename: str) -> str:
    key = filename.casefold()
    for prefix in ("adversary_task.", "benign_task."):
        if key.startswith(prefix):
            return key[len(prefix) :]
    return key


def _paired_benign(
    rows: list[tuple[Path, int, dict[str, Any], str]],
    item_index: int,
) -> tuple[Path, int, dict[str, Any], str] | None:
    if not rows:
        return None
    if item_index < len(rows):
        return rows[item_index]
    return rows[0]


def _user_instruction(item: Mapping[str, Any]) -> str:
    instruction = item.get("instruction")
    if isinstance(instruction, str):
        return instruction
    if not isinstance(instruction, Mapping):
        return ""
    declared = json_text(item.get("type"))
    order = [declared, "pointer", "specific", "loose", "end2end"]
    for key in order:
        value = instruction.get(key)
        if isinstance(value, Mapping):
            text = json_text(value.get("instruction"))
        else:
            text = json_text(value)
        if text:
            return text
    return ""


def _injection_text(injection: Any) -> str:
    if isinstance(injection, str):
        return injection
    if not isinstance(injection, Mapping):
        return json_text(injection)
    action = injection.get("action")
    parameters = action.get("parameters") if isinstance(action, Mapping) else None
    candidates = ("new_content", "content", "instruction", "prompt", "text", "body", "message")
    if isinstance(parameters, Mapping):
        for key in candidates:
            text = json_text(parameters.get(key))
            if text:
                return text
    for key in candidates:
        text = json_text(injection.get(key))
        if text:
            return text
    return json_text(injection)


def _injection_variant(injection: Any) -> str:
    if not isinstance(injection, Mapping):
        return "unknown"
    return json_text(injection.get("type")) or "unknown"


def _platform(filename: str) -> str:
    lower = filename.casefold()
    for platform in ("owncloud", "rocketchat", "reddit"):
        if platform in lower:
            return platform
    return "web"


def _scenario(platform: str, category: str, description: str) -> str:
    text = f"{platform} {category} {description}".casefold()
    if any(word in text for word in ("owncloud", "pdf", "docker", "tutorial")):
        return "pdf_stego"
    if any(word in text for word in ("rocketchat", "chat")):
        return "external_email_hidden"
    return "external_web_hidden"
