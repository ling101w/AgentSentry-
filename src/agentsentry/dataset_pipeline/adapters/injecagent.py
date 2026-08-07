from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..schema import make_record
from ..sources import SourceSpec
from ._common import AdapterContext, command_envelope, json_text, object_rows, read_json, set_mapping, slug


CASE_FILES = (
    "test_cases_ds_base.json",
    "test_cases_dh_base.json",
    "test_cases_ds_enhanced.json",
    "test_cases_dh_enhanced.json",
)


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
    records: list[dict[str, Any]] = []
    for filename in CASE_FILES:
        path = ctx.root / "data" / filename
        rows = object_rows(ctx, path, read_json(ctx, path))
        for index, item in rows:
            locator = f"$[{index}]"
            user_instruction = json_text(item.get("User Instruction"))
            attacker_instruction = json_text(item.get("Attacker Instruction"))
            tool_response = json_text(item.get("Tool Response"))
            user_tool = json_text(item.get("User Tool"))
            attack_type = json_text(item.get("Attack Type"))
            if not user_instruction:
                ctx.error(path, f"{locator}.User Instruction", "missing User Instruction")
            if not attacker_instruction:
                ctx.error(path, f"{locator}.Attacker Instruction", "missing Attacker Instruction")
            if not tool_response:
                ctx.error(path, f"{locator}.Tool Response", "missing Tool Response")
            if not attack_type:
                ctx.error(path, f"{locator}.Attack Type", "missing Attack Type")
                attack_type = "tool_response_injection"

            attacker_tools = item.get("Attacker Tools", [])
            scenario = _scenario(attack_type, attacker_tools, attacker_instruction, tool_response)
            source_ref = f"data/{filename}#/{index}"
            original_id = item.get("id") if item.get("id") not in (None, "") else f"{filename}:{index}"
            command = command_envelope(
                user_instruction,
                untrusted_inputs=(
                    {
                        "kind": "tool_response",
                        "origin": source_ref,
                        "tool_name": user_tool,
                        "text": tool_response,
                    },
                ),
            )
            trajectory = []
            thought = json_text(item.get("Thought"))
            if thought:
                trajectory.append({"role": "assistant", "content": thought})
            if user_tool or item.get("Tool Parameters") not in (None, ""):
                trajectory.append(
                    {
                        "type": "tool_call",
                        "tool_name": user_tool,
                        "parameters": item.get("Tool Parameters"),
                    }
                )
            if tool_response:
                trajectory.append(
                    {
                        "type": "tool_response",
                        "tool_name": user_tool,
                        "content": tool_response,
                    }
                )
            notes = json_text(
                {
                    "attacker_tools": attacker_tools,
                    "expected_achievements": item.get("Expected Achievements", ""),
                    "tool_parameters": item.get("Tool Parameters", ""),
                }
            )
            record = make_record(
                spec=ctx.spec,
                original_id=original_id,
                source_ref=source_ref,
                attack=True,
                attack_type=attack_type,
                user_instruction=user_instruction,
                attacker_instruction=attacker_instruction,
                tool_response=tool_response,
                tool_name=user_tool,
                trajectory=trajectory,
                scenario=scenario,
                command=command,
                expectation="protected",
                notes=notes,
                raw_record=item,
                template_id=f"injecagent:{slug(attack_type)}:{slug(user_tool)}",
                **ctx.source_fields(path),
            )
            records.append(
                set_mapping(
                    record,
                    synthetic_wrapper=True,
                    transforms=(
                        "encode_command_trust_envelope",
                        "map_tool_response_to_scenario",
                    ),
                )
            )
    return records


def _scenario(
    attack_type: str,
    attacker_tools: Any,
    attacker_instruction: str,
    tool_response: str,
) -> str:
    text = f"{attack_type} {attacker_tools} {attacker_instruction} {tool_response}".casefold()
    if any(word in text for word in ("email", "gmail", "send", "alternate email")):
        return "external_email_hidden"
    if any(word in text for word in ("smartlock", "lock", "grant", "access", "bank", "payment", "transfer")):
        return "malicious_skill"
    return "external_web_hidden"
