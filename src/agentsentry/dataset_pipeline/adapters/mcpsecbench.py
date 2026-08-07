from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..schema import make_record
from ..sources import SourceSpec
from ._common import AdapterContext, json_text, object_rows, read_json, set_mapping, slug


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
    path = ctx.root / "data" / "data.json"
    rows = object_rows(ctx, path, read_json(ctx, path))
    records: list[dict[str, Any]] = []
    for index, item in rows:
        attack_name = json_text(item.get("attack"))
        prompt = json_text(item.get("prompt"))
        result = json_text(item.get("result"))
        if not attack_name:
            ctx.error(path, f"$[{index}].attack", "missing attack name")
            attack_name = "MCP attack"
        if not prompt:
            ctx.error(path, f"$[{index}].prompt", "missing prompt")
        original_id = item.get("id") if item.get("id") not in (None, "") else index
        source_ref = f"data/data.json#/{index}"
        record = make_record(
            spec=ctx.spec,
            original_id=original_id,
            source_ref=source_ref,
            attack=True,
            attack_type=attack_name,
            user_instruction=prompt,
            scenario=_scenario(attack_name, prompt),
            command=prompt,
            expectation="protected",
            notes=result,
            raw_record=item,
            template_id=f"mcpsecbench:{slug(attack_name)}",
            **ctx.source_fields(path),
        )
        records.append(set_mapping(record, synthetic_wrapper=False))
    return records


def _scenario(attack: str, prompt: str) -> str:
    text = f"{attack} {prompt}".casefold()
    if any(word in text for word in ("poison", "shadow", "squatting", "rug pull", "confused ai")):
        return "malicious_skill"
    if any(word in text for word in ("sandbox", "vulnerable server", "../", "command")):
        return "gateway_hijack"
    if any(word in text for word in ("credential", "available tools", "data exfiltration")):
        return "external_web_hidden"
    return "external_email_hidden"
