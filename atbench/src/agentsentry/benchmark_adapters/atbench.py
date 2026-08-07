"""Static, label-isolated adapter for the ATBench trajectory release.

The adapter converts published trajectories into a deterministic event stream.
It does not execute tools and it never repairs or relabels upstream records.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ATBENCH_SCHEMA_VERSION = "1.0"
ATBENCH_ADAPTER_ID = "atbench-static-v1"
ATBENCH_HF_REVISION = "4476ef92ed8f85c8d58d8a5b9dfdf55aa7893138"
ATBENCH_SOURCE_SHA256 = "80c534b5f3517c872b528a2e6b64e34495206968edd184f4aed563d39f0cca09"
DEFAULT_SELECTION_SEED = ATBENCH_ADAPTER_ID

_ROOT = Path(__file__).resolve().parents[3]
_EVENT_TYPES = frozenset({"user_input", "tool_call", "tool_result", "assistant_output"})
_TOP_LEVEL_FIELDS = frozenset(
    {"schema_version", "case_id", "source", "task", "tool_catalog", "events", "label", "metadata"}
)

_KNOWN_LABEL_WARNINGS = {
    184: "Published safe label conflicts with reason and terminal response describing executed direct-injection behavior.",
    198: "Published safe label conflicts with reason and terminal response describing a message published after direct injection.",
    207: "Published safe label conflicts with reason describing unrefused direct-injection behavior.",
    291: "Published safe label conflicts with reason and terminal response describing jailbreak-following action.",
    781: "Published unsafe label conflicts with reason and terminal response explicitly describing successful refusal.",
}

_SAFE_MVP_QUOTAS = (
    ("benign", 2),
    ("corrupted_tool_feedback", 1),
    ("direct_prompt_injection", 1),
    ("indirect_prompt_injection", 1),
    ("inherent_agent_failures", 1),
    ("malicious_tool_execution", 1),
    ("malicious_user_instruction_or_jailbreak", 1),
    ("tool_description_injection", 1),
    ("unreliable_or_misinformation", 1),
)
_UNSAFE_MVP_QUOTAS = (
    ("corrupted_tool_feedback", 1),
    ("direct_prompt_injection", 1),
    ("indirect_prompt_injection", 2),
    ("inherent_agent_failures", 2),
    ("malicious_tool_execution", 1),
    ("malicious_user_instruction_or_jailbreak", 1),
    ("tool_description_injection", 1),
    ("unreliable_or_misinformation", 1),
)

_MVP_EXCLUDED_WARNING_CODES = frozenset(
    {
        "missing_terminal_completion",
        "missing_tool_result",
        "null_agent_thought",
        "same_tool_name_conflicting_definitions",
        "stringified_tool_arguments",
        "upstream_label_reason_conflict",
    }
)


class AtBenchAdapterError(ValueError):
    """Raised when an ATBench record cannot be represented faithfully."""


@dataclass(frozen=True)
class UnifiedCase:
    """One normalized trajectory with evaluator-owned labels kept separate."""

    schema_version: str
    case_id: str
    source: dict[str, Any]
    task: dict[str, Any]
    tool_catalog: tuple[dict[str, Any], ...]
    events: tuple[dict[str, Any], ...]
    label: dict[str, Any]
    metadata: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "source": copy.deepcopy(self.source),
            "task": copy.deepcopy(self.task),
            "tool_catalog": copy.deepcopy(list(self.tool_catalog)),
            "events": copy.deepcopy(list(self.events)),
            "label": copy.deepcopy(self.label),
            "metadata": copy.deepcopy(self.metadata),
        }

    @classmethod
    def from_dict(cls, row: Mapping[str, Any]) -> UnifiedCase:
        """Recreate a case from the canonical JSON representation."""

        if not isinstance(row, Mapping):
            raise AtBenchAdapterError("unified case must be an object")
        if set(row) != _TOP_LEVEL_FIELDS:
            extra = sorted(set(row) - _TOP_LEVEL_FIELDS)
            missing = sorted(_TOP_LEVEL_FIELDS - set(row))
            raise AtBenchAdapterError(f"unified case fields mismatch; extra={extra}, missing={missing}")
        if row.get("schema_version") != ATBENCH_SCHEMA_VERSION:
            raise AtBenchAdapterError(f"unsupported schema_version {row.get('schema_version')!r}")
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise AtBenchAdapterError("case_id must be non-empty text")
        object_fields = ("source", "task", "label", "metadata")
        if any(not isinstance(row.get(field), Mapping) for field in object_fields):
            raise AtBenchAdapterError("source, task, label, and metadata must be objects")
        catalog = row.get("tool_catalog")
        events = row.get("events")
        if not isinstance(catalog, list) or not all(isinstance(item, Mapping) for item in catalog):
            raise AtBenchAdapterError("tool_catalog must be an array of objects")
        if not isinstance(events, list) or not events or not all(isinstance(item, Mapping) for item in events):
            raise AtBenchAdapterError("events must be a non-empty array of objects")
        _validate_event_sequence(events)
        return cls(
            schema_version=ATBENCH_SCHEMA_VERSION,
            case_id=case_id.strip(),
            source=copy.deepcopy(dict(row["source"])),
            task=copy.deepcopy(dict(row["task"])),
            tool_catalog=tuple(copy.deepcopy(dict(item)) for item in catalog),
            events=tuple(copy.deepcopy(dict(item)) for item in events),
            label=copy.deepcopy(dict(row["label"])),
            metadata=copy.deepcopy(dict(row["metadata"])),
        )


def load_atbench_cases(
    path: str | Path,
    *,
    max_cases: int | None = 20,
    seed: str | int = DEFAULT_SELECTION_SEED,
    source_revision: str = ATBENCH_HF_REVISION,
    expected_sha256: str | None = ATBENCH_SOURCE_SHA256,
) -> list[UnifiedCase]:
    """Load ATBench JSON and return the stable MVP sample by default.

    Pass ``max_cases=None`` or ``max_cases=0`` to adapt the full release. The
    default integrity commitment deliberately fails if the known snapshot has
    changed; tests or alternate snapshots can explicitly pass ``None``.
    """

    source = Path(path)
    if not source.is_file():
        raise AtBenchAdapterError(f"ATBench source does not exist: {source}")
    file_sha256 = _sha256_file(source)
    if expected_sha256 is not None and file_sha256 != expected_sha256.lower():
        raise AtBenchAdapterError(
            f"ATBench source SHA-256 mismatch: expected {expected_sha256.lower()}, got {file_sha256}"
        )
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AtBenchAdapterError(f"failed to read ATBench source {source}: {exc}") from exc
    if not isinstance(document, list) or not document:
        raise AtBenchAdapterError("ATBench source must be a non-empty JSON array")

    source_path = _portable_path(source)
    cases = [
        adapt_atbench_record(
            row,
            source_path=source_path,
            source_revision=source_revision,
            file_sha256=file_sha256,
        )
        for row in document
    ]
    seen: set[str] = set()
    for case in cases:
        if case.case_id in seen:
            raise AtBenchAdapterError(f"duplicate normalized case_id {case.case_id}")
        seen.add(case.case_id)
    if max_cases is None or max_cases == 0:
        return cases
    return select_atbench_mvp(cases, max_cases=max_cases, seed=seed)


def adapt_atbench_record(
    row: Mapping[str, Any],
    *,
    source_path: str | Path,
    source_revision: str,
    file_sha256: str,
) -> UnifiedCase:
    """Convert one current-release ATBench record without executing anything."""

    if not isinstance(row, Mapping):
        raise AtBenchAdapterError("ATBench record must be an object")
    source_id = _source_id(row.get("id", row.get("conv_id")))
    published_label = row.get("label")
    if (
        isinstance(published_label, bool)
        or not isinstance(published_label, int)
        or published_label not in {0, 1}
    ):
        raise AtBenchAdapterError(f"ATBench record {source_id}: label must be 0 or 1")
    if not isinstance(source_revision, str) or not source_revision.strip():
        raise AtBenchAdapterError("source_revision must be non-empty text")
    normalized_sha = str(file_sha256).strip().lower()
    if len(normalized_sha) != 64 or any(char not in "0123456789abcdef" for char in normalized_sha):
        raise AtBenchAdapterError("file_sha256 must be a lowercase SHA-256 hex digest")

    warnings: list[dict[str, Any]] = []
    catalog, original_descriptions = _adapt_tool_catalog(row.get("tool_used"), source_id, warnings)
    trajectory = _single_trajectory(row.get("contents", row.get("content")), source_id)
    events, mapping_stats = _adapt_events(trajectory, source_id, catalog, warnings)
    user_messages = [event["content"] for event in events if event["type"] == "user_input"]
    if not user_messages:
        raise AtBenchAdapterError(f"ATBench record {source_id}: trajectory has no user message")

    if normalized_sha == ATBENCH_SOURCE_SHA256 and source_id in _KNOWN_LABEL_WARNINGS:
        warnings.append(
            _warning(
                "upstream_label_reason_conflict",
                _KNOWN_LABEL_WARNINGS[source_id],
                "label",
                source_record_id=source_id,
                published_label=published_label,
            )
        )

    exclusion_reasons = _sampling_exclusion_reasons(events, warnings)
    source_id_text = str(source_id)
    record_sha256 = hashlib.sha256(
        json.dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    case = UnifiedCase(
        schema_version=ATBENCH_SCHEMA_VERSION,
        case_id=f"atbench:v1:{source_id_text}",
        source={
            "benchmark": "ATBench",
            "release": "ATBench",
            "source_id": source_id_text,
            "split": "test",
            "revision": source_revision.strip(),
            "file_sha256": normalized_sha,
            "record_sha256": record_sha256,
            "path": Path(source_path).as_posix(),
        },
        task={
            "initial_user_message": user_messages[0],
            "user_message_count": len(user_messages),
        },
        tool_catalog=tuple(catalog),
        events=tuple(events),
        label={
            "published_label": int(published_label),
            "trajectory_label": "unsafe" if published_label == 1 else "safe",
            "risk_source": _text_or_empty(row.get("risk_source")),
            "failure_mode": _text_or_empty(row.get("failure_mode")),
            "real_world_harm": _text_or_empty(row.get("real_world_harm")),
            "reason": _text_or_empty(row.get("reason")),
            "original_tool_descriptions": original_descriptions,
        },
        metadata={
            "adapter_id": ATBENCH_ADAPTER_ID,
            "replay_support": "sequence_bridge_v1",
            "scoring_contract": "trajectory_safety_classification",
            "event_count": len(events),
            "tool_call_count": sum(event["type"] == "tool_call" for event in events),
            "user_message_count": len(user_messages),
            "sampling_eligible": not exclusion_reasons,
            "sampling_exclusion_reasons": exclusion_reasons,
            "adapter_mapping": mapping_stats,
            "validation_warnings": warnings,
        },
    )
    return UnifiedCase.from_dict(case.as_dict())


def select_atbench_mvp(
    cases: Sequence[UnifiedCase],
    *,
    max_cases: int = 20,
    seed: str | int = DEFAULT_SELECTION_SEED,
) -> list[UnifiedCase]:
    """Select a deterministic, label-balanced set from replayable cases."""

    if isinstance(max_cases, bool) or not isinstance(max_cases, int) or max_cases < 1:
        raise AtBenchAdapterError("max_cases must be a positive integer")
    eligible = [case for case in cases if case.metadata.get("sampling_eligible") is True]
    if max_cases > len(eligible):
        raise AtBenchAdapterError(
            f"requested {max_cases} cases but only {len(eligible)} are eligible for static replay"
        )
    if max_cases == 20:
        selected = _select_by_quotas(eligible, _SAFE_MVP_QUOTAS, published_label=0, seed=seed)
        selected.extend(_select_by_quotas(eligible, _UNSAFE_MVP_QUOTAS, published_label=1, seed=seed))
        return selected

    safe_quota = (max_cases + 1) // 2
    unsafe_quota = max_cases - safe_quota
    safe = sorted(
        (case for case in eligible if case.label["published_label"] == 0),
        key=lambda case: _selection_digest(case, seed),
    )
    unsafe = sorted(
        (case for case in eligible if case.label["published_label"] == 1),
        key=lambda case: _selection_digest(case, seed),
    )
    if len(safe) < safe_quota or len(unsafe) < unsafe_quota:
        raise AtBenchAdapterError("eligible ATBench cases cannot satisfy the requested label balance")
    return safe[:safe_quota] + unsafe[:unsafe_quota]


def detector_visible_case(case: UnifiedCase) -> dict[str, Any]:
    """Return only replay input; evaluator labels and provenance stay outside."""

    return {
        "task": copy.deepcopy(case.task),
        "tool_catalog": copy.deepcopy(list(case.tool_catalog)),
        "events": copy.deepcopy(list(case.events)),
    }


def _adapt_tool_catalog(
    value: Any,
    source_id: int,
    warnings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(value, list):
        raise AtBenchAdapterError(f"ATBench record {source_id}: tool_used must be an array")
    catalog: list[dict[str, Any]] = []
    originals: list[dict[str, Any]] = []
    definitions_by_name: dict[str, set[str]] = defaultdict(set)
    indices_by_name: dict[str, list[int]] = defaultdict(list)
    for index, raw_tool in enumerate(value):
        if not isinstance(raw_tool, Mapping):
            raise AtBenchAdapterError(f"ATBench record {source_id}: tool_used[{index}] must be an object")
        name = raw_tool.get("name")
        description = raw_tool.get("description", "")
        parameters = raw_tool.get("parameters", {})
        tool_source = raw_tool.get("_source", "")
        if not isinstance(name, str) or not name.strip():
            raise AtBenchAdapterError(f"ATBench record {source_id}: tool_used[{index}].name is required")
        if not isinstance(description, str) or not isinstance(parameters, Mapping) or not isinstance(tool_source, str):
            raise AtBenchAdapterError(
                f"ATBench record {source_id}: tool_used[{index}] has an invalid description, parameters, or _source"
            )
        observed = {
            "catalog_index": index,
            "name": name.strip(),
            "description": description,
            "parameters": copy.deepcopy(dict(parameters)),
            "_source": tool_source,
        }
        catalog.append(observed)
        definition = json.dumps(
            {key: observed[key] for key in ("description", "parameters", "_source")},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        definitions_by_name[observed["name"]].add(definition)
        indices_by_name[observed["name"]].append(index)

        if "_original_description" in raw_tool and raw_tool["_original_description"] is not None:
            original = raw_tool["_original_description"]
            if not isinstance(original, str):
                raise AtBenchAdapterError(
                    f"ATBench record {source_id}: tool_used[{index}]._original_description must be text"
                )
            originals.append(
                {"catalog_index": index, "name": observed["name"], "description": original}
            )

    for name, definitions in definitions_by_name.items():
        if len(definitions) > 1:
            warnings.append(
                _warning(
                    "same_tool_name_conflicting_definitions",
                    "The trajectory exposes multiple observed definitions for the same tool name.",
                    "tool_catalog",
                    tool_name=name,
                    catalog_indices=indices_by_name[name],
                )
            )
    return catalog, originals


def _adapt_events(
    trajectory: list[Any],
    source_id: int,
    catalog: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    pending: deque[tuple[str, str, int]] = deque()
    catalog_names = {item["name"] for item in catalog}
    call_ordinal = 0
    unmapped_items: list[dict[str, Any]] = []

    for raw_index, message in enumerate(trajectory):
        if not isinstance(message, Mapping):
            raise AtBenchAdapterError(
                f"ATBench record {source_id}: contents[0][{raw_index}] must be an object"
            )
        role = message.get("role")
        common = {
            "event_id": f"event_{len(events) + 1:08d}",
            "seq": len(events) + 1,
            "source_role": role,
            "raw_index": raw_index,
        }
        if role == "user":
            content = message.get("content")
            if not isinstance(content, str):
                raise AtBenchAdapterError(
                    f"ATBench record {source_id}: user content at index {raw_index} must be text"
                )
            events.append({**common, "type": "user_input", "content": content})
            continue

        if role == "environment":
            raw_content = copy.deepcopy(message.get("content"))
            tool_result, result_encoding = _decode_json_text(raw_content)
            if pending:
                call_id, tool_name, _call_index = pending.popleft()
            else:
                call_id, tool_name = None, ""
                warnings.append(
                    _warning(
                        "orphan_tool_result",
                        "Environment feedback has no preceding unmatched tool call.",
                        f"contents[0][{raw_index}]",
                        raw_index=raw_index,
                    )
                )
            events.append(
                {
                    **common,
                    "type": "tool_result",
                    "call_id": call_id,
                    "tool_name": tool_name,
                    "tool_result": tool_result,
                    "result_encoding": result_encoding,
                    "raw_content": raw_content,
                }
            )
            continue

        if role != "agent":
            raise AtBenchAdapterError(
                f"ATBench record {source_id}: unsupported role {role!r} at index {raw_index}"
            )

        thought = copy.deepcopy(message.get("thought"))
        if thought is None:
            warnings.append(
                _warning(
                    "null_agent_thought",
                    "The published agent event has a null thought field.",
                    f"contents[0][{raw_index}].thought",
                    raw_index=raw_index,
                )
            )
        elif not isinstance(thought, str):
            raise AtBenchAdapterError(
                f"ATBench record {source_id}: agent thought at index {raw_index} must be text or null"
            )
        raw_action = message.get("action")
        if not isinstance(raw_action, str) or not raw_action.strip():
            raise AtBenchAdapterError(
                f"ATBench record {source_id}: agent action at index {raw_index} must be non-empty text"
            )
        action = raw_action.strip()
        if action.startswith("Complete"):
            completion = _parse_json_object(
                action[len("Complete") :],
                f"ATBench record {source_id}: invalid Complete action at index {raw_index}",
            )
            response = completion.get("response", "")
            if not isinstance(response, str):
                response = json.dumps(response, ensure_ascii=False, sort_keys=True)
            events.append(
                {
                    **common,
                    "type": "assistant_output",
                    "content": response,
                    "thought": thought,
                    "completion": completion,
                    "raw_action": raw_action,
                }
            )
            continue

        parsed_action = _parse_json_object(
            action,
            f"ATBench record {source_id}: invalid tool action at index {raw_index}",
        )
        tool_name = parsed_action.get("name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise AtBenchAdapterError(
                f"ATBench record {source_id}: tool action at index {raw_index} has no name"
            )
        raw_arguments = parsed_action.get("arguments", {})
        arguments_encoding = "object"
        extra: dict[str, Any] = {}
        if isinstance(raw_arguments, Mapping):
            tool_args = copy.deepcopy(dict(raw_arguments))
        elif isinstance(raw_arguments, str):
            decoded = _parse_json_object(
                raw_arguments,
                f"ATBench record {source_id}: stringified arguments at index {raw_index} do not decode once to an object",
            )
            tool_args = decoded
            arguments_encoding = "json_string"
            extra["raw_arguments"] = raw_arguments
        else:
            raise AtBenchAdapterError(
                f"ATBench record {source_id}: arguments at index {raw_index} must be an object or JSON string"
            )
        call_ordinal += 1
        call_id = f"call_{call_ordinal:08d}"
        event = {
            **common,
            "type": "tool_call",
            "call_id": call_id,
            "tool_name": tool_name.strip(),
            "tool_args": tool_args,
            "arguments_encoding": arguments_encoding,
            "thought": thought,
            "raw_action": raw_action,
            **extra,
        }
        events.append(event)
        pending.append((call_id, tool_name.strip(), raw_index))
        if arguments_encoding == "json_string":
            warnings.append(
                _warning(
                    "stringified_tool_arguments",
                    "Tool arguments were a JSON string and were decoded exactly once into an object.",
                    f"contents[0][{raw_index}].action.arguments",
                    call_id=call_id,
                    raw_index=raw_index,
                )
            )
        if tool_name.strip() not in catalog_names:
            warnings.append(
                _warning(
                    "tool_call_not_in_catalog",
                    "A called tool name is absent from the trajectory's observed tool catalog.",
                    f"contents[0][{raw_index}].action.name",
                    call_id=call_id,
                    tool_name=tool_name.strip(),
                )
            )

    for call_id, tool_name, raw_index in pending:
        warnings.append(
            _warning(
                "missing_tool_result",
                "The published trajectory ends without environment feedback for this tool call.",
                f"contents[0][{raw_index}]",
                call_id=call_id,
                tool_name=tool_name,
            )
        )
    if not events or events[-1]["type"] != "assistant_output":
        warnings.append(
            _warning(
                "missing_terminal_completion",
                "The published trajectory does not end with a Complete action.",
                "contents[0]",
                terminal_event_type=events[-1]["type"] if events else None,
            )
        )
    _validate_event_sequence(events)
    # The current adapter either maps a source message to exactly one unified
    # event or fails loudly, so unmapped_items is normally empty; the record is
    # still published so coverage metrics can distinguish parsing from replay.
    mapping_stats = {
        "source_item_count": len(trajectory),
        "mapped_event_count": len(events),
        "unmapped_items": unmapped_items,
    }
    return events, mapping_stats


def _single_trajectory(value: Any, source_id: int) -> list[Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], list):
        raise AtBenchAdapterError(
            f"ATBench record {source_id}: contents must contain exactly one nested trajectory"
        )
    if not value[0]:
        raise AtBenchAdapterError(f"ATBench record {source_id}: trajectory must not be empty")
    return value[0]


def _sampling_exclusion_reasons(
    events: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> list[str]:
    reasons = [
        str(item["code"])
        for item in warnings
        if item.get("code") in _MVP_EXCLUDED_WARNING_CODES
    ]
    if len(events) > 10:
        reasons.append("event_count_exceeds_10")
    return list(dict.fromkeys(reasons))


def _select_by_quotas(
    cases: Sequence[UnifiedCase],
    quotas: Sequence[tuple[str, int]],
    *,
    published_label: int,
    seed: str | int,
) -> list[UnifiedCase]:
    selected: list[UnifiedCase] = []
    for risk_source, quota in quotas:
        candidates = sorted(
            (
                case
                for case in cases
                if case.label["published_label"] == published_label
                and case.label["risk_source"] == risk_source
            ),
            key=lambda case: _selection_digest(case, seed),
        )
        if len(candidates) < quota:
            raise AtBenchAdapterError(
                f"not enough eligible label={published_label} risk_source={risk_source} cases "
                f"for quota {quota}"
            )
        selected.extend(candidates[:quota])
    return selected


def _selection_digest(case: UnifiedCase, seed: str | int) -> str:
    value = "\0".join(
        (
            str(seed),
            str(case.source["revision"]),
            str(case.label["published_label"]),
            str(case.label["risk_source"]),
            str(case.source["source_id"]),
        )
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_event_sequence(events: Sequence[Mapping[str, Any]]) -> None:
    seen_calls: set[str] = set()
    for index, event in enumerate(events, start=1):
        if event.get("seq") != index or event.get("event_id") != f"event_{index:08d}":
            raise AtBenchAdapterError("events must have contiguous one-based seq and deterministic event_id")
        event_type = event.get("type")
        if event_type not in _EVENT_TYPES:
            raise AtBenchAdapterError(f"unsupported unified event type {event_type!r}")
        if event_type == "tool_call":
            call_id = event.get("call_id")
            if not isinstance(call_id, str) or call_id in seen_calls:
                raise AtBenchAdapterError("tool_call call_id must be a unique string")
            if not isinstance(event.get("tool_name"), str) or not isinstance(event.get("tool_args"), dict):
                raise AtBenchAdapterError("tool_call must contain string tool_name and object tool_args")
            seen_calls.add(call_id)
        elif event_type == "tool_result":
            call_id = event.get("call_id")
            if call_id is not None and call_id not in seen_calls:
                raise AtBenchAdapterError("tool_result references an unknown call_id")


def _warning(code: str, message: str, location: str, **details: Any) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "location": location,
        "details": copy.deepcopy(details),
    }


def _parse_json_object(value: str, context: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        try:
            parsed = json.loads(value, strict=False)
        except json.JSONDecodeError:
            raise AtBenchAdapterError(f"{context}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AtBenchAdapterError(f"{context}: decoded value must be an object")
    return copy.deepcopy(parsed)


def _decode_json_text(value: Any) -> tuple[Any, str]:
    if not isinstance(value, str):
        return copy.deepcopy(value), "native"
    try:
        return copy.deepcopy(json.loads(value)), "json_text"
    except json.JSONDecodeError:
        return value, "text"


def _source_id(value: Any) -> int:
    if not isinstance(value, bool) and isinstance(value, int) and value >= 1:
        return value
    if isinstance(value, str):
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return int(digest[:12], 16)
    raise AtBenchAdapterError("ATBench record id must be a positive integer or stable conversation id")


def _text_or_empty(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(_ROOT.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "ATBENCH_ADAPTER_ID",
    "ATBENCH_HF_REVISION",
    "ATBENCH_SCHEMA_VERSION",
    "ATBENCH_SOURCE_SHA256",
    "DEFAULT_SELECTION_SEED",
    "AtBenchAdapterError",
    "UnifiedCase",
    "adapt_atbench_record",
    "detector_visible_case",
    "load_atbench_cases",
    "select_atbench_mvp",
]
