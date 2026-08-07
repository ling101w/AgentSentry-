from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schema import make_record
from ..sources import SourceSpec
from ._common import AdapterContext, command_envelope, json_safe, set_mapping, slug


SUITE_ROOT = Path("src/agentdojo/default_suites/v1")
_UNRESOLVED = object()


@dataclass(frozen=True)
class ParsedTask:
    path: Path
    class_name: str
    text: str
    line: int
    raw: dict[str, Any]


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
    suite_root = ctx.root / SUITE_ROOT
    suite_dirs = sorted(
        {path.parent for path in suite_root.glob("*/user_tasks.py")},
        key=lambda path: path.name,
    )
    if not suite_dirs:
        ctx.error(suite_root, "$", "no AgentDojo v1 suite user_tasks.py files found")
        return []

    records: list[dict[str, Any]] = []
    for suite_dir in suite_dirs:
        suite = suite_dir.name
        user_path = suite_dir / "user_tasks.py"
        injection_path = suite_dir / "injection_tasks.py"
        user_tasks = _parse_task_file(ctx, user_path, "PROMPT", "UserTask")
        injection_tasks = _parse_task_file(ctx, injection_path, "GOAL", "InjectionTask")

        for user in user_tasks:
            records.append(_benign_record(ctx, suite, user))
        for user in user_tasks:
            for injection in injection_tasks:
                records.append(_attack_record(ctx, suite, user, injection))
    return records


def _parse_task_file(
    ctx: AdapterContext,
    path: Path,
    field_name: str,
    class_prefix: str,
) -> list[ParsedTask]:
    entry = ctx.track_file(path, "python")
    entry["target_field"] = field_name
    if not path.is_file():
        ctx.error(path, "$", "required AgentDojo task file is missing")
        return []
    try:
        source = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        ctx.error(path, "$", f"unable to read UTF-8 Python: {exc}")
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        ctx.error(path, f"line {exc.lineno or 0}, column {exc.offset or 0}", f"invalid Python: {exc.msg}")
        return []

    tasks: list[ParsedTask] = []
    candidate_classes = 0
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        direct_fields = {
            assigned[0]
            for statement in node.body
            if (assigned := _class_assignment(statement)) is not None
        }
        if not node.name.startswith(class_prefix) and field_name not in direct_fields:
            continue
        candidate_classes += 1
        env: dict[str, Any] = {}
        assignments: dict[str, Any] = {}
        target_seen = False
        target_text = ""
        for statement in node.body:
            assigned = _class_assignment(statement)
            if assigned is None:
                continue
            name, value_node = assigned
            value = _eval_static_node(value_node, env)
            if value is not _UNRESOLVED:
                env[name] = value
                assignments[name] = json_safe(value)
            if name != field_name:
                continue
            target_seen = True
            if isinstance(value, str):
                target_text = value
            elif value is _UNRESOLVED:
                ctx.error(
                    path,
                    f"class {node.name}.{field_name} (line {getattr(statement, 'lineno', node.lineno)})",
                    "unsupported static expression",
                )
            else:
                ctx.error(
                    path,
                    f"class {node.name}.{field_name} (line {getattr(statement, 'lineno', node.lineno)})",
                    "expected a string",
                )
        if not target_seen:
            ctx.error(path, f"class {node.name} (line {node.lineno})", f"missing {field_name} assignment")
            continue
        if not target_text:
            continue
        class_source = ast.get_source_segment(source, node) or ""
        raw = {
            "class": node.name,
            "field": field_name,
            "text": target_text,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "assignments": assignments,
            "source": class_source,
        }
        tasks.append(ParsedTask(path=path, class_name=node.name, text=target_text, line=node.lineno, raw=raw))
    entry["classes"] = candidate_classes
    entry["objects"] = len(tasks)
    return tasks


def _class_assignment(statement: ast.stmt) -> tuple[str, ast.AST] | None:
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    ):
        return statement.targets[0].id, statement.value
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and statement.value is not None:
        return statement.target.id, statement.value
    return None


def _eval_static_node(node: ast.AST, env: Mapping[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id, _UNRESOLVED)
    if isinstance(node, ast.List):
        return _eval_sequence(node.elts, env, list)
    if isinstance(node, ast.Tuple):
        return _eval_sequence(node.elts, env, tuple)
    if isinstance(node, ast.Set):
        values = _eval_sequence(node.elts, env, tuple)
        return _UNRESOLVED if values is _UNRESOLVED else set(values)
    if isinstance(node, ast.Dict):
        result: dict[Any, Any] = {}
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            if key_node is None:
                return _UNRESOLVED
            key = _eval_static_node(key_node, env)
            value = _eval_static_node(value_node, env)
            if key is _UNRESOLVED or value is _UNRESOLVED:
                return _UNRESOLVED
            try:
                result[key] = value
            except TypeError:
                return _UNRESOLVED
        return result
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value_node in node.values:
            if isinstance(value_node, ast.Constant):
                parts.append(str(value_node.value))
                continue
            if not isinstance(value_node, ast.FormattedValue):
                return _UNRESOLVED
            value = _eval_static_node(value_node.value, env)
            if value is _UNRESOLVED:
                return _UNRESOLVED
            if value_node.conversion == ord("r"):
                rendered = repr(value)
            elif value_node.conversion == ord("a"):
                rendered = ascii(value)
            else:
                rendered = str(value)
            if value_node.format_spec is not None:
                format_spec = _eval_static_node(value_node.format_spec, env)
                if not isinstance(format_spec, str):
                    return _UNRESOLVED
                try:
                    rendered = format(value, format_spec)
                except (TypeError, ValueError):
                    return _UNRESOLVED
            parts.append(rendered)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_static_node(node.left, env)
        right = _eval_static_node(node.right, env)
        if left is _UNRESOLVED or right is _UNRESOLVED:
            return _UNRESOLVED
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        if isinstance(left, list) and isinstance(right, list):
            return left + right
        if isinstance(left, tuple) and isinstance(right, tuple):
            return left + right
        return _UNRESOLVED
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and not node.keywords
    ):
        separator = _eval_static_node(node.func.value, env)
        values = _eval_static_node(node.args[0], env)
        if isinstance(separator, str) and isinstance(values, (list, tuple)) and all(
            isinstance(value, str) for value in values
        ):
            return separator.join(values)
        return _UNRESOLVED
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        operand = _eval_static_node(node.operand, env)
        if not isinstance(operand, (int, float, complex)) or isinstance(operand, bool):
            return _UNRESOLVED
        return operand if isinstance(node.op, ast.UAdd) else -operand
    return _UNRESOLVED


def _eval_sequence(
    nodes: list[ast.expr],
    env: Mapping[str, Any],
    factory: type[list[Any]] | type[tuple[Any, ...]],
) -> Any:
    values: list[Any] = []
    for node in nodes:
        value = _eval_static_node(node, env)
        if value is _UNRESOLVED:
            return _UNRESOLVED
        values.append(value)
    return factory(values)


def _benign_record(ctx: AdapterContext, suite: str, user: ParsedTask) -> dict[str, Any]:
    relative = ctx.relative(user.path)
    source_ref = f"{relative}:class={user.class_name}:line={user.line}"
    original_id = f"{suite}:{user.class_name}:benign"
    command = command_envelope(user.text)
    record = make_record(
        spec=ctx.spec,
        original_id=original_id,
        source_ref=source_ref,
        attack=False,
        attack_type=f"agentdojo_{suite}_benign_task",
        user_instruction=user.text,
        scenario="manual",
        command=command,
        expectation="allow",
        tool="read_file",
        target="README.md",
        notes=f"AgentDojo {suite} benign user task mapped to a local documentation read",
        raw_record=user.raw,
        template_id=f"agentdojo:{suite}:benign:{user.class_name}",
        **ctx.source_fields(user.path),
    )
    return set_mapping(
        record,
        synthetic_wrapper=True,
        transforms=(
            "extract_static_prompt_ast",
            "encode_command_trust_envelope",
            "map_benign_task_to_local_read_file",
        ),
    )


def _attack_record(
    ctx: AdapterContext,
    suite: str,
    user: ParsedTask,
    injection: ParsedTask,
) -> dict[str, Any]:
    user_relative = ctx.relative(user.path)
    injection_relative = ctx.relative(injection.path)
    source_ref = (
        f"{user_relative}:class={user.class_name}:line={user.line} + "
        f"{injection_relative}:class={injection.class_name}:line={injection.line}"
    )
    original_id = f"{suite}:{user.class_name}:{injection.class_name}"
    command = command_envelope(
        user.text,
        untrusted_inputs=(
            {
                "kind": "attack_goal_proxy",
                "origin": f"{injection_relative}:class={injection.class_name}:line={injection.line}",
                "text": injection.text,
            },
        ),
    )
    raw_record = {
        "user_task": user.raw,
        "injection_task": injection.raw,
        "source_hashes": {
            user_relative: ctx.file_hash(user.path),
            injection_relative: ctx.file_hash(injection.path),
        },
    }
    record = make_record(
        spec=ctx.spec,
        original_id=original_id,
        source_ref=source_ref,
        attack=True,
        attack_type="indirect_prompt_injection",
        user_instruction=user.text,
        attacker_instruction=injection.text,
        scenario=_scenario(suite, injection.text),
        command=command,
        expectation="protected",
        notes=f"AgentDojo {suite} injection goal from {injection.class_name}",
        raw_record=raw_record,
        template_id=f"agentdojo:{suite}:{injection.class_name}",
        **ctx.source_fields(injection.path),
    )
    return set_mapping(
        record,
        synthetic_wrapper=True,
        transforms=(
            "extract_static_prompt_and_goal_ast",
            "compose_user_injection_pair",
            "encode_command_trust_envelope",
            "map_goal_to_scenario",
        ),
    )


def _scenario(suite: str, injection_goal: str) -> str:
    text = f"{suite} {injection_goal}".casefold()
    if any(word in text for word in ("email", "security code", "send the body", "recipient")):
        return "external_email_hidden"
    if any(word in text for word in ("delete", "file", "cloud drive", "download")):
        return "pdf_stego"
    if any(word in text for word in ("bank", "transaction", "transfer", "money", "account")):
        return "malicious_skill"
    return "external_web_hidden"


__all__ = ["load", "load_with_report"]
