"""Deterministic ATBench tool-onboarding registry.

The registry is evaluator setup context, not benchmark ground truth.  It is
constructed only from the observed tool name, description, JSON schema and
source metadata.  Trajectory labels, tool results, benchmark reasons and
assistant outputs are deliberately unavailable to this module.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

REGISTRY_SCHEMA_VERSION = "agentsentry.atbench_tool_registry.v1"
REGISTRY_GENERATOR_VERSION = "1.1.0"
REGISTRY_SOURCE_POLICY = "catalog_only_no_labels_results_or_trajectory_outcomes"
ONBOARDING_MODES = frozenset({"registered", "zero_shot"})

_READ_PREFIXES = {
    "get",
    "list",
    "search",
    "check",
    "verify",
    "calculate",
    "generate",
    "retrieve",
    "lookup",
    "find",
    "convert",
    "estimate",
    "preview",
    "recommend",
    "analyze",
    "analyse",
    "download",
    "read",
    "fetch",
    "query",
    "inspect",
    "view",
}
_WRITE_PREFIXES = {
    "add",
    "apply",
    "approve",
    "archive",
    "ban",
    "block",
    "book",
    "buy",
    "cancel",
    "close",
    "comment",
    "create",
    "delete",
    "deliver",
    "deploy",
    "deposit",
    "disable",
    "edit",
    "enable",
    "enroll",
    "favorite",
    "favourite",
    "flag",
    "follow",
    "forward",
    "grant",
    "install",
    "invite",
    "issue",
    "like",
    "lock",
    "message",
    "mute",
    "notify",
    "open",
    "order",
    "patch",
    "pay",
    "pin",
    "place",
    "post",
    "publish",
    "purchase",
    "rate",
    "react",
    "refund",
    "register",
    "reject",
    "remove",
    "reply",
    "report",
    "reserve",
    "reschedule",
    "revoke",
    "schedule",
    "send",
    "set",
    "share",
    "sign",
    "sms",
    "start",
    "stop",
    "submit",
    "subscribe",
    "trade",
    "transfer",
    "trigger",
    "tweet",
    "unlock",
    "update",
    "upload",
    "vote",
    "withdraw",
}
_EXECUTE_TOKENS = {"shell", "exec", "execute", "command", "terminal", "powershell", "cmd", "run_code"}
_MEMORY_TOKENS = {"memory", "remember", "recall"}
_FILE_TOKENS = {"file", "document", "folder", "directory", "path"}
_EMAIL_TOKENS = {"email", "mail"}

_PUBLIC_LOCATION_TOKENS = {
    "weather",
    "forecast",
    "landmark",
    "landmarks",
    "location",
    "locations",
    "geolocation",
    "geo",
    "amenity",
    "amenities",
    "crime",
    "map",
    "route",
    "travel",
    "destination",
    "attraction",
    "attractions",
    "restaurant",
    "restaurants",
    "hotel",
    "hotels",
}
_PUBLIC_WEB_TOKENS = {
    "url",
    "domain",
    "website",
    "web",
    "safety",
    "reputation",
    "phishing",
    "news",
    "article",
    "public",
    "search",
}
_ACCOUNT_TOKENS = {
    "account",
    "coinbase",
    "wallet",
    "balance",
    "transaction",
    "transactions",
    "login",
    "activity",
    "order",
    "orders",
    "payment",
    "bank",
    "billing",
    "profile",
    "customer",
}
_ADMIN_TOKENS = {
    "user",
    "users",
    "group",
    "groups",
    "role",
    "roles",
    "permission",
    "permissions",
    "member",
    "members",
    "tenant",
    "organization",
    "organisation",
}
_SECURITY_CONTROL_TOKENS = {
    "firewall",
    "acl",
    "policy",
    "security_group",
    "securitygroup",
    "access_control",
    "accesscontrol",
    "rule",
    "rules",
}
_SECRET_RESOURCE_TOKENS = {
    "credential",
    "credentials",
    "secret",
    "secrets",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "token_store",
}
_CREDENTIAL_FIELD_RE = re.compile(
    r"(?:^|_)(?:access_?token|refresh_?token|api_?key|secret|password|passwd|authorization|auth_?token|bearer|credential|session_?token)(?:$|_)",
    re.I,
)
_TARGET_FIELD_RE = re.compile(
    r"(?:^|_)(?:url|uri|endpoint|host|domain|location|address|place|account_?id|order_?id|firewall_?id|group_?id|user_?id|email|recipient|target|resource_?id)(?:$|_)",
    re.I,
)
_PAYLOAD_FIELD_RE = re.compile(
    r"(?:^|_)(?:body|payload|data|content|message|text|attachment|file|document|comment|description)(?:$|_)",
    re.I,
)


class ToolRegistryError(ValueError):
    """Raised when a generated or reviewed tool registry is invalid."""


def build_tool_registry(catalogs: Iterable[Iterable[Mapping[str, Any]]]) -> dict[str, Any]:
    """Build one frozen registry from observed catalogs only.

    Identical definitions are deduplicated.  Conflicting definitions with the
    same tool name remain separate and are bound by ``catalog_fingerprint``.
    """

    descriptors: dict[tuple[str, str], dict[str, Any]] = {}
    for catalog in catalogs:
        for raw in catalog:
            observed = _validate_observed_tool(raw)
            fingerprint = catalog_fingerprint(observed)
            key = (_normalize_lookup_name(observed["name"]), fingerprint)
            descriptors.setdefault(key, classify_observed_tool(observed, fingerprint=fingerprint))
    registry = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "generator_version": REGISTRY_GENERATOR_VERSION,
        "source_policy": REGISTRY_SOURCE_POLICY,
        "tools": sorted(
            descriptors.values(),
            key=lambda item: (
                str(item["normalized_name"]),
                str(item["catalog_fingerprint"]),
            ),
        ),
    }
    registry["registry_sha256"] = registry_sha256(registry)
    validate_tool_registry(registry)
    return registry


def classify_observed_tool(
    raw: Mapping[str, Any], *, fingerprint: str | None = None
) -> dict[str, Any]:
    """Create a conservative simulated security manifest for one tool."""

    tool = _validate_observed_tool(raw)
    name = tool["name"]
    snake_name = normalize_tool_name(name)
    tokens = set(token for token in snake_name.split("_") if token)
    schema_fields = _schema_field_names(tool["parameters"])
    lowered_fields = {normalize_tool_name(field) for field in schema_fields}
    credential_fields = sorted(field for field in schema_fields if _CREDENTIAL_FIELD_RE.search(normalize_tool_name(field)))
    target_fields = sorted(field for field in schema_fields if _TARGET_FIELD_RE.search(normalize_tool_name(field)))
    payload_fields = sorted(field for field in schema_fields if _PAYLOAD_FIELD_RE.search(normalize_tool_name(field)))

    operation = _operation_for(tokens, snake_name, tool["description"])
    resource_type = _resource_type_for(tokens, lowered_fields, tool["description"])
    if operation == "unknown" and _looks_like_read_only_lookup(resource_type, credential_fields, payload_fields):
        operation = "read"
    elif operation in {"send", "update"} and resource_type in {"generic_api", "public_location_data", "public_web_data"} and not credential_fields and not payload_fields:
        operation = "read"
    sensitivity = _sensitivity_for(resource_type, operation, credential_fields)
    effect = _effect_for(operation, resource_type)
    canonical_tool = _canonical_tool(operation, resource_type, sensitivity)
    side_effects = _side_effects_for(canonical_tool, effect)

    confidence = _classification_confidence(tokens, operation, resource_type)
    can_exfiltrate = bool(
        canonical_tool == "send_email"
        or "network_write" in side_effects
        and (payload_fields or operation in {"send", "create", "update", "delete", "admin"})
    )
    accepts_sensitive = bool(credential_fields or sensitivity in {"secret", "user_private"} or payload_fields)
    caller_bound_read = (
        effect == "read_only"
        and sensitivity == "user_private"
        and not can_exfiltrate
        and not payload_fields
        # A read-only tool without a subject selector can only address the
        # authenticated/session caller. Authentication may be explicit in the
        # schema or supplied by the provider session.
        and (bool(credential_fields) or not target_fields)
    )
    requires_authorization = (
        effect in {"persistent_change", "privileged_change"}
        or sensitivity in {"secret", "user_private"}
        or can_exfiltrate
        or canonical_tool in {"send_email", "shell_exec", "write_file", "memory_write"}
        or confidence < 0.75
    )

    manifest = {
        "toolId": canonical_tool,
        "aliases": [name] if _normalize_lookup_name(name) != _normalize_lookup_name(canonical_tool) else [],
        "dataOrigins": [_data_origin_for(canonical_tool)],
        "sideEffects": side_effects,
        "acceptsSensitiveData": accepts_sensitive,
        "canExfiltrate": can_exfiltrate,
        "requiresExplicitAuthorization": requires_authorization,
        "defaultTrust": _default_trust_for(canonical_tool),
        # These declarations are derived only from the tool catalog. They
        # describe an authentication-bound read, never a permission to access
        # arbitrary accounts or to transmit user data.
        "accessScope": "caller_bound" if caller_bound_read else (
            "explicit_target" if target_fields else "unknown"
        ),
        "sensitiveInputHandling": "authentication_only" if caller_bound_read and credential_fields else (
            "business_payload" if payload_fields else "none"
        ),
        "credentialFields": credential_fields,
        "targetFields": target_fields,
        # Catalog text cannot reliably establish a data subject or business
        # purpose. Reviewed registries may replace these explicit unknowns.
        "subjectFields": [],
        "dataSubjects": ["unknown"],
        "purposeBinding": "unknown",
        "dataClassification": sensitivity,
    }
    return {
        "tool_name": name,
        "normalized_name": snake_name,
        "catalog_fingerprint": fingerprint or catalog_fingerprint(tool),
        "canonical_tool": canonical_tool,
        "operation": operation,
        "resource_type": resource_type,
        "effect": effect,
        "data_sensitivity": sensitivity,
        "credential_fields": credential_fields,
        "target_fields": target_fields,
        "payload_fields": payload_fields,
        "classification_source": "deterministic_catalog_heuristic",
        "confidence": round(confidence, 3),
        "manifest": manifest,
    }


def select_registry_for_catalog(
    registry: Mapping[str, Any], catalog: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Return the exact registry subset bound to one case catalog."""

    validated = validate_tool_registry(registry)
    by_key = {
        (_normalize_lookup_name(item["tool_name"]), item["catalog_fingerprint"]): item
        for item in validated["tools"]
    }
    selected_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in catalog:
        tool = _validate_observed_tool(raw)
        key = (_normalize_lookup_name(tool["name"]), catalog_fingerprint(tool))
        descriptor = by_key.get(key)
        if descriptor is None:
            raise ToolRegistryError(
                f"registered onboarding is missing exact tool definition: {tool['name']} ({key[1][:12]})"
            )
        selected_by_key.setdefault(key, copy.deepcopy(descriptor))
    selected = list(selected_by_key.values())
    subset = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "generator_version": str(validated["generator_version"]),
        "source_policy": str(validated["source_policy"]),
        "tools": sorted(
            selected,
            key=lambda item: (
                str(item["normalized_name"]),
                str(item["catalog_fingerprint"]),
            ),
        ),
    }
    subset["registry_sha256"] = registry_sha256(subset)
    return validate_tool_registry(subset)


def load_tool_registry(path: str | Path) -> dict[str, Any]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolRegistryError(f"failed to read tool registry {path}: {exc}") from exc
    if not isinstance(document, Mapping):
        raise ToolRegistryError("tool registry must be a JSON object")
    return validate_tool_registry(document)


def validate_tool_registry(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolRegistryError("tool registry must be an object")
    expected = {
        "schema_version",
        "generator_version",
        "source_policy",
        "tools",
        "registry_sha256",
    }
    if set(value) != expected:
        raise ToolRegistryError(
            f"tool registry fields mismatch; missing={sorted(expected - set(value))}, extra={sorted(set(value) - expected)}"
        )
    if value.get("schema_version") != REGISTRY_SCHEMA_VERSION:
        raise ToolRegistryError(f"unsupported tool registry schema: {value.get('schema_version')!r}")
    tools = value.get("tools")
    if not isinstance(tools, list):
        raise ToolRegistryError("tool registry tools must be an array")
    validated_tools = [_validate_descriptor(item, index) for index, item in enumerate(tools)]
    keys = [(_normalize_lookup_name(item["tool_name"]), item["catalog_fingerprint"]) for item in validated_tools]
    if len(keys) != len(set(keys)):
        raise ToolRegistryError("tool registry contains duplicate tool definition bindings")
    document = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "generator_version": _required_text(value.get("generator_version"), "generator_version"),
        "source_policy": _required_text(value.get("source_policy"), "source_policy"),
        "tools": copy.deepcopy(validated_tools),
        "registry_sha256": _required_sha256(value.get("registry_sha256"), "registry_sha256"),
    }
    computed = registry_sha256(document)
    if computed != document["registry_sha256"]:
        raise ToolRegistryError(
            f"tool registry SHA-256 mismatch: declared {document['registry_sha256']}, computed {computed}"
        )
    return document


def registry_sha256(registry: Mapping[str, Any]) -> str:
    committed = {
        "schema_version": registry.get("schema_version"),
        "generator_version": registry.get("generator_version"),
        "source_policy": registry.get("source_policy"),
        "tools": registry.get("tools"),
    }
    return hashlib.sha256(_canonical_json(committed).encode("utf-8")).hexdigest()


def catalog_fingerprint(raw: Mapping[str, Any]) -> str:
    tool = _validate_observed_tool(raw)
    committed = {
        "name": tool["name"],
        "description": tool["description"],
        "parameters": tool["parameters"],
        "_source": tool["_source"],
    }
    return hashlib.sha256(_canonical_json(committed).encode("utf-8")).hexdigest()


def normalize_tool_name(value: str) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value).strip())
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", text)
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "unknown_tool"


def _operation_for(tokens: set[str], snake_name: str, description: str) -> str:
    if tokens.intersection(_EXECUTE_TOKENS) or "run_code" in snake_name:
        return "execute"
    first = snake_name.split("_", 1)[0]
    if tokens.intersection(_MEMORY_TOKENS):
        return "read" if first in _READ_PREFIXES else "persist"
    if first in {"send", "forward", "reply", "deliver", "message", "sms", "tweet", "publish", "post"}:
        return "send"
    if first in _READ_PREFIXES or (first == "bulk" and tokens.intersection(_READ_PREFIXES)):
        operation = "read"
    elif first in _WRITE_PREFIXES:
        operation = "delete" if first in {"delete", "remove", "revoke", "cancel"} else "update"
    else:
        operation = "unknown"

    # Description is untrusted.  It may only raise risk, never lower it.
    desc = description.strip().lower()
    if operation in {"read", "unknown"} and re.match(
        r"^(?:create|update|delete|remove|send|post|upload|share|transfer|purchase|book|cancel|add|set|submit|register|trigger)\b",
        desc,
    ):
        return "update"
    return operation


def _resource_type_for(tokens: set[str], fields: set[str], description: str) -> str:
    field_tokens = {part for field in fields for part in field.split("_") if part}
    combined = tokens | field_tokens
    if tokens.intersection(_EXECUTE_TOKENS):
        return "shell"
    if tokens.intersection(_MEMORY_TOKENS):
        return "memory"
    # Name semantics outrank generic schema fields such as email/password.
    if tokens.intersection(_SECRET_RESOURCE_TOKENS):
        return "secret_store"
    if tokens.intersection(_SECURITY_CONTROL_TOKENS):
        return "security_control"
    if tokens.intersection(_ADMIN_TOKENS):
        return "identity_admin"
    if tokens.intersection(_ACCOUNT_TOKENS):
        return "account_data"
    if tokens.intersection(_FILE_TOKENS):
        return "file"
    if tokens.intersection(_EMAIL_TOKENS):
        return "email"
    if tokens.intersection(_PUBLIC_LOCATION_TOKENS):
        return "public_location_data"
    if tokens.intersection(_PUBLIC_WEB_TOKENS):
        return "public_web_data"

    if field_tokens.intersection(_SECRET_RESOURCE_TOKENS):
        return "secret_store"
    if field_tokens.intersection(_FILE_TOKENS):
        return "file"
    if field_tokens.intersection(_EMAIL_TOKENS):
        return "email"
    if field_tokens.intersection(_PUBLIC_LOCATION_TOKENS):
        return "public_location_data"
    if field_tokens.intersection(_PUBLIC_WEB_TOKENS):
        return "public_web_data"

    # For generic names, nouns from the description may raise sensitivity.  A
    # description can never turn an account/admin tool into a public tool.
    desc_tokens = set(normalize_tool_name(description).split("_"))
    if desc_tokens.intersection(_SECURITY_CONTROL_TOKENS):
        return "security_control"
    if desc_tokens.intersection(_ADMIN_TOKENS):
        return "identity_admin"
    if desc_tokens.intersection(_ACCOUNT_TOKENS):
        return "account_data"
    return "generic_api"


def _looks_like_read_only_lookup(
    resource_type: str,
    credential_fields: list[str],
    payload_fields: list[str],
) -> bool:
    return (
        resource_type in {"generic_api", "public_location_data", "public_web_data"}
        and not credential_fields
        and not payload_fields
    )


def _sensitivity_for(resource_type: str, operation: str, credential_fields: list[str]) -> str:
    if resource_type == "secret_store":
        return "secret"
    if resource_type in {"account_data", "identity_admin"}:
        return "user_private"
    if resource_type == "security_control":
        return "internal"
    if resource_type in {"public_location_data", "public_web_data"} and operation == "read":
        return "public"
    if credential_fields:
        return "user_private"
    return "internal" if operation != "read" else "public"


def _effect_for(operation: str, resource_type: str) -> str:
    if operation == "read":
        return "read_only"
    if operation == "execute":
        return "privileged_change"
    if resource_type in {"security_control", "identity_admin", "secret_store"}:
        return "privileged_change"
    if operation == "persist" or resource_type in {"file", "memory"}:
        return "persistent_change"
    return "external_side_effect"


def _canonical_tool(operation: str, resource_type: str, sensitivity: str) -> str:
    if resource_type == "shell":
        return "shell_exec"
    if resource_type == "memory":
        return "memory_read" if operation == "read" else "memory_write"
    if resource_type == "file":
        return "read_file" if operation == "read" else "write_file"
    if resource_type == "email" and operation in {"send", "update", "create"}:
        return "send_email"
    if operation == "read" and sensitivity == "public":
        return "external_api_read"
    return "call_api"


def _side_effects_for(canonical_tool: str, effect: str) -> list[str]:
    if canonical_tool == "shell_exec":
        return ["process_exec"]
    if canonical_tool == "read_file":
        return ["file_read"]
    if canonical_tool == "write_file":
        return ["file_write"]
    if canonical_tool == "memory_read":
        return ["persistent_state"]
    if canonical_tool == "memory_write":
        return ["persistent_state"]
    if canonical_tool == "external_api_read" or effect == "read_only":
        return ["network_read"]
    return ["network_write"]


def _data_origin_for(canonical_tool: str) -> str:
    if canonical_tool in {"read_file", "write_file"}:
        return "workspace"
    if canonical_tool in {"memory_read", "memory_write"}:
        return "memory"
    if canonical_tool == "send_email":
        return "email"
    return "third_party_api"


def _default_trust_for(canonical_tool: str) -> str:
    if canonical_tool in {"read_file", "write_file"}:
        return "workspace"
    return "external"


def _classification_confidence(tokens: set[str], operation: str, resource_type: str) -> float:
    score = 0.55
    if operation != "unknown":
        score += 0.2
    if resource_type != "generic_api":
        score += 0.2
    if tokens:
        score += 0.03
    return min(score, 0.98)


def _schema_field_names(schema: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(schema, Mapping):
        properties = schema.get("properties")
        if isinstance(properties, Mapping):
            for key, value in properties.items():
                names.add(str(key))
                names.update(_schema_field_names(value))
        for key in ("items", "allOf", "anyOf", "oneOf", "definitions", "$defs"):
            value = schema.get(key)
            if isinstance(value, list):
                for item in value:
                    names.update(_schema_field_names(item))
            else:
                names.update(_schema_field_names(value))
    elif isinstance(schema, list):
        for item in schema:
            names.update(_schema_field_names(item))
    return names


def _validate_observed_tool(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ToolRegistryError("observed tool must be an object")
    allowed = {"catalog_index", "name", "description", "parameters", "_source"}
    extra = set(raw) - allowed
    if extra:
        raise ToolRegistryError(f"observed tool contains unsupported fields: {sorted(extra)}")
    name = _required_text(raw.get("name"), "tool.name")
    description = raw.get("description", "")
    parameters = raw.get("parameters", {})
    source = raw.get("_source", "")
    if not isinstance(description, str):
        raise ToolRegistryError("tool.description must be text")
    if not isinstance(parameters, Mapping):
        raise ToolRegistryError("tool.parameters must be an object")
    if not isinstance(source, str):
        raise ToolRegistryError("tool._source must be text")
    return {
        "name": name,
        "description": description,
        "parameters": copy.deepcopy(dict(parameters)),
        "_source": source,
        "catalog_index": int(raw.get("catalog_index", 0)),
    }


def _validate_descriptor(raw: Any, index: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ToolRegistryError(f"tools[{index}] must be an object")
    expected = {
        "tool_name",
        "normalized_name",
        "catalog_fingerprint",
        "canonical_tool",
        "operation",
        "resource_type",
        "effect",
        "data_sensitivity",
        "credential_fields",
        "target_fields",
        "payload_fields",
        "classification_source",
        "confidence",
        "manifest",
    }
    if set(raw) != expected:
        raise ToolRegistryError(
            f"tools[{index}] fields mismatch; missing={sorted(expected - set(raw))}, extra={sorted(set(raw) - expected)}"
        )
    list_fields = ("credential_fields", "target_fields", "payload_fields")
    for field in list_fields:
        if not isinstance(raw.get(field), list) or not all(isinstance(item, str) for item in raw[field]):
            raise ToolRegistryError(f"tools[{index}].{field} must be an array of strings")
    confidence = raw.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= float(confidence) <= 1:
        raise ToolRegistryError(f"tools[{index}].confidence must be between 0 and 1")
    manifest = _validate_manifest(raw.get("manifest"), index)
    descriptor = {
        "tool_name": _required_text(raw.get("tool_name"), f"tools[{index}].tool_name"),
        "normalized_name": _required_text(raw.get("normalized_name"), f"tools[{index}].normalized_name"),
        "catalog_fingerprint": _required_sha256(raw.get("catalog_fingerprint"), f"tools[{index}].catalog_fingerprint"),
        "canonical_tool": _required_text(raw.get("canonical_tool"), f"tools[{index}].canonical_tool"),
        "operation": _required_text(raw.get("operation"), f"tools[{index}].operation"),
        "resource_type": _required_text(raw.get("resource_type"), f"tools[{index}].resource_type"),
        "effect": _required_text(raw.get("effect"), f"tools[{index}].effect"),
        "data_sensitivity": _required_text(raw.get("data_sensitivity"), f"tools[{index}].data_sensitivity"),
        "credential_fields": list(raw["credential_fields"]),
        "target_fields": list(raw["target_fields"]),
        "payload_fields": list(raw["payload_fields"]),
        "classification_source": _required_text(raw.get("classification_source"), f"tools[{index}].classification_source"),
        "confidence": round(float(confidence), 3),
        "manifest": manifest,
    }
    if _normalize_lookup_name(descriptor["tool_name"]) != _normalize_lookup_name(descriptor["normalized_name"]):
        raise ToolRegistryError(f"tools[{index}] normalized_name does not match tool_name")
    if descriptor["canonical_tool"] != manifest["toolId"]:
        raise ToolRegistryError(f"tools[{index}] canonical_tool differs from manifest.toolId")
    if descriptor["tool_name"] not in manifest["aliases"] and _normalize_lookup_name(descriptor["tool_name"]) != _normalize_lookup_name(manifest["toolId"]):
        raise ToolRegistryError(f"tools[{index}] manifest does not bind the observed tool name")
    return descriptor


def _validate_manifest(raw: Any, index: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ToolRegistryError(f"tools[{index}].manifest must be an object")
    expected = {
        "toolId",
        "aliases",
        "dataOrigins",
        "sideEffects",
        "acceptsSensitiveData",
        "canExfiltrate",
        "requiresExplicitAuthorization",
        "defaultTrust",
        "accessScope",
        "sensitiveInputHandling",
        "credentialFields",
        "targetFields",
        "subjectFields",
        "dataSubjects",
        "purposeBinding",
        "dataClassification",
    }
    if set(raw) != expected:
        raise ToolRegistryError(f"tools[{index}].manifest fields mismatch")
    for field in ("aliases", "dataOrigins", "sideEffects"):
        if not isinstance(raw.get(field), list) or not raw[field] or not all(isinstance(item, str) and item for item in raw[field]):
            if field == "aliases" and isinstance(raw.get(field), list) and not raw[field]:
                continue
            raise ToolRegistryError(f"tools[{index}].manifest.{field} must be an array of strings")
    for field in ("acceptsSensitiveData", "canExfiltrate", "requiresExplicitAuthorization"):
        if not isinstance(raw.get(field), bool):
            raise ToolRegistryError(f"tools[{index}].manifest.{field} must be boolean")
    if raw.get("accessScope") not in {"caller_bound", "explicit_target", "unscoped", "unknown"}:
        raise ToolRegistryError(f"tools[{index}].manifest.accessScope is invalid")
    if raw.get("sensitiveInputHandling") not in {"none", "authentication_only", "business_payload", "unknown"}:
        raise ToolRegistryError(f"tools[{index}].manifest.sensitiveInputHandling is invalid")
    for field in ("credentialFields", "targetFields", "subjectFields"):
        if not isinstance(raw.get(field), list) or not all(isinstance(item, str) and item for item in raw[field]):
            raise ToolRegistryError(f"tools[{index}].manifest.{field} must be an array of strings")
    if raw.get("dataClassification") not in {"public", "internal", "user_private", "secret", "unknown"}:
        raise ToolRegistryError(f"tools[{index}].manifest.dataClassification is invalid")
    if not isinstance(raw.get("dataSubjects"), list) or not raw["dataSubjects"] or any(item not in {"caller", "named_subject", "third_party", "unknown"} for item in raw["dataSubjects"]):
        raise ToolRegistryError(f"tools[{index}].manifest.dataSubjects is invalid")
    if raw.get("purposeBinding") not in {"task_bound", "operator_defined", "unknown"}:
        raise ToolRegistryError(f"tools[{index}].manifest.purposeBinding is invalid")
    return {
        "toolId": _required_text(raw.get("toolId"), f"tools[{index}].manifest.toolId"),
        "aliases": list(raw["aliases"]),
        "dataOrigins": list(raw["dataOrigins"]),
        "sideEffects": list(raw["sideEffects"]),
        "acceptsSensitiveData": bool(raw["acceptsSensitiveData"]),
        "canExfiltrate": bool(raw["canExfiltrate"]),
        "requiresExplicitAuthorization": bool(raw["requiresExplicitAuthorization"]),
        "defaultTrust": _required_text(raw.get("defaultTrust"), f"tools[{index}].manifest.defaultTrust"),
        "accessScope": str(raw["accessScope"]),
        "sensitiveInputHandling": str(raw["sensitiveInputHandling"]),
        "credentialFields": list(raw["credentialFields"]),
        "targetFields": list(raw["targetFields"]),
        "subjectFields": list(raw["subjectFields"]),
        "dataSubjects": list(raw["dataSubjects"]),
        "purposeBinding": str(raw["purposeBinding"]),
        "dataClassification": str(raw["dataClassification"]),
    }


def _required_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolRegistryError(f"{name} must be non-empty text")
    return value.strip()


def _required_sha256(value: Any, name: str) -> str:
    text = _required_text(value, name).lower()
    if not re.fullmatch(r"[a-f0-9]{64}", text):
        raise ToolRegistryError(f"{name} must be a lowercase SHA-256")
    return text


def _normalize_lookup_name(value: str) -> str:
    return normalize_tool_name(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
