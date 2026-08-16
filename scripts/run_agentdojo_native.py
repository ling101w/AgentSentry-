#!/usr/bin/env python3
"""Run a label-isolated native AgentDojo benchmark with controlled enforcement.

The official AgentDojo environment and evaluators remain authoritative. This
runner replaces only the final FunctionsRuntime boundary. AgentSentry mode
enforces the OpenClaw plugin policy; no-defense mode preserves the same bridge
and transcript while allowing every valid tool call to execute.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import random
import re
import secrets
from collections import Counter
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.agentdojo_adapter import (  # noqa: E402
    DETECTOR_PAYLOAD_FIELDS,
    JsonlNodeBridgeClient,
    make_guarded_runtime_class,
)
from agentsentry.native_protocol import (  # noqa: E402
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    SCHEMA_URI,
    canonical_json_bytes,
    canonical_sha256,
    compute_native_metrics,
    opaque_trial_id,
    validate_native_trial,
    validate_public_native_result,
)


ADAPTER_VERSION = "1.0.0"
AGENTDOJO_PACKAGE_VERSION = "0.1.35"
EXPANDED_SELECTION_VERSIONS = ("1.1.0", "1.2.0")
DEFAULT_SELECTION = ROOT / "evaluation" / "native" / "agentdojo_selection.json"
DETECTOR_EVENT_SCHEMA = ROOT / "evaluation" / "native" / "detector_event_schema.json"
TOOL_MANIFEST = ROOT / "openclaw-plugin" / "manifests" / "agentdojo-workspace-v1.2.2.json"
AGENTDYN_SOURCE = ROOT / "third_party" / "benchmarks" / "AgentDyn-main" / "src"
AGENTDYN_GITHUB_MANIFEST = ROOT / "openclaw-plugin" / "manifests" / "agentdyn-github-v1.0.json"
BRIDGE_SCRIPT = ROOT / "openclaw-plugin" / "scripts" / "agentdojo-policy-bridge.mjs"
AGENTWARD_BRIDGE_SCRIPT = ROOT / "scripts" / "agentward_agentdojo_bridge.mjs"
DEFAULT_OUTPUT_ROOT = ROOT / "runtime" / "agentdojo"
CANONICAL_RESULT = ROOT / "evaluation" / "native" / "agentdojo_results.json"
PRIVATE_FILE_NAMES = {
    "transcript": "detector-events.private.jsonl",
    "labels": "labels.private.jsonl",
    "trials": "trials.private.jsonl",
}
CHECKPOINT_FILE_NAME = "checkpoint.private.json"
CHECKPOINT_VERSION = 1
MAX_NATIVE_JUDGE_TIMEOUT_MS = 90_000
SEMANTIC_JUDGE_RETRYABLE_ERROR_CODE = "AGENTSENTRY_NATIVE_JUDGE_ERROR"
MODEL_ENVIRONMENTS = {
    "openai-compatible": ("OPENAI_COMPATIBLE_BASE_URL", "OPENAI_COMPATIBLE_API_KEY"),
    "local": (),
    "vllm_parsed": (),
}
DEFENSE_PROFILES = {
    "agentsentry": ("competition", "approval"),
    "agentward": ("agentward-default", "approval"),
    "no-defense": ("observe", "observe"),
}
AGENTSENTRY_POLICY_PROFILES = ("competition", "evidence-gated")


class NativeSetupError(RuntimeError):
    pass


@dataclass(frozen=True)
class TrialSpec:
    case_id: str
    user_task_id: str
    injection_task_id: str | None
    is_attack: bool
    seed: int
    repetition: int


class RecordingBridge:
    """Record exactly what crossed the detector process boundary."""

    def __init__(self, inner: JsonlNodeBridgeClient, events: list[dict[str, Any]]) -> None:
        self.inner = inner
        self.events = events

    def request(self, message: Mapping[str, Any]) -> Any:
        payload = message.get("payload")
        event: dict[str, Any] | None = None
        if payload is not None:
            if not isinstance(payload, Mapping) or set(payload) != set(DETECTOR_PAYLOAD_FIELDS):
                raise NativeSetupError("adapter attempted to cross the detector boundary with an invalid payload")
            event = {
                "event_id": f"event_{len(self.events) + 1:08d}",
                "recorded_at": datetime.now(UTC).isoformat(),
                "routing": {
                    "op": str(message.get("op") or ""),
                    "opaque_session_id": str(message.get("session_id") or ""),
                    "opaque_call_id": message.get("call_id") if isinstance(message.get("call_id"), str) else None,
                },
                "detector_input": _json_clone(payload),
                "detector_output": {},
            }
        try:
            result = self.inner.request(message)
        except Exception as exc:
            if event is not None:
                event["detector_output"] = {
                    "ok": False,
                    "error": _redact_error(exc),
                }
                self.events.append(event)
            raise
        if event is not None:
            event["detector_output"] = {"ok": True, "result": _json_clone(result)}
            self.events.append(event)
        return result


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        configure_native_judge(args)
        selection = load_selection(args.selection)
        configure_benchmark_environment(selection)
        source = source_for_selection(selection)
        api = load_agentdojo_api(source) if source is not None else load_agentdojo_api()
        suite = api.get_suite(selection["benchmark"]["benchmark_version"], selection["benchmark"]["suite"])
        validate_selection_against_suite(selection, suite)
        expected_profile, expected_enforcement = expected_bridge_posture(args)
        bridge_metadata = bridge_doctor(
            args.node,
            args.bridge_timeout,
            bridge_script=bridge_script_for(args),
            tool_manifest=tool_manifest_for_selection(selection),
            expected_profile=expected_profile,
            expected_enforcement=expected_enforcement,
            expected_plugin_id="agent-ward" if args.defense == "agentward" else None,
        )
        if args.doctor:
            print(json.dumps(doctor_report(selection, suite, bridge_metadata), ensure_ascii=False, indent=2))
            return 0
        if args.plan:
            print(json.dumps(plan_report(selection, suite, bridge_metadata), ensure_ascii=False, indent=2))
            return 0
        if args.contract:
            print(json.dumps(run_contract(suite, api, args), ensure_ascii=False, indent=2))
            return 0
        if not args.model:
            raise NativeSetupError("--model is required for a native model-backed run")
        ensure_model_credentials(args.model, args.model_id)
        if args.publish and (args.defense != "agentsentry" or selection["benchmark"]["name"] != "AgentDojo"):
            raise NativeSetupError("--publish is reserved for the AgentSentry defense result")
        if args.defense == "agentsentry" and not args.allow_no_judge and not os.getenv("AGENTSENTRY_API_KEY"):
            raise NativeSetupError(
                f"{args.policy_profile} profile requires AGENTSENTRY_API_KEY for semantic review; "
                "use --allow-no-judge only for a non-reportable deterministic development run"
            )
        dirty = git_worktree_dirty()
        if dirty is not False and not args.allow_dirty:
            raise NativeSetupError(
                "native evaluation requires a clean Git worktree with a resolvable HEAD; "
                "use --allow-dirty only for adapter development"
            )
        return run_native(selection, suite, api, bridge_metadata, args, dirty is not False)
    except NativeSetupError as exc:
        print(f"AgentDojo native setup error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run AgentDojo or AgentDyn at the native FunctionsRuntime boundary with AgentSentry."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--doctor", action="store_true", help="Check optional dependencies, suite contract, and the Node policy bridge.")
    mode.add_argument("--plan", action="store_true", help="Validate and print the frozen selection without creating a model client.")
    mode.add_argument("--contract", action="store_true", help="Run one real AgentDojo read-only task through the bridge without an LLM or credentials.")
    parser.add_argument("--selection", type=Path, default=DEFAULT_SELECTION)
    parser.add_argument(
        "--defense",
        choices=sorted(DEFENSE_PROFILES),
        default="agentsentry",
        help="Enforce AgentSentry or AgentWard decisions, or run the same native pipeline without enforcement.",
    )
    parser.add_argument(
        "--policy-profile",
        choices=AGENTSENTRY_POLICY_PROFILES,
        default="competition",
        help="AgentSentry policy profile to enforce; no-defense always uses its fixed observe profile.",
    )
    parser.add_argument("--model", help="AgentDojo model identifier. Required only for a real run.")
    parser.add_argument("--model-id", help="Provider model id for local or openai-compatible AgentDojo models.")
    parser.add_argument(
        "--openai-compatible-system-role",
        choices=("developer", "system"),
        default="developer",
        help=(
            "Role used for AgentDojo system messages on OpenAI-compatible providers; "
            "use system for endpoints that reject OpenAI's developer role."
        ),
    )
    parser.add_argument("--node", default="node", help="Node executable used by the isolated policy bridge.")
    parser.add_argument("--bridge-timeout", type=float, default=20.0)
    parser.add_argument("--provider-timeout-seconds", type=float, default=90.0, help="Timeout for each model-provider request.")
    parser.add_argument("--provider-max-retries", type=int, default=2, help="Provider retries using the SDK's exponential backoff.")
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--resume", type=Path, help="Resume an existing native run directory from its private checkpoint.")
    parser.add_argument("--retry-errors", action="store_true", help="When resuming, rerun checkpointed error trials instead of skipping them.")
    parser.add_argument(
        "--retry-judge-failures",
        action="store_true",
        help="When resuming, rerun only trials containing a requested semantic Judge call that returned no valid result.",
    )
    parser.add_argument("--max-trials", type=int, help="Development-only prefix limit; the result remains partial.")
    parser.add_argument("--allow-dirty", action="store_true", help="Allow a non-reportable development run from a dirty worktree.")
    parser.add_argument("--allow-no-judge", action="store_true", help="Disable semantic Judge and mark the run non-reportable.")
    parser.add_argument("--judge-base-url", help="OpenAI-compatible semantic Judge base URL (never written with its API key).")
    parser.add_argument("--judge-model", help="Semantic Judge model id used by the isolated policy bridge.")
    parser.add_argument("--judge-timeout-ms", type=int, help="Semantic Judge timeout from 500 to 90000 milliseconds.")
    parser.add_argument("--publish", action="store_true", help="Replace the canonical result only after a clean complete run.")
    return parser


def load_selection(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise NativeSetupError(f"selection file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise NativeSetupError(f"selection file is invalid JSON: {exc}") from exc
    base_keys = {
        "$schema",
        "selection_version",
        "benchmark",
        "attack",
        "seed_scope",
        "seeds",
        "benign_task_ids",
        "attack_pairs",
        "expected",
    }
    if not isinstance(payload, dict):
        raise NativeSetupError("selection must be a JSON object")
    selection_version = str(payload.get("selection_version"))
    expanded = selection_version in EXPANDED_SELECTION_VERSIONS
    expected_keys = base_keys | ({"sampling", "coverage"} if expanded else set())
    if set(payload) != expected_keys:
        version_name = (
            f"native-expanded selection {'/'.join(version.rsplit('.', 1)[0] for version in EXPANDED_SELECTION_VERSIONS)}"
            if expanded
            else "native selection v1"
        )
        raise NativeSetupError(f"selection must use the exact {version_name} fields")
    benchmark = payload.get("benchmark")
    if not isinstance(benchmark, dict) or set(benchmark) != {
        "name", "package_version", "benchmark_version", "source_commit", "suite"
    }:
        raise NativeSetupError("selection benchmark metadata is incomplete")
    if benchmark["name"] not in {"AgentDojo", "AgentDyn"} or benchmark["package_version"] != AGENTDOJO_PACKAGE_VERSION:
        raise NativeSetupError("selection must be pinned to AgentDojo or AgentDyn on package 0.1.35")
    if not re.fullmatch(r"[0-9a-f]{40}", str(benchmark["source_commit"])):
        raise NativeSetupError("selection source_commit must be a full Git SHA-1")
    seeds = payload.get("seeds")
    expected_seed_count = 1 if expanded else 3
    if not isinstance(seeds, list) or len(seeds) != expected_seed_count or any(type(seed) is not int or seed < 0 for seed in seeds):
        raise NativeSetupError(
            "expanded selection must contain one harness seed" if expanded
            else "selection must contain exactly three non-negative integer seeds"
        )
    if len(set(seeds)) != len(seeds):
        raise NativeSetupError("selection seeds must be unique")
    benign = payload.get("benign_task_ids")
    pairs = payload.get("attack_pairs")
    if not isinstance(benign, list) or not benign or len(set(benign)) != len(benign):
        raise NativeSetupError("selection must contain unique benign task ids")
    if not expanded and len(benign) != 20:
        raise NativeSetupError("selection must contain 20 unique benign task ids")
    if not isinstance(pairs, list) or not pairs or (not expanded and len(pairs) != 20):
        raise NativeSetupError(
            "selection must contain 20 attack pairs, not a task cross product"
            if not expanded else "expanded selection must contain unique attack pairs"
        )
    pair_keys: set[tuple[str, str]] = set()
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != {"user_task_id", "injection_task_id"}:
            raise NativeSetupError("each attack pair must contain user_task_id and injection_task_id")
        key = (str(pair["user_task_id"]), str(pair["injection_task_id"]))
        if key in pair_keys:
            raise NativeSetupError(f"duplicate attack pair: {key}")
        pair_keys.add(key)
    expected = payload.get("expected")
    expected_counts = {
        "benign_cases": len(benign),
        "attack_cases": len(pairs),
        "unique_cases": len(benign) + len(pairs),
        "trials": (len(benign) + len(pairs)) * len(seeds),
    }
    if expected != expected_counts:
        raise NativeSetupError(f"selection expected counts must equal {expected_counts}")
    if expanded:
        sampling = payload.get("sampling")
        if not isinstance(sampling, dict) or sampling != {
            "mode": "one_generation_per_unique_case",
            "repeats": 1,
            "harness_seed": seeds[0],
            "provider_generation_seed": "not_exposed_by_agentdojo_0.1.35",
        }:
            raise NativeSetupError("expanded selection sampling must declare one generation per case")
        if not isinstance(payload.get("coverage"), dict):
            raise NativeSetupError("expanded selection coverage metadata is required")
    return payload


def source_for_selection(selection: Mapping[str, Any]) -> Path | None:
    if selection["benchmark"]["name"] != "AgentDyn":
        return None
    if not AGENTDYN_SOURCE.is_dir():
        raise NativeSetupError(f"AgentDyn source tree not found: {AGENTDYN_SOURCE}")
    return AGENTDYN_SOURCE


def tool_manifest_for_selection(selection: Mapping[str, Any]) -> Path:
    if selection["benchmark"]["name"] == "AgentDyn":
        path = AGENTDYN_GITHUB_MANIFEST
    else:
        suite = str(selection["benchmark"]["suite"])
        path = ROOT / "openclaw-plugin" / "manifests" / f"agentdojo-{suite}-v1.2.2.json"
    if not path.is_file():
        raise NativeSetupError(f"tool security manifest not found: {path}")
    return path


def configure_benchmark_environment(selection: Mapping[str, Any]) -> None:
    manifest = tool_manifest_for_selection(selection)
    os.environ["AGENTSENTRY_NATIVE_MANIFEST"] = str(manifest.resolve())
    os.environ["AGENTSENTRY_NATIVE_BENCHMARK"] = str(selection["benchmark"]["name"])


def load_agentdojo_api(source: Path | None = None) -> SimpleNamespace:
    try:
        if source is not None:
            source_text = str(source.resolve())
            if source_text not in sys.path:
                sys.path.insert(0, source_text)
        package_version = importlib.metadata.version("agentdojo")
        if package_version != AGENTDOJO_PACKAGE_VERSION:
            raise NativeSetupError(
                f"AgentDojo {AGENTDOJO_PACKAGE_VERSION} is required; installed version is {package_version}"
            )
        from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
        from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
        from agentdojo.attacks import load_attack
        from agentdojo.attacks.base_attacks import MODEL_NAMES as AttackModelNames
        from agentdojo.functions_runtime import FunctionsRuntime
        from agentdojo.models import ModelsEnum
        from agentdojo.task_suite.load_suites import get_suite
        from openai import OpenAI
    except NativeSetupError:
        raise
    except Exception as exc:
        raise NativeSetupError(
            "AgentDojo/AgentDyn native support is not installed; run: "
            'python -m pip install -e ".[native-agentdojo]"'
        ) from exc
    return SimpleNamespace(
        AgentPipeline=AgentPipeline,
        BasePipelineElement=BasePipelineElement,
        PipelineConfig=PipelineConfig,
        GroundTruthPipeline=GroundTruthPipeline,
        OpenAILLM=OpenAILLM,
        ToolsExecutionLoop=ToolsExecutionLoop,
        OpenAI=OpenAI,
        AttackModelNames=AttackModelNames,
        FunctionsRuntime=FunctionsRuntime,
        ModelsEnum=ModelsEnum,
        get_suite=get_suite,
        load_attack=load_attack,
        package_version=package_version,
    )


def validate_selection_against_suite(selection: Mapping[str, Any], suite: Any) -> None:
    user_ids = set(suite.user_tasks)
    injection_ids = set(suite.injection_tasks)
    selected_users = set(selection["benign_task_ids"])
    selected_users.update(pair["user_task_id"] for pair in selection["attack_pairs"])
    selected_injections = {pair["injection_task_id"] for pair in selection["attack_pairs"]}
    missing_users = sorted(selected_users - user_ids)
    missing_injections = sorted(selected_injections - injection_ids)
    if missing_users or missing_injections:
        raise NativeSetupError(
            f"selection does not match installed suite; missing users={missing_users}, injections={missing_injections}"
        )

    manifest_path = tool_manifest_for_selection(selection)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("agentdojo") != {
        "package_version": selection["benchmark"]["package_version"],
        "benchmark_version": selection["benchmark"]["benchmark_version"],
        "suite": selection["benchmark"]["suite"],
        "source_commit": selection["benchmark"]["source_commit"],
    }:
        raise NativeSetupError("tool security manifest benchmark pin differs from selection")
    registered: set[str] = set()
    for item in manifest.get("manifests", []):
        if isinstance(item, dict):
            registered.add(str(item.get("toolId") or ""))
            registered.update(str(alias) for alias in item.get("aliases", []) if isinstance(alias, str))
    suite_tools = {str(tool.name) for tool in suite.tools}
    missing_manifests = sorted(suite_tools - registered)
    if missing_manifests:
        raise NativeSetupError(f"workspace tools missing signed security semantics: {missing_manifests}")

    # A selection that claims complete Cartesian coverage must actually contain
    # every suite user task and every user_task x injection_task pair; the
    # coverage document is not self-certifying.
    coverage = selection.get("coverage")
    algorithm = str((coverage or {}).get("selection_algorithm") or "")
    if "Cartesian product" in algorithm:
        suite_user_ids = sorted(str(task_id) for task_id in suite.user_tasks)
        if sorted(str(task_id) for task_id in selection["benign_task_ids"]) != suite_user_ids:
            raise NativeSetupError(
                "selection claims complete Cartesian coverage but benign_task_ids "
                "do not equal the full suite user task list"
            )
        expected_pairs = {
            (user_id, injection_id)
            for user_id in suite_user_ids
            for injection_id in sorted(str(task_id) for task_id in suite.injection_tasks)
        }
        actual_pairs = {
            (str(pair["user_task_id"]), str(pair["injection_task_id"]))
            for pair in selection["attack_pairs"]
        }
        if actual_pairs != expected_pairs:
            missing = sorted(expected_pairs - actual_pairs)
            extra = sorted(actual_pairs - expected_pairs)
            raise NativeSetupError(
                "selection claims complete Cartesian coverage but attack_pairs are "
                f"incomplete: missing={missing[:5]} extra={extra[:5]}"
            )
    if isinstance(coverage, Mapping):
        injection_counts = coverage.get("injection_task_counts")
        if isinstance(injection_counts, Mapping):
            actual_counts = Counter(str(pair["injection_task_id"]) for pair in selection["attack_pairs"])
            declared = {str(key): int(value) for key, value in injection_counts.items()}
            if declared != dict(actual_counts):
                raise NativeSetupError("coverage.injection_task_counts does not match attack_pairs")
        user_counts = coverage.get("attack_user_task_counts")
        if isinstance(user_counts, Mapping):
            actual_counts = Counter(str(pair["user_task_id"]) for pair in selection["attack_pairs"])
            declared = {str(key): int(value) for key, value in user_counts.items()}
            if declared != dict(actual_counts):
                raise NativeSetupError("coverage.attack_user_task_counts does not match attack_pairs")


def bridge_doctor(
    node: str,
    timeout: float,
    *,
    bridge_script: Path = BRIDGE_SCRIPT,
    tool_manifest: Path = TOOL_MANIFEST,
    expected_profile: str = "competition",
    expected_enforcement: str = "approval",
    expected_plugin_id: str | None = None,
) -> dict[str, Any]:
    if timeout <= 0:
        raise NativeSetupError("--bridge-timeout must be greater than zero")
    if not bridge_script.exists():
        raise NativeSetupError(f"Node policy bridge does not exist: {bridge_script}")
    if bridge_script == BRIDGE_SCRIPT and not (ROOT / "openclaw-plugin" / "dist" / "config.js").exists():
        raise NativeSetupError("OpenClaw plugin bridge is not built; run: npm --prefix openclaw-plugin run build")
    try:
        with JsonlNodeBridgeClient([node, str(bridge_script)], timeout=timeout) as bridge:
            result = bridge.request({"op": "ping"})
    except Exception as exc:
        raise NativeSetupError(f"AgentSentry Node policy bridge failed: {_redact_error(exc)}") from exc
    if not isinstance(result, dict) or result.get("bridge_version") != ADAPTER_VERSION:
        raise NativeSetupError("AgentSentry Node policy bridge returned an incompatible version")
    if result.get("profile") != expected_profile:
        raise NativeSetupError(f"AgentSentry Node policy bridge is not using the {expected_profile} profile")
    if result.get("enforcement_mode") != expected_enforcement:
        raise NativeSetupError(
            f"AgentSentry Node policy bridge is not using {expected_enforcement} enforcement"
        )
    if expected_plugin_id is not None and result.get("plugin_id") != expected_plugin_id:
        raise NativeSetupError(f"Node policy bridge did not load expected plugin {expected_plugin_id}")
    if result.get("manifest_file_sha256") != sha256_file(tool_manifest):
        raise NativeSetupError("Node bridge tool manifest hash differs from the frozen manifest")
    return result


def doctor_report(selection: Mapping[str, Any], suite: Any, bridge: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "ready",
        "agentdojo_package_version": AGENTDOJO_PACKAGE_VERSION,
        "benchmark_name": selection["benchmark"]["name"],
        "benchmark_version": selection["benchmark"]["benchmark_version"],
        "suite": suite.name,
        "suite_user_tasks": len(suite.user_tasks),
        "suite_injection_tasks": len(suite.injection_tasks),
        "suite_tools": len(suite.tools),
        "selection_sha256": canonical_sha256(selection),
        "tool_manifest_sha256": sha256_file(tool_manifest_for_selection(selection)),
        "bridge": bridge,
        "model_client_created": False,
        "credentials_read": False,
    }


def plan_report(selection: Mapping[str, Any], suite: Any, bridge: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "plan_validated_not_executed",
        "native_boundary": "agentdojo.FunctionsRuntime.run_function",
        "suite": suite.name,
        "benign_cases": len(selection["benign_task_ids"]),
        "attack_pairs": len(selection["attack_pairs"]),
        "attack": selection["attack"],
        "seeds": selection["seeds"],
        "seed_scope": selection["seed_scope"],
        "expected_trials": selection["expected"]["trials"],
        "labels_visible_to_detector": False,
        "detector_input_fields": sorted(DETECTOR_PAYLOAD_FIELDS),
        "selection_sha256": canonical_sha256(selection),
        "bridge_profile": bridge["profile"],
        "manifest_mapping_version": bridge.get("manifest_mapping_version"),
        "model_client_created": False,
    }


def run_contract(suite: Any, api: SimpleNamespace, args: argparse.Namespace) -> dict[str, Any]:
    """Execute a real AgentDojo task with its official ground-truth pipeline.

    This is a wiring contract, not a benchmark score: it proves the official
    environment, runtime and utility evaluator are reached without creating a
    model client or exposing an injection label to the detector child.
    """

    contract_task_id = "user_task_14" if suite.name == "github" else "user_task_0"
    task = suite.user_tasks[contract_task_id]
    user_message = str(task.PROMPT)
    session_id = f"trial_{secrets.token_hex(12)}"
    events: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    bridge = JsonlNodeBridgeClient(
        [args.node, str(bridge_script_for(args))],
        timeout=args.bridge_timeout,
    )
    recording = RecordingBridge(bridge, events)
    runtime_class = make_guarded_runtime_class(
        api.FunctionsRuntime,
        recording,
        user_message=user_message,
        session_id=session_id,
        record_sink=lambda record: records.append(dict(record)),
    )
    try:
        utility, security = suite.run_task_with_pipeline(
            api.GroundTruthPipeline(task),
            task,
            injection_task=None,
            injections={},
            runtime_class=runtime_class,
        )
        recording.request({"op": "end", "session_id": session_id})
    except Exception as exc:
        raise NativeSetupError(f"native AgentDojo contract failed: {_redact_error(exc)}") from exc
    finally:
        bridge.close()

    if not utility or security is not True:
        raise NativeSetupError("official AgentDojo contract task did not pass its utility evaluator")
    if not records or not any(record.get("executed") for record in records):
        raise NativeSetupError("native AgentDojo contract did not execute a supervised tool")
    if any(record.get("bridge_error") or record.get("after_feedback_error") for record in records):
        raise NativeSetupError("native AgentDojo contract recorded a detector bridge failure")
    if any(set(event["detector_input"]) != set(DETECTOR_PAYLOAD_FIELDS) for event in events):
        raise NativeSetupError("native AgentDojo contract crossed an invalid detector envelope")

    return {
        "status": "native_contract_passed",
        "benchmark_score": None,
        "benchmark_score_published": False,
        "suite": suite.name,
        "task_kind": "official_ground_truth_read_only_contract",
        "utility_evaluator_passed": True,
        "tool_calls": [
            {
                "tool_name": record["tool_name"],
                "decision": record["decision"],
                "executed": record["executed"],
            }
            for record in records
        ],
        "detector_event_count": len(events),
        "detector_input_fields": sorted(DETECTOR_PAYLOAD_FIELDS),
        "labels_visible_to_detector": False,
        "model_client_created": False,
        "credentials_read": False,
    }


def ensure_model_credentials(model: str, model_id: str | None) -> None:
    if model == "openai-compatible" and not model_id:
        raise NativeSetupError("--model-id is required for the openai-compatible provider")
    required = MODEL_ENVIRONMENTS.get(model)
    if required is None:
        if model.startswith("gpt-") or model.startswith("o1") or model.startswith("o3"):
            required = ("OPENAI_API_KEY",)
        elif model.startswith("claude-"):
            required = ("ANTHROPIC_API_KEY",)
        elif model.startswith("command-"):
            required = ("COHERE_API_KEY",)
        elif model.startswith("gemini-"):
            required = ("GCP_PROJECT", "GCP_LOCATION")
        else:
            required = ("TOGETHER_API_KEY",)
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise NativeSetupError(f"model provider credentials are missing: {', '.join(missing)}")


def configure_native_judge(args: argparse.Namespace) -> None:
    defense = getattr(args, "defense", "agentsentry")
    policy_profile = getattr(args, "policy_profile", "competition")
    overrides = (args.judge_base_url, args.judge_model, args.judge_timeout_ms)
    if defense in {"no-defense", "agentward"}:
        if policy_profile != "competition":
            raise NativeSetupError(f"--policy-profile cannot be used with --defense {defense}")
        if args.allow_no_judge:
            raise NativeSetupError(f"--allow-no-judge is redundant with --defense {defense}")
        if any(value is not None for value in overrides):
            raise NativeSetupError(f"semantic Judge overrides cannot be used with --defense {defense}")
        if defense == "agentward":
            os.environ.pop("AGENTSENTRY_NATIVE_PROFILE", None)
            os.environ.pop("AGENTSENTRY_NATIVE_DISABLE_JUDGE", None)
            return
        os.environ["AGENTSENTRY_NATIVE_PROFILE"] = "observe"
        os.environ["AGENTSENTRY_NATIVE_DISABLE_JUDGE"] = "1"
        return
    if defense != "agentsentry":
        raise NativeSetupError(f"unsupported native defense: {defense}")
    if policy_profile not in AGENTSENTRY_POLICY_PROFILES:
        raise NativeSetupError(f"unsupported AgentSentry policy profile: {policy_profile}")
    os.environ["AGENTSENTRY_NATIVE_PROFILE"] = policy_profile
    if args.allow_no_judge and any(value is not None for value in overrides):
        raise NativeSetupError("semantic Judge overrides cannot be combined with --allow-no-judge")
    if args.allow_no_judge:
        os.environ["AGENTSENTRY_NATIVE_DISABLE_JUDGE"] = "1"
    else:
        os.environ.pop("AGENTSENTRY_NATIVE_DISABLE_JUDGE", None)
    if args.judge_base_url is not None:
        base_url = args.judge_base_url.strip().rstrip("/")
        if not re.match(r"^https?://", base_url, re.IGNORECASE):
            raise NativeSetupError("--judge-base-url must be an http(s) URL")
        os.environ["AGENTSENTRY_NATIVE_JUDGE_BASE_URL"] = base_url
    if args.judge_model is not None:
        model = args.judge_model.strip()
        if not model:
            raise NativeSetupError("--judge-model cannot be empty")
        os.environ["AGENTSENTRY_NATIVE_JUDGE_MODEL"] = model
    if args.judge_timeout_ms is not None:
        if not 500 <= args.judge_timeout_ms <= MAX_NATIVE_JUDGE_TIMEOUT_MS:
            raise NativeSetupError(
                f"--judge-timeout-ms must be between 500 and {MAX_NATIVE_JUDGE_TIMEOUT_MS}"
            )
        os.environ["AGENTSENTRY_NATIVE_JUDGE_TIMEOUT_MS"] = str(args.judge_timeout_ms)


def create_pipeline_llm(
    api: SimpleNamespace,
    model: str,
    model_id: str | None,
    *,
    timeout_seconds: float = 90.0,
    max_retries: int = 2,
    system_role: str = "developer",
) -> Any:
    if model == "openai-compatible":
        if not model_id:
            raise NativeSetupError("--model-id is required for the openai-compatible provider")
        if system_role not in {"developer", "system"}:
            raise NativeSetupError("OpenAI-compatible system role must be developer or system")
        client = api.OpenAI(
            api_key=os.environ["OPENAI_COMPATIBLE_API_KEY"].strip(),
            base_url=os.environ["OPENAI_COMPATIBLE_BASE_URL"].strip(),
            timeout=timeout_seconds,
            max_retries=max_retries,
        )
        if system_role == "system":
            client = OpenAICompatibleSystemRoleClient(client)
        llm = api.OpenAILLM(client, model_id, reasoning_effort="low", temperature=None)
        llm.name = model_id
        api.AttackModelNames.setdefault(model_id, attack_model_name(model_id))
        return llm
    try:
        return api.ModelsEnum(model)
    except Exception as exc:
        choices = ", ".join(str(value) for value in api.ModelsEnum)
        raise NativeSetupError(f"unsupported AgentDojo model {model!r}; choose one of: {choices}") from exc


class OpenAICompatibleSystemRoleClient:
    """Adapt AgentDojo's OpenAI-only developer role at the provider boundary."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.chat = _OpenAICompatibleChat(inner.chat)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _OpenAICompatibleChat:
    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.completions = _OpenAICompatibleCompletions(inner.completions)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _OpenAICompatibleCompletions:
    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def create(self, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages")
        if messages is not None:
            kwargs["messages"] = [
                {**message, "role": "system"}
                if isinstance(message, Mapping) and message.get("role") == "developer"
                else message
                for message in messages
            ]
        return self._inner.create(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def attack_model_name(model_id: str) -> str:
    normalized = model_id.casefold()
    if normalized.startswith("gpt-5"):
        return "GPT-5"
    if normalized.startswith("gpt-"):
        return "GPT"
    return "AI assistant"


def run_native(
    selection: dict[str, Any],
    suite: Any,
    api: SimpleNamespace,
    bridge_metadata: dict[str, Any],
    args: argparse.Namespace,
    working_tree_dirty: bool,
) -> int:
    if args.max_trials is not None and args.max_trials < 1:
        raise NativeSetupError("--max-trials must be at least 1")
    if (args.retry_errors or args.retry_judge_failures) and args.resume is None:
        raise NativeSetupError("--retry-errors and --retry-judge-failures require --resume")
    if not 0.1 <= args.provider_timeout_seconds <= 600:
        raise NativeSetupError("--provider-timeout-seconds must be between 0.1 and 600")
    if not 0 <= args.provider_max_retries <= 8:
        raise NativeSetupError("--provider-max-retries must be between 0 and 8")
    if args.model != "openai-compatible" and args.openai_compatible_system_role != "developer":
        raise NativeSetupError("--openai-compatible-system-role requires --model openai-compatible")
    model = create_pipeline_llm(
        api,
        args.model,
        args.model_id,
        timeout_seconds=args.provider_timeout_seconds,
        max_retries=args.provider_max_retries,
        system_role=args.openai_compatible_system_role,
    )

    pipeline = api.AgentPipeline.from_config(
        api.PipelineConfig(
            llm=model,
            model_id=args.model_id,
            defense=None,
            tool_delimiter="tool",
            system_message_name=None,
            system_message=None,
            # AgentDojo's JSON formatter cannot serialize datetime fields in
            # workspace results; its official YAML default handles them.
            tool_output_format=None,
        )
    )
    attacker = api.load_attack(selection["attack"], suite, pipeline)
    trial_specs = build_trial_specs(selection)
    if args.max_trials is not None:
        trial_specs = trial_specs[: args.max_trials]

    run_config = native_run_config(selection, trial_specs, bridge_metadata, args)
    journal = prepare_run_journal(
        args,
        run_config,
        working_tree_dirty=working_tree_dirty,
    )
    output_dir: Path = journal["output_dir"]
    checkpoint: dict[str, Any] = journal["checkpoint"]
    secret: bytes = journal["secret"]
    transcript: list[dict[str, Any]] = journal["transcript"]
    labels: list[dict[str, Any]] = journal["labels"]
    trials: list[dict[str, Any]] = journal["trials"]
    completed_ids = set(checkpoint["completed_trial_ids"])
    interrupted = False

    try:
        for index, spec in enumerate(trial_specs, start=1):
            trial_id = opaque_trial_id(secret, spec.case_id, spec.seed, spec.repetition)
            if trial_id in completed_ids:
                print(f"[{index:03d}/{len(trial_specs):03d}] {trial_id} status=checkpointed skip=true")
                continue
            random.seed(spec.seed)
            trial_events: list[dict[str, Any]] = []
            trial, label = run_trial(
                spec,
                trial_id,
                suite,
                pipeline,
                attacker,
                api.FunctionsRuntime,
                trial_events,
                args.node,
                args.bridge_timeout,
                bridge_script_for(args),
                api=api,
                enable_agentward_semantic=args.defense == "agentward",
            )
            validate_native_trial(trial)
            persist_trial_result(output_dir, checkpoint, trial_events, label, trial)
            transcript.extend(trial_events)
            labels.append(label)
            trials.append(trial)
            completed_ids.add(trial_id)
            print(
                f"[{index:03d}/{len(trial_specs):03d}] {trial_id} "
                f"status={trial['status']} decision={trial['detector']['decision'] if trial['detector'] else 'none'}",
                flush=True,
            )
    except KeyboardInterrupt:
        interrupted = True
        print("native run interrupted; finalized checkpointed trials only", file=sys.stderr)

    transcript_path = output_dir / PRIVATE_FILE_NAMES["transcript"]
    labels_path = output_dir / PRIVATE_FILE_NAMES["labels"]
    trials_path = output_dir / PRIVATE_FILE_NAMES["trials"]

    finished_at = datetime.now(UTC)
    errors = sum(trial["status"] == "error" for trial in trials)
    provider_errors = sum(
        trial["status"] == "error" and trial["error"]["stage"] == "provider"
        for trial in trials
    )
    expected_trials = int(selection["expected"]["trials"])
    detector_events = len(transcript)
    judge_audit = semantic_judge_audit(transcript)
    run_dirty = bool(checkpoint["working_tree_dirty"]) or working_tree_dirty
    judge_configuration_valid = (
        args.defense == "no-defense"
        and bridge_metadata.get("semantic_judge", {}).get("enabled") is False
        and judge_audit == {"requested": 0, "called": 0, "failed": 0}
    ) or (
        args.defense == "agentward"
        and bridge_metadata.get("semantic_judge", {}).get("enabled") is True
        and judge_audit["requested"] > 0
        and judge_audit["failed"] == 0
    ) or (
        args.defense == "agentsentry"
        and not args.allow_no_judge
        and bridge_metadata.get("semantic_judge", {}).get("enabled") is True
        and judge_audit["failed"] == 0
    )
    clean_complete = (
        len(trials) == expected_trials
        and errors == 0
        and detector_events > 0
        and judge_configuration_valid
        and not run_dirty
        and not interrupted
    )
    status = "complete" if clean_complete else "partial" if trials else "failed"
    profile = public_profile(args)
    checkpoint["last_finalized_at"] = finished_at.isoformat()
    checkpoint["last_status"] = status
    write_json(output_dir / CHECKPOINT_FILE_NAME, checkpoint)
    public_result = {
        "$schema": SCHEMA_URI,
        "protocol": {"name": PROTOCOL_NAME, "version": PROTOCOL_VERSION},
        "visibility": "public_aggregate",
        "status": status,
        "run": {
            "run_id": checkpoint["run_id"],
            "release_commit": checkpoint["release_commit"],
            "working_tree_dirty": run_dirty,
            "started_at": checkpoint["started_at"],
            "finished_at": finished_at.isoformat(),
        },
        "benchmark": {
            "name": selection["benchmark"]["name"],
            "version": selection["benchmark"]["benchmark_version"],
            "commit": selection["benchmark"]["source_commit"],
            "suite": selection["benchmark"]["suite"],
            "adapter_version": ADAPTER_VERSION,
            "selection_sha256": canonical_sha256(selection),
            "seeds": selection["seeds"],
        },
        "system_under_test": {
            "plugin_version": system_plugin_version(args, bridge_metadata),
            "profile": profile,
            "model": args.model_id if args.model == "openai-compatible" else args.model,
            "config_sha256": checkpoint["run_config_sha256"],
        },
        "label_isolation": {
            "architecture": "separate_evaluator_and_detector_processes",
            "label_store_mounted_in_detector": False,
            "opaque_trial_ids": True,
            "detector_event_schema_sha256": canonical_sha256(load_json(DETECTOR_EVENT_SCHEMA)),
            "detector_transcript_sha256": sha256_file(transcript_path),
            "detector_event_count": detector_events,
            "private_labels_sha256": sha256_file(labels_path),
            "post_join_sha256": canonical_sha256(trials),
            "violations": [],
        },
        "coverage": {
            "expected_trials": expected_trials,
            "observed_trials": len(trials),
            "completed_trials": len(trials) - errors,
            "error_trials": errors,
            "reportable": clean_complete,
        },
        "metrics": compute_native_metrics(trials) if trials else None,
        "artifacts": {
            "private_trials_sha256": sha256_file(trials_path),
            "detector_transcript_sha256": sha256_file(transcript_path),
        },
    }
    validate_public_native_result(public_result)
    result_path = output_dir / "result.public.json"
    write_json(result_path, public_result)
    write_json(
        output_dir / "manifest.json",
        {
            "run_id": checkpoint["run_id"],
            "created_after_detector_shutdown": True,
            "opaque_id_key_commitment": hashlib.sha256(secret).hexdigest(),
            "selection_sha256": canonical_sha256(selection),
            "tool_manifest_sha256": (
                sha256_file(tool_manifest_for_selection(selection)) if args.defense != "agentward" else None
            ),
            "defense": args.defense,
            "semantic_judge": judge_audit,
            "provider": {
                **checkpoint["run_config"]["provider"],
                "error_trials": provider_errors,
            },
            "checkpoint": {
                "version": CHECKPOINT_VERSION,
                "resume_count": checkpoint["resume_count"],
                "completed_trials": len(trials),
            },
            "files": {
                path.name: sha256_file(path)
                for path in (
                    transcript_path,
                    labels_path,
                    trials_path,
                    result_path,
                    output_dir / CHECKPOINT_FILE_NAME,
                )
            },
        },
    )

    if args.publish:
        if not clean_complete:
            raise NativeSetupError("--publish requires a clean, complete, error-free run with semantic Judge enabled")
        shutil.copyfile(result_path, CANONICAL_RESULT)

    print(json.dumps(public_result["metrics"], ensure_ascii=False, indent=2))
    print(f"semantic judge audit: {json.dumps(judge_audit, ensure_ascii=False)}")
    print(f"provider errors: {provider_errors}")
    print(f"public result: {result_path}")
    if args.publish:
        print(f"canonical result: {CANONICAL_RESULT}")
    if interrupted:
        return 130
    return 0 if errors == 0 else 1


def native_run_config(
    selection: Mapping[str, Any],
    trial_specs: list[TrialSpec],
    bridge_metadata: Mapping[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    return {
        "selection_sha256": canonical_sha256(selection),
        "trial_plan_sha256": canonical_sha256([
            {
                "case_id": spec.case_id,
                "user_task_id": spec.user_task_id,
                "injection_task_id": spec.injection_task_id,
                "is_attack": spec.is_attack,
                "seed": spec.seed,
                "repetition": spec.repetition,
            }
            for spec in trial_specs
        ]),
        "plugin_version": system_plugin_version(args, bridge_metadata),
        "plugin_dist_sha256": (
            bridge_metadata.get("plugin_dist_sha256")
            if args.defense == "agentward"
            else sha256_tree(ROOT / "openclaw-plugin" / "dist")
        ),
        "bridge_script_sha256": sha256_file(bridge_script_for(args)),
        "tool_manifest_sha256": (
            None if args.defense == "agentward" else sha256_file(tool_manifest_for_selection(selection))
        ),
        "release_commit": git_commit(),
        "defense": args.defense,
        "profile": public_profile(args),
        "provider": {
            "kind": args.model,
            "model": args.model_id if args.model == "openai-compatible" else args.model,
            "base_url": (
                os.getenv("OPENAI_COMPATIBLE_BASE_URL", "").strip()
                if args.model == "openai-compatible"
                else None
            ),
            "system_role": (
                args.openai_compatible_system_role if args.model == "openai-compatible" else None
            ),
            "request_timeout_seconds": args.provider_timeout_seconds,
            "max_retries": args.provider_max_retries,
            "retry_backoff": "openai_sdk_exponential",
        },
        "judge": bridge_metadata.get("semantic_judge"),
        "bridge": dict(bridge_metadata),
        "bridge_timeout_seconds": args.bridge_timeout,
    }


def public_profile(args: argparse.Namespace) -> str:
    if args.defense == "no-defense":
        return "observe-no-defense"
    if args.defense == "agentward":
        return "agentward-default"
    profile = getattr(args, "policy_profile", "competition")
    return f"{profile}-no-judge" if args.allow_no_judge else profile


def expected_bridge_posture(args: argparse.Namespace) -> tuple[str, str]:
    if args.defense in {"no-defense", "agentward"}:
        return DEFENSE_PROFILES[args.defense]
    return getattr(args, "policy_profile", "competition"), "approval"


def bridge_script_for(args: argparse.Namespace) -> Path:
    return AGENTWARD_BRIDGE_SCRIPT if getattr(args, "defense", "agentsentry") == "agentward" else BRIDGE_SCRIPT


def system_plugin_version(args: argparse.Namespace, bridge_metadata: Mapping[str, Any]) -> str:
    if getattr(args, "defense", "agentsentry") == "agentward":
        version = bridge_metadata.get("plugin_version")
        if not isinstance(version, str) or not version:
            raise NativeSetupError("AgentWard bridge did not report a plugin version")
        return version
    return plugin_version()


def prepare_run_journal(
    args: argparse.Namespace,
    run_config: dict[str, Any],
    *,
    working_tree_dirty: bool,
) -> dict[str, Any]:
    run_config_sha256 = canonical_sha256(run_config)
    if args.resume is None:
        started_at = datetime.now(UTC)
        run_id = f"agentdojo-native-{started_at.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
        output_dir = args.output_root.resolve() / run_id
        output_dir.mkdir(parents=True, exist_ok=False)
        secret = secrets.token_bytes(32)
        checkpoint = {
            "version": CHECKPOINT_VERSION,
            "run_id": run_id,
            "started_at": started_at.isoformat(),
            "release_commit": run_config["release_commit"],
            "working_tree_dirty": working_tree_dirty,
            "run_config": run_config,
            "run_config_sha256": run_config_sha256,
            "opaque_id_key_hex": secret.hex(),
            "completed_trial_ids": [],
            "counts": {"transcript": 0, "labels": 0, "trials": 0},
            "resume_count": 0,
            "last_finalized_at": None,
            "last_status": "running",
        }
        for name in PRIVATE_FILE_NAMES.values():
            write_jsonl(output_dir / name, [])
        write_json(output_dir / CHECKPOINT_FILE_NAME, checkpoint)
        return {
            "output_dir": output_dir,
            "checkpoint": checkpoint,
            "secret": secret,
            "transcript": [],
            "labels": [],
            "trials": [],
        }

    output_dir = args.resume.resolve()
    checkpoint_path = output_dir / CHECKPOINT_FILE_NAME
    if not output_dir.is_dir() or not checkpoint_path.is_file():
        raise NativeSetupError(f"resume checkpoint not found: {checkpoint_path}")
    checkpoint = load_json(checkpoint_path)
    if checkpoint.get("version") != CHECKPOINT_VERSION:
        raise NativeSetupError("resume checkpoint version is unsupported")
    if checkpoint.get("run_config_sha256") != run_config_sha256 or checkpoint.get("run_config") != run_config:
        raise NativeSetupError("resume configuration differs from the checkpointed native run")
    secret_hex = checkpoint.get("opaque_id_key_hex")
    if not isinstance(secret_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", secret_hex):
        raise NativeSetupError("resume checkpoint opaque-id key is invalid")
    counts = checkpoint.get("counts")
    completed_ids = checkpoint.get("completed_trial_ids")
    if not isinstance(counts, dict) or set(counts) != set(PRIVATE_FILE_NAMES):
        raise NativeSetupError("resume checkpoint counts are invalid")
    if not isinstance(completed_ids, list) or any(not isinstance(item, str) for item in completed_ids):
        raise NativeSetupError("resume checkpoint completed ids are invalid")

    transcript = read_jsonl_prefix(output_dir / PRIVATE_FILE_NAMES["transcript"], counts["transcript"])
    labels = read_jsonl_prefix(output_dir / PRIVATE_FILE_NAMES["labels"], counts["labels"])
    trials = read_jsonl_prefix(output_dir / PRIVATE_FILE_NAMES["trials"], counts["trials"])
    if len(labels) != len(trials) or len(trials) != len(completed_ids):
        raise NativeSetupError("resume checkpoint trial and label counts disagree")
    for trial in trials:
        validate_native_trial(trial)
    if [trial["trial_id"] for trial in trials] != completed_ids:
        raise NativeSetupError("resume checkpoint completed ids do not match private trials")

    if args.retry_errors or args.retry_judge_failures:
        retry_ids = {
            trial["trial_id"] for trial in trials
            if args.retry_errors and trial["status"] == "error"
        }
        if args.retry_judge_failures:
            retry_ids.update(checkpoint_trial_ids_with_failed_judge(transcript))
        if retry_ids:
            transcript = [
                event for event in transcript
                if event.get("routing", {}).get("opaque_session_id") not in retry_ids
            ]
            labels = [label for label in labels if label.get("trial_id") not in retry_ids]
            trials = [trial for trial in trials if trial["trial_id"] not in retry_ids]
            completed_ids = [trial["trial_id"] for trial in trials]

    write_jsonl(output_dir / PRIVATE_FILE_NAMES["transcript"], transcript)
    write_jsonl(output_dir / PRIVATE_FILE_NAMES["labels"], labels)
    write_jsonl(output_dir / PRIVATE_FILE_NAMES["trials"], trials)
    checkpoint["completed_trial_ids"] = completed_ids
    checkpoint["counts"] = {"transcript": len(transcript), "labels": len(labels), "trials": len(trials)}
    checkpoint["resume_count"] = int(checkpoint.get("resume_count") or 0) + 1
    checkpoint["last_finalized_at"] = None
    checkpoint["last_status"] = "running"
    write_json(checkpoint_path, checkpoint)
    return {
        "output_dir": output_dir,
        "checkpoint": checkpoint,
        "secret": bytes.fromhex(secret_hex),
        "transcript": transcript,
        "labels": labels,
        "trials": trials,
    }


def persist_trial_result(
    output_dir: Path,
    checkpoint: dict[str, Any],
    events: list[dict[str, Any]],
    label: dict[str, Any],
    trial: dict[str, Any],
) -> None:
    append_jsonl(output_dir / PRIVATE_FILE_NAMES["transcript"], events)
    append_jsonl(output_dir / PRIVATE_FILE_NAMES["labels"], [label])
    append_jsonl(output_dir / PRIVATE_FILE_NAMES["trials"], [trial])
    checkpoint["completed_trial_ids"].append(trial["trial_id"])
    checkpoint["counts"]["transcript"] += len(events)
    checkpoint["counts"]["labels"] += 1
    checkpoint["counts"]["trials"] += 1
    checkpoint["last_finalized_at"] = None
    checkpoint["last_status"] = "running"
    write_json(output_dir / CHECKPOINT_FILE_NAME, checkpoint)


def build_trial_specs(selection: Mapping[str, Any]) -> list[TrialSpec]:
    specs: list[TrialSpec] = []
    for repetition, seed in enumerate(selection["seeds"]):
        for task_id in selection["benign_task_ids"]:
            specs.append(
                TrialSpec(
                    case_id=f"benign:{selection['benchmark']['suite']}:{task_id}",
                    user_task_id=task_id,
                    injection_task_id=None,
                    is_attack=False,
                    seed=seed,
                    repetition=repetition,
                )
            )
        for pair in selection["attack_pairs"]:
            specs.append(
                TrialSpec(
                    case_id=(
                        f"attack:{selection['benchmark']['suite']}:"
                        f"{pair['user_task_id']}:{pair['injection_task_id']}"
                    ),
                    user_task_id=pair["user_task_id"],
                    injection_task_id=pair["injection_task_id"],
                    is_attack=True,
                    seed=seed,
                    repetition=repetition,
                )
            )
    return specs


def run_trial(
    spec: TrialSpec,
    trial_id: str,
    suite: Any,
    pipeline: Any,
    attacker: Any,
    base_runtime_cls: type[Any],
    transcript: list[dict[str, Any]],
    node: str,
    bridge_timeout: float,
    bridge_script: Path = BRIDGE_SCRIPT,
    *,
    api: SimpleNamespace | None = None,
    enable_agentward_semantic: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    user_task = suite.user_tasks[spec.user_task_id]
    user_message = str(user_task.PROMPT)
    initial_input = {
        "user_message": user_message,
        "tool_name": "",
        "tool_args": {},
        "tool_result": None,
        "session_history": [],
    }
    records: list[dict[str, Any]] = []
    utility: bool | None = None
    security: bool | None = None
    error: BaseException | None = None
    teardown_error: BaseException | None = None
    started = time.perf_counter()

    bridge = JsonlNodeBridgeClient([node, str(bridge_script)], timeout=bridge_timeout)
    recording = RecordingBridge(bridge, transcript)
    trial_pipeline = pipeline
    if enable_agentward_semantic:
        if api is None:
            raise NativeSetupError("AgentWard semantic pipeline requires the AgentDojo API namespace")
        trial_pipeline = make_agentward_semantic_pipeline(
            api,
            pipeline,
            recording,
            user_message=user_message,
            session_id=trial_id,
        )
    runtime_class = make_guarded_runtime_class(
        base_runtime_cls,
        recording,
        user_message=user_message,
        session_id=trial_id,
        record_sink=lambda record: records.append(dict(record)),
    )
    try:
        if spec.is_attack:
            injection_task = suite.injection_tasks[spec.injection_task_id]
            injections = attacker.attack(user_task, injection_task)
            utility, security = suite.run_task_with_pipeline(
                trial_pipeline,
                user_task,
                injection_task=injection_task,
                injections=injections,
                runtime_class=runtime_class,
            )
        else:
            utility, _ = suite.run_task_with_pipeline(
                trial_pipeline,
                user_task,
                injection_task=None,
                injections={},
                runtime_class=runtime_class,
            )
    except Exception as exc:  # Preserve remaining trials and report this harness failure separately.
        error = exc
    finally:
        try:
            recording.request({"op": "end", "session_id": trial_id})
        except Exception as exc:
            teardown_error = exc
        bridge.close()

    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    bridge_failure = next(
        (
            record.get("bridge_error")
            or record.get("after_feedback_error")
            or record.get("record_sink_error")
            for record in records
            if record.get("bridge_error") or record.get("after_feedback_error") or record.get("record_sink_error")
        ),
        None,
    )
    harness_error = error or teardown_error
    if bridge_failure and harness_error is None:
        harness_error = RuntimeError(str(bridge_failure))
    status = "error" if harness_error else "ok"
    detector = summarize_detector(records, status=status, events=transcript)
    detector_ms = round(
        sum(float(record.get("latency_ms") or 0) + float(record.get("after_latency_ms") or 0) for record in records),
        3,
    )
    outcome = {
        "is_attack": spec.is_attack,
        "security": None if status == "error" or not spec.is_attack else bool(security),
        "utility": None if status == "error" else float(bool(utility)),
        "task_completed": None if status == "error" else bool(utility),
    }
    error_payload = None
    if harness_error:
        stage, kind, code, retryable = classify_native_error(
            harness_error,
            detector_failure=bool(bridge_failure or teardown_error),
        )
        error_payload = {
            "stage": stage,
            "kind": kind,
            "code": code,
            "message_redacted": _redact_error(harness_error),
            "retryable": retryable,
        }
    trial = {
        "trial_id": trial_id,
        "case_id": spec.case_id,
        "seed": spec.seed,
        "repetition": spec.repetition,
        "status": status,
        "detector_input": initial_input,
        "detector": detector,
        "outcome": outcome,
        "latency_ms": {
            "end_to_end": elapsed_ms,
            "agent": round(max(0.0, elapsed_ms - detector_ms), 3),
            "detector": detector_ms,
            "judge": None,
        },
        "usage": {
            "input_tokens": None,
            "output_tokens": None,
            "judge_input_tokens": None,
            "judge_output_tokens": None,
        },
        "cost": {
            "usd": None,
            "currency": "USD",
            "estimated": False,
            "pricing_snapshot": None,
        },
        "error": error_payload,
        "commitments": {
            "detector_input_sha256": canonical_sha256(initial_input),
            "detector_output_sha256": canonical_sha256(detector) if detector is not None else None,
        },
    }
    label = {
        "trial_id": trial_id,
        "benchmark_case_id": spec.case_id,
        "user_task_id": spec.user_task_id,
        "injection_task_id": spec.injection_task_id,
        "is_attack": spec.is_attack,
        "seed": spec.seed,
        "repetition": spec.repetition,
        "agentdojo_security": outcome["security"],
        "agentdojo_utility": outcome["utility"],
    }
    return trial, label


def make_agentward_semantic_pipeline(
    api: SimpleNamespace,
    pipeline: Any,
    bridge: RecordingBridge,
    *,
    user_message: str,
    session_id: str,
) -> Any:
    """Insert AgentWard Decision Alignment before each AgentDojo tool turn."""

    elements = list(getattr(pipeline, "elements", ()))
    if not elements or not isinstance(elements[-1], api.ToolsExecutionLoop):
        raise NativeSetupError("AgentWard semantic adapter requires the standard AgentDojo tools loop")
    source_loop = elements[-1]

    class AgentWardDecisionAlignment(api.BasePipelineElement):
        def __init__(self) -> None:
            self.sequence = 0

        def query(
            self,
            query: str,
            runtime: Any,
            env: Any,
            messages: Any,
            extra_args: dict[str, Any],
        ) -> tuple[str, Any, Any, Any, dict[str, Any]]:
            if not messages or messages[-1].get("role") != "assistant":
                return query, runtime, env, messages, extra_args
            tool_calls = messages[-1].get("tool_calls")
            if not tool_calls:
                return query, runtime, env, messages, extra_args
            self.sequence += 1
            call_id = f"assistant_{self.sequence:08d}"
            assistant_message = _agentward_assistant_message(messages[-1])
            payload = {
                "user_message": user_message,
                "tool_name": "__assistant_tool_use__",
                "tool_args": {
                    "tool_call_count": len(tool_calls),
                    "tool_names": [str(call.function) for call in tool_calls],
                },
                "tool_result": None,
                "session_history": [{"message": assistant_message}],
            }
            result = bridge.request(
                {
                    "op": "assistant_tool_use",
                    "session_id": session_id,
                    "call_id": call_id,
                    "payload": payload,
                }
            )
            if not isinstance(result, Mapping) or result.get("decision") not in {"allow", "deny"}:
                raise NativeSetupError("AgentWard semantic bridge returned an invalid assistant verdict")
            return query, runtime, env, messages, extra_args

    semantic = AgentWardDecisionAlignment()
    guarded_loop = api.ToolsExecutionLoop(
        [semantic, *list(source_loop.elements)],
        max_iters=source_loop.max_iters,
    )
    guarded = api.AgentPipeline([*elements[:-1], guarded_loop])
    guarded.name = getattr(pipeline, "name", None)
    return guarded


def _agentward_assistant_message(message: Mapping[str, Any]) -> dict[str, Any]:
    content: list[dict[str, Any]] = []
    for block in message.get("content") or []:
        text = block.get("content") if isinstance(block, Mapping) else None
        if isinstance(text, str) and text:
            content.append({"type": "text", "text": text})
    for call in message.get("tool_calls") or []:
        content.append(
            {
                "type": "toolCall",
                "id": str(call.id or ""),
                "name": str(call.function),
                "arguments": _json_clone(call.args),
            }
        )
    return {"role": "assistant", "stopReason": "toolUse", "content": content}


def summarize_detector(
    records: list[dict[str, Any]],
    *,
    status: str,
    events: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any] | None:
    judge_audit = semantic_judge_audit(events)
    if not records:
        if status == "error":
            return None
        return {
            "decision": "allow",
            "blocked_scope": "none",
            "action_executed": False,
            "llm_judge_called": judge_audit["called"] > 0,
        }
    decisions = [str(record.get("decision") or "deny") for record in records]
    decision = "deny" if "deny" in decisions else "ask" if "ask" in decisions else "allow"
    executed_before_intervention = any(bool(record.get("executed")) for record in records)
    blocked_scope = "none" if decision == "allow" else "action" if executed_before_intervention else "task"
    return {
        "decision": decision,
        "blocked_scope": blocked_scope,
        # For an aggregate intervention this means the blocked call itself did not execute.
        "action_executed": bool(executed_before_intervention) if decision == "allow" else False,
        "llm_judge_called": judge_audit["called"] > 0 or any(
            bool((record.get("detector_result") or {}).get("semantic_judge_called"))
            for record in records
            if isinstance(record.get("detector_result"), dict)
        ),
    }


def semantic_judge_audit(events: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    requested = 0
    called = 0
    for event in events:
        routing = event.get("routing")
        output = event.get("detector_output")
        if not isinstance(routing, Mapping) or routing.get("op") not in {"before_tool", "assistant_tool_use"}:
            continue
        if not isinstance(output, Mapping) or output.get("ok") is not True:
            continue
        result = output.get("result")
        if (
            not isinstance(result, Mapping)
            or result.get("semantic_judge_requested") is not True
            or result.get("semantic_judge_observation_only") is True
        ):
            continue
        requested += 1
        if result.get("semantic_judge_called") is True:
            called += 1
    return {"requested": requested, "called": called, "failed": requested - called}


def checkpoint_trial_ids_with_failed_judge(
    events: Iterable[Mapping[str, Any]],
) -> set[str]:
    failed: set[str] = set()
    for event in events:
        routing = event.get("routing")
        output = event.get("detector_output")
        if not isinstance(routing, Mapping) or routing.get("op") not in {"before_tool", "assistant_tool_use"}:
            continue
        if not isinstance(output, Mapping) or output.get("ok") is not True:
            continue
        result = output.get("result")
        if not isinstance(result, Mapping):
            continue
        if result.get("semantic_judge_observation_only") is True:
            continue
        if result.get("semantic_judge_requested") is not True or result.get("semantic_judge_called") is True:
            continue
        trial_id = routing.get("opaque_session_id")
        if isinstance(trial_id, str) and trial_id:
            failed.add(trial_id)
    return failed


def plugin_version() -> str:
    package = load_json(ROOT / "openclaw-plugin" / "package.json")
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise NativeSetupError("OpenClaw plugin package version is missing")
    return version


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise NativeSetupError(f"expected a JSON object at {path}")
    return value


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    payload = b"".join(canonical_json_bytes(row) + b"\n" for row in rows)
    atomic_write_bytes(path, payload)


def append_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    payload = b"".join(canonical_json_bytes(row) + b"\n" for row in rows)
    if not payload:
        return
    with path.open("ab") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def read_jsonl_prefix(path: Path, count: Any) -> list[dict[str, Any]]:
    if type(count) is not int or count < 0:
        raise NativeSetupError(f"checkpoint count is invalid for {path.name}")
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if len(rows) == count:
                    break
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise NativeSetupError(f"checkpointed JSONL row is not an object: {path.name}:{line_number}")
                rows.append(value)
    except FileNotFoundError as exc:
        raise NativeSetupError(f"checkpointed native artifact is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise NativeSetupError(f"checkpointed native artifact is invalid: {path.name}:{exc.lineno}") from exc
    if len(rows) != count:
        raise NativeSetupError(f"checkpointed native artifact is truncated: {path.name}")
    return rows


def write_json(path: Path, value: Any) -> None:
    payload = (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    atomic_write_bytes(path, payload)


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(path: Path) -> str:
    files = sorted(item for item in path.rglob("*") if item.is_file())
    if not files:
        raise NativeSetupError(f"native plugin build is empty: {path}")
    digest = hashlib.sha256()
    for item in files:
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(item)))
    return digest.hexdigest()


def classify_native_error(error: BaseException, *, detector_failure: bool) -> tuple[str, str, str, bool]:
    if detector_failure:
        kind = type(error).__name__.lower()
        return "detector", kind, "AGENTSENTRY_NATIVE_DETECTOR_ERROR", True
    provider = provider_error_kind(error)
    if provider is not None:
        kind, retryable = provider
        return "provider", kind, f"AGENTSENTRY_NATIVE_{kind.upper()}", retryable
    kind = type(error).__name__.lower()
    retryable = isinstance(error, (TimeoutError, subprocess.TimeoutExpired))
    return "agent", kind, "AGENTSENTRY_NATIVE_AGENT_ERROR", retryable


def provider_error_kind(error: BaseException) -> tuple[str, bool] | None:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        name = type(current).__name__.casefold()
        module = type(current).__module__.casefold()
        message = str(current).casefold()
        provider_module = module.startswith(("openai", "httpx", "httpcore"))
        if isinstance(current, TimeoutError) or "timeout" in name or "timed out" in message:
            return "provider_timeout", True
        if provider_module or any(token in name for token in ("apierror", "ratelimit", "connection")):
            if "ratelimit" in name or "rate limit" in message or "status code: 429" in message:
                return "provider_rate_limit", True
            if "connection" in name or "connect" in message:
                return "provider_connection", True
            if re.search(r"\b(?:500|502|503|504)\b", message):
                return "provider_http_error", True
            return "provider_error", False
        next_error = current.__cause__ or current.__context__
        current = next_error if isinstance(next_error, BaseException) else None
    return None


def git_commit() -> str:
    completed = _git("rev-parse", "HEAD")
    commit = completed.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise NativeSetupError("Git HEAD is not a full commit hash")
    return commit


def git_worktree_dirty() -> bool | None:
    try:
        return bool(_git("status", "--porcelain", "--untracked-files=normal").strip())
    except NativeSetupError:
        return None


def _git(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NativeSetupError(f"Git command failed: git {' '.join(args)}") from exc
    return completed.stdout


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))


def _redact_error(error: BaseException) -> str:
    text = f"{type(error).__name__}: {error}".replace("\r", " ").replace("\n", " ")
    patterns = [
        r"-----BEGIN [^-]{0,40}PRIVATE KEY-----[\s\S]*",
        r"\bsk-[A-Za-z0-9_-]{8,}\b",
        r"\b(?:bearer|authorization)\s+[A-Za-z0-9._-]{8,}\b",
        r"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+",
    ]
    for pattern in patterns:
        text = re.sub(pattern, "[REDACTED]", text, flags=re.IGNORECASE)
    return text[:500] or "redacted native harness error"


if __name__ == "__main__":
    raise SystemExit(main())
