#!/usr/bin/env python3
"""Run a label-isolated, native AgentDojo benchmark through AgentSentry.

The official AgentDojo environment and evaluators remain authoritative. This
runner replaces only the final FunctionsRuntime boundary so every real tool
call is approved by the OpenClaw plugin policy before execution and every tool
result is returned to the policy state for provenance tracking.
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
DEFAULT_SELECTION = ROOT / "evaluation" / "native" / "agentdojo_selection.json"
DETECTOR_EVENT_SCHEMA = ROOT / "evaluation" / "native" / "detector_event_schema.json"
TOOL_MANIFEST = ROOT / "openclaw-plugin" / "manifests" / "agentdojo-workspace-v1.2.2.json"
BRIDGE_SCRIPT = ROOT / "openclaw-plugin" / "scripts" / "agentdojo-policy-bridge.mjs"
DEFAULT_OUTPUT_ROOT = ROOT / "runtime" / "agentdojo"
CANONICAL_RESULT = ROOT / "evaluation" / "native" / "agentdojo_results.json"
PRIVATE_FILE_NAMES = {
    "transcript": "detector-events.private.jsonl",
    "labels": "labels.private.jsonl",
    "trials": "trials.private.jsonl",
}
MODEL_ENVIRONMENTS = {
    "openai-compatible": ("OPENAI_COMPATIBLE_BASE_URL", "OPENAI_COMPATIBLE_API_KEY"),
    "local": (),
    "vllm_parsed": (),
}


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
        selection = load_selection(args.selection)
        api = load_agentdojo_api()
        suite = api.get_suite(selection["benchmark"]["benchmark_version"], selection["benchmark"]["suite"])
        validate_selection_against_suite(selection, suite)
        bridge_metadata = bridge_doctor(args.node, args.bridge_timeout)
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
        if not args.allow_no_judge and not os.getenv("AGENTSENTRY_API_KEY"):
            raise NativeSetupError(
                "competition profile requires AGENTSENTRY_API_KEY for semantic review; "
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
        description="Run the official AgentDojo environment with AgentSentry at the native FunctionsRuntime boundary."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--doctor", action="store_true", help="Check optional dependencies, suite contract, and the Node policy bridge.")
    mode.add_argument("--plan", action="store_true", help="Validate and print the frozen selection without creating a model client.")
    mode.add_argument("--contract", action="store_true", help="Run one real AgentDojo read-only task through the bridge without an LLM or credentials.")
    parser.add_argument("--selection", type=Path, default=DEFAULT_SELECTION)
    parser.add_argument("--model", help="AgentDojo model identifier. Required only for a real run.")
    parser.add_argument("--model-id", help="Provider model id for local or openai-compatible AgentDojo models.")
    parser.add_argument("--node", default="node", help="Node executable used by the isolated policy bridge.")
    parser.add_argument("--bridge-timeout", type=float, default=20.0)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--max-trials", type=int, help="Development-only prefix limit; the result remains partial.")
    parser.add_argument("--allow-dirty", action="store_true", help="Allow a non-reportable development run from a dirty worktree.")
    parser.add_argument("--allow-no-judge", action="store_true", help="Disable semantic Judge and mark the run non-reportable.")
    parser.add_argument("--publish", action="store_true", help="Replace the canonical result only after a clean complete run.")
    return parser


def load_selection(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise NativeSetupError(f"selection file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise NativeSetupError(f"selection file is invalid JSON: {exc}") from exc
    expected_keys = {
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
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise NativeSetupError("selection must use the exact native selection v1 fields")
    benchmark = payload.get("benchmark")
    if not isinstance(benchmark, dict) or set(benchmark) != {
        "name", "package_version", "benchmark_version", "source_commit", "suite"
    }:
        raise NativeSetupError("selection benchmark metadata is incomplete")
    if benchmark["name"] != "AgentDojo" or benchmark["package_version"] != AGENTDOJO_PACKAGE_VERSION:
        raise NativeSetupError("selection is not pinned to AgentDojo 0.1.35")
    if not re.fullmatch(r"[0-9a-f]{40}", str(benchmark["source_commit"])):
        raise NativeSetupError("selection source_commit must be a full Git SHA-1")
    seeds = payload.get("seeds")
    if not isinstance(seeds, list) or len(seeds) != 3 or any(type(seed) is not int or seed < 0 for seed in seeds):
        raise NativeSetupError("selection must contain exactly three non-negative integer seeds")
    if len(set(seeds)) != len(seeds):
        raise NativeSetupError("selection seeds must be unique")
    benign = payload.get("benign_task_ids")
    pairs = payload.get("attack_pairs")
    if not isinstance(benign, list) or len(benign) != 20 or len(set(benign)) != len(benign):
        raise NativeSetupError("selection must contain 20 unique benign task ids")
    if not isinstance(pairs, list) or len(pairs) != 20:
        raise NativeSetupError("selection must contain 20 attack pairs, not a task cross product")
    pair_keys: set[tuple[str, str]] = set()
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != {"user_task_id", "injection_task_id"}:
            raise NativeSetupError("each attack pair must contain user_task_id and injection_task_id")
        key = (str(pair["user_task_id"]), str(pair["injection_task_id"]))
        if key in pair_keys:
            raise NativeSetupError(f"duplicate attack pair: {key}")
        pair_keys.add(key)
    expected = payload.get("expected")
    if expected != {"benign_cases": 20, "attack_cases": 20, "unique_cases": 40, "trials": 120}:
        raise NativeSetupError("selection expected counts must be 20 benign + 20 attack pairs x 3 seeds")
    return payload


def load_agentdojo_api() -> SimpleNamespace:
    try:
        package_version = importlib.metadata.version("agentdojo")
        if package_version != AGENTDOJO_PACKAGE_VERSION:
            raise NativeSetupError(
                f"AgentDojo {AGENTDOJO_PACKAGE_VERSION} is required; installed version is {package_version}"
            )
        from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
        from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
        from agentdojo.attacks import load_attack
        from agentdojo.functions_runtime import FunctionsRuntime
        from agentdojo.models import ModelsEnum
        from agentdojo.task_suite.load_suites import get_suite
    except NativeSetupError:
        raise
    except Exception as exc:
        raise NativeSetupError(
            "AgentDojo native support is not installed; run: "
            'python -m pip install -e ".[native-agentdojo]"'
        ) from exc
    return SimpleNamespace(
        AgentPipeline=AgentPipeline,
        PipelineConfig=PipelineConfig,
        GroundTruthPipeline=GroundTruthPipeline,
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

    manifest = json.loads(TOOL_MANIFEST.read_text(encoding="utf-8"))
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


def bridge_doctor(node: str, timeout: float) -> dict[str, Any]:
    if timeout <= 0:
        raise NativeSetupError("--bridge-timeout must be greater than zero")
    if not BRIDGE_SCRIPT.exists() or not (ROOT / "openclaw-plugin" / "dist" / "config.js").exists():
        raise NativeSetupError("OpenClaw plugin bridge is not built; run: npm --prefix openclaw-plugin run build")
    try:
        with JsonlNodeBridgeClient([node, str(BRIDGE_SCRIPT)], timeout=timeout) as bridge:
            result = bridge.request({"op": "ping"})
    except Exception as exc:
        raise NativeSetupError(f"AgentSentry Node policy bridge failed: {_redact_error(exc)}") from exc
    if not isinstance(result, dict) or result.get("bridge_version") != ADAPTER_VERSION:
        raise NativeSetupError("AgentSentry Node policy bridge returned an incompatible version")
    if result.get("profile") != "competition":
        raise NativeSetupError("AgentSentry Node policy bridge is not using the competition profile")
    if result.get("manifest_file_sha256") != sha256_file(TOOL_MANIFEST):
        raise NativeSetupError("Node bridge tool manifest hash differs from the frozen manifest")
    return result


def doctor_report(selection: Mapping[str, Any], suite: Any, bridge: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "ready",
        "agentdojo_package_version": AGENTDOJO_PACKAGE_VERSION,
        "benchmark_version": selection["benchmark"]["benchmark_version"],
        "suite": suite.name,
        "suite_user_tasks": len(suite.user_tasks),
        "suite_injection_tasks": len(suite.injection_tasks),
        "suite_tools": len(suite.tools),
        "selection_sha256": canonical_sha256(selection),
        "tool_manifest_sha256": sha256_file(TOOL_MANIFEST),
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
        "manifest_mapping_version": bridge["manifest_mapping_version"],
        "model_client_created": False,
    }


def run_contract(suite: Any, api: SimpleNamespace, args: argparse.Namespace) -> dict[str, Any]:
    """Execute a real AgentDojo task with its official ground-truth pipeline.

    This is a wiring contract, not a benchmark score: it proves the official
    environment, runtime and utility evaluator are reached without creating a
    model client or exposing an injection label to the detector child.
    """

    task = suite.user_tasks["user_task_0"]
    user_message = str(task.PROMPT)
    session_id = f"trial_{secrets.token_hex(12)}"
    events: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    bridge = JsonlNodeBridgeClient([args.node, str(BRIDGE_SCRIPT)], timeout=args.bridge_timeout)
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
    try:
        model = api.ModelsEnum(args.model)
    except Exception as exc:
        choices = ", ".join(str(value) for value in api.ModelsEnum)
        raise NativeSetupError(f"unsupported AgentDojo model {args.model!r}; choose one of: {choices}") from exc

    if args.allow_no_judge:
        os.environ["AGENTSENTRY_NATIVE_DISABLE_JUDGE"] = "1"
    pipeline = api.AgentPipeline.from_config(
        api.PipelineConfig(
            llm=model,
            model_id=args.model_id,
            defense=None,
            tool_delimiter="tool",
            system_message_name=None,
            system_message=None,
            tool_output_format="json",
        )
    )
    attacker = api.load_attack(selection["attack"], suite, pipeline)
    trial_specs = build_trial_specs(selection)
    if args.max_trials is not None:
        trial_specs = trial_specs[: args.max_trials]

    started_at = datetime.now(UTC)
    run_id = f"agentdojo-native-{started_at.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
    output_dir = args.output_root.resolve() / run_id
    output_dir.mkdir(parents=True, exist_ok=False)
    secret = secrets.token_bytes(32)
    transcript: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []
    trials: list[dict[str, Any]] = []

    for index, spec in enumerate(trial_specs, start=1):
        random.seed(spec.seed)
        trial_id = opaque_trial_id(secret, spec.case_id, spec.seed, spec.repetition)
        trial, label = run_trial(
            spec,
            trial_id,
            suite,
            pipeline,
            attacker,
            api.FunctionsRuntime,
            transcript,
            args.node,
            args.bridge_timeout,
        )
        validate_native_trial(trial)
        trials.append(trial)
        labels.append(label)
        print(
            f"[{index:03d}/{len(trial_specs):03d}] {trial_id} "
            f"status={trial['status']} decision={trial['detector']['decision'] if trial['detector'] else 'none'}"
        )

    # Private evaluator files are created only after every detector child has exited.
    transcript_path = output_dir / PRIVATE_FILE_NAMES["transcript"]
    labels_path = output_dir / PRIVATE_FILE_NAMES["labels"]
    trials_path = output_dir / PRIVATE_FILE_NAMES["trials"]
    write_jsonl(transcript_path, transcript)
    write_jsonl(labels_path, labels)
    write_jsonl(trials_path, trials)

    finished_at = datetime.now(UTC)
    errors = sum(trial["status"] == "error" for trial in trials)
    expected_trials = int(selection["expected"]["trials"])
    detector_events = len(transcript)
    clean_complete = (
        len(trials) == expected_trials
        and errors == 0
        and detector_events > 0
        and not working_tree_dirty
        and not args.allow_no_judge
    )
    status = "complete" if clean_complete else "partial" if detector_events else "failed"
    profile = "competition" if not args.allow_no_judge else "competition-no-judge"
    config_sha256 = canonical_sha256(
        {
            "plugin_version": plugin_version(),
            "profile": profile,
            "bridge": bridge_metadata,
            "tool_manifest_sha256": sha256_file(TOOL_MANIFEST),
        }
    )
    public_result = {
        "$schema": SCHEMA_URI,
        "protocol": {"name": PROTOCOL_NAME, "version": PROTOCOL_VERSION},
        "visibility": "public_aggregate",
        "status": status,
        "run": {
            "run_id": run_id,
            "release_commit": git_commit(),
            "working_tree_dirty": working_tree_dirty,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
        },
        "benchmark": {
            "name": "AgentDojo",
            "version": selection["benchmark"]["benchmark_version"],
            "commit": selection["benchmark"]["source_commit"],
            "suite": selection["benchmark"]["suite"],
            "adapter_version": ADAPTER_VERSION,
            "selection_sha256": canonical_sha256(selection),
            "seeds": selection["seeds"],
        },
        "system_under_test": {
            "plugin_version": plugin_version(),
            "profile": profile,
            "model": args.model_id if args.model == "openai-compatible" else args.model,
            "config_sha256": config_sha256,
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
        "metrics": compute_native_metrics(trials),
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
            "run_id": run_id,
            "created_after_detector_shutdown": True,
            "opaque_id_key_commitment": hashlib.sha256(secret).hexdigest(),
            "selection_sha256": canonical_sha256(selection),
            "tool_manifest_sha256": sha256_file(TOOL_MANIFEST),
            "files": {
                path.name: sha256_file(path)
                for path in (transcript_path, labels_path, trials_path, result_path)
            },
        },
    )

    if args.publish:
        if not clean_complete:
            raise NativeSetupError("--publish requires a clean, complete, error-free run with semantic Judge enabled")
        shutil.copyfile(result_path, CANONICAL_RESULT)

    print(json.dumps(public_result["metrics"], ensure_ascii=False, indent=2))
    print(f"public result: {result_path}")
    if args.publish:
        print(f"canonical result: {CANONICAL_RESULT}")
    return 0 if errors == 0 else 1


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

    bridge = JsonlNodeBridgeClient([node, str(BRIDGE_SCRIPT)], timeout=bridge_timeout)
    recording = RecordingBridge(bridge, transcript)
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
                pipeline,
                user_task,
                injection_task=injection_task,
                injections=injections,
                runtime_class=runtime_class,
            )
        else:
            utility, _ = suite.run_task_with_pipeline(
                pipeline,
                user_task,
                injection_task=None,
                injections={},
                runtime_class=runtime_class,
            )
    except BaseException as exc:  # Preserve remaining trials and report this harness failure separately.
        error = exc
    finally:
        try:
            recording.request({"op": "end", "session_id": trial_id})
        except BaseException as exc:
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
    detector = summarize_detector(records, status=status)
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
        stage = "detector" if bridge_failure or teardown_error else "agent"
        error_payload = {
            "stage": stage,
            "kind": type(harness_error).__name__.lower(),
            "code": f"AGENTSENTRY_NATIVE_{stage.upper()}_ERROR",
            "message_redacted": _redact_error(harness_error),
            "retryable": isinstance(harness_error, (TimeoutError, subprocess.TimeoutExpired)) or stage == "detector",
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


def summarize_detector(records: list[dict[str, Any]], *, status: str) -> dict[str, Any] | None:
    if not records:
        if status == "error":
            return None
        return {
            "decision": "allow",
            "blocked_scope": "none",
            "action_executed": False,
            "llm_judge_called": False,
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
        "llm_judge_called": any(
            bool((record.get("detector_result") or {}).get("semantic_judge_called"))
            for record in records
            if isinstance(record.get("detector_result"), dict)
        ),
    }


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
    path.write_bytes(payload)


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
