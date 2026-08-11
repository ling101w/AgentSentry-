"""Replay observed AgentDojo native attack sinks through AgentSentry.

This is a counterfactual policy experiment, not an end-to-end benchmark run.
It consumes a no-defense private detector transcript, selects trials where the
independent side-effect audit found a successful attack-related sink, and
feeds the original five-field detector inputs (including tool results and
session history) to the competition bridge.  AgentDojo tools are never
invoked.  A target is reported as ``unreachable`` when an earlier replayed
decision already stopped the enforced prefix.

The default ``--disable-judge`` mode is deliberate: it gives a deterministic,
no-model-cost measurement of the competition deterministic policy.  Omit it
only when a configured Judge endpoint is explicitly desired.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "openclaw-plugin" / "scripts" / "agentdojo-policy-bridge.mjs"
DEFAULT_SOURCE = ROOT / ".tmp" / "release-clone" / "runtime" / "agentdojo" / "agentdojo-native-20260809T062111Z-d3dd5e1f"
DEFAULT_SELECTION = ROOT / "evaluation" / "native" / "agentdojo_selection.json"

# Support both ``python scripts/replay_agentdojo_native.py`` and importing the
# command from the test suite, where the repository root is already on path.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.audit_agentdojo_side_effects import (  # noqa: E402
    Run,
    analyze_run_rows,
    build_pair_metadata,
    load_jsonl,
)


class ReplayError(RuntimeError):
    """Raised when a private transcript violates the replay contract."""


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(path: Path) -> str:
    files = sorted(item for item in path.rglob("*") if item.is_file())
    if not files:
        raise ReplayError(f"plugin dist is empty: {path}")
    digest = hashlib.sha256()
    for item in files:
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_sha256(item)))
    return digest.hexdigest()


def git_head(repo: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip()
    return value if len(value) == 40 else None


def opaque_replay_session(source_trial_id: str) -> str:
    return "trial_" + hashlib.sha256(("native-eval-v2:" + source_trial_id).encode("utf-8")).hexdigest()[:24]


class JsonlBridge:
    """Small synchronous client for the repository's native Node bridge."""

    def __init__(self, node: str, bridge_path: Path, *, disable_judge: bool) -> None:
        env = os.environ.copy()
        env["AGENTSENTRY_NATIVE_PROFILE"] = "competition"
        if disable_judge:
            env["AGENTSENTRY_NATIVE_DISABLE_JUDGE"] = "1"
        self.process = subprocess.Popen(
            [node, str(bridge_path)],
            cwd=bridge_path.parents[1],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self.sequence = 0

    def request(self, message: dict[str, Any]) -> dict[str, Any]:
        if self.process.stdin is None or self.process.stdout is None:
            raise ReplayError("bridge pipes are unavailable")
        self.sequence += 1
        request = {"id": self.sequence, **message}
        self.process.stdin.write(json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr is not None else ""
            raise ReplayError(f"bridge exited without a response: {stderr[-500:]}")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReplayError("bridge returned invalid JSON") from exc
        if not response.get("ok"):
            error = response.get("error") or {}
            raise ReplayError(str(error.get("message") or "bridge request failed"))
        result = response.get("result")
        if not isinstance(result, dict):
            raise ReplayError("bridge result must be an object")
        return result

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


def parse_run(value: str) -> Run:
    parts = value.split("|", 2)
    if len(parts) != 3:
        raise ReplayError("--run must be model|arm|private-run-directory")
    model, arm, raw_path = parts
    path = Path(raw_path)
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    return Run(model, arm, path)


def grouped_events(path: Path) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in load_jsonl(path / "detector-events.private.jsonl"):
        routing = event.get("routing") or {}
        session = routing.get("opaque_session_id")
        if not isinstance(session, str) or not session:
            raise ReplayError("detector event is missing routing.opaque_session_id")
        if not isinstance(event.get("detector_input"), dict):
            raise ReplayError(f"event {event.get('event_id')} has no detector_input")
        grouped[session].append(event)
    return grouped


def replay_trial(
    bridge: JsonlBridge,
    source_trial_id: str,
    events: list[dict[str, Any]],
    target_call_ids: set[str],
    target_atoms: dict[str, list[str]],
) -> dict[str, Any]:
    if not events or events[0].get("routing", {}).get("op") != "start":
        raise ReplayError(f"trial {source_trial_id} does not start with a bridge start event")
    replay_session = opaque_replay_session(source_trial_id)
    sent_events: list[dict[str, Any]] = []
    decisions: dict[str, dict[str, Any]] = {}
    pending: set[str] = set()
    stopped = False
    first_intervention: dict[str, Any] | None = None

    def send(event: dict[str, Any], op: str, call_id: str | None = None) -> dict[str, Any]:
        payload = event["detector_input"]
        source_hash = canonical_sha256(payload)
        # Model the JSONL wire round trip before handing the request to Node;
        # this makes the equality check meaningful for nested tool results.
        wire_payload = json.loads(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        replay_hash = canonical_sha256(wire_payload)
        request: dict[str, Any] = {
            "op": op,
            "session_id": replay_session,
            "payload": wire_payload,
        }
        if call_id is not None:
            request["call_id"] = call_id
        result = bridge.request(request)
        sent_events.append(
            {
                "source_event_id": event.get("event_id"),
                "source_op": op,
                "call_id": call_id,
                "detector_input_sha256": source_hash,
                "replayed_detector_input_sha256": replay_hash,
                "input_identical": source_hash == replay_hash,
                "decision": result.get("decision"),
                "policy_decision": result.get("policy_decision"),
            }
        )
        return result

    start = events[0]
    send(start, "start")
    for event in events[1:]:
        routing = event.get("routing") or {}
        op = routing.get("op")
        call_id = routing.get("opaque_call_id")
        if op == "before_tool":
            if not isinstance(call_id, str) or not call_id:
                raise ReplayError(f"before_tool event {event.get('event_id')} has no call id")
            if stopped:
                if call_id in target_call_ids:
                    decisions[call_id] = {
                        "call_id": call_id,
                        "atoms": target_atoms.get(call_id, []),
                        "decision": "unreachable",
                        "reason": "earlier intervention stopped enforced replay prefix",
                    }
                continue
            result = send(event, op, call_id)
            decision = str(result.get("decision") or "unknown")
            if call_id in target_call_ids:
                decisions[call_id] = {
                    "call_id": call_id,
                    "atoms": target_atoms.get(call_id, []),
                    "decision": decision,
                    "policy_decision": result.get("policy_decision"),
                    "normalized_tool": result.get("normalized_tool"),
                }
            if decision == "allow":
                pending.add(call_id)
            else:
                stopped = True
                if first_intervention is None:
                    first_intervention = {
                        "call_id": call_id,
                        "event_id": event.get("event_id"),
                        "decision": decision,
                        "policy_decision": result.get("policy_decision"),
                        "is_target": call_id in target_call_ids,
                    }
        elif op == "after_tool":
            if not isinstance(call_id, str) or call_id not in pending:
                continue
            send(event, op, call_id)
            pending.remove(call_id)
        elif op == "end":
            continue
        else:
            raise ReplayError(f"unsupported source event op {op!r}")

    for call_id in target_call_ids:
        decisions.setdefault(
            call_id,
            {
                "call_id": call_id,
                "atoms": target_atoms.get(call_id, []),
                "decision": "unreachable",
                "reason": "target was not reached in replayed prefix",
            },
        )
    values = {item["decision"] for item in decisions.values()}
    if "deny" in values:
        trial_decision = "deny"
    elif "ask" in values:
        trial_decision = "ask"
    elif values and values <= {"allow"}:
        trial_decision = "allow"
    elif values and values <= {"unreachable"}:
        trial_decision = "unreachable"
    else:
        trial_decision = "mixed"
    return {
        "source_trial_id": source_trial_id,
        "replay_session_id": replay_session,
        "target_call_count": len(target_call_ids),
        "target_decisions": [decisions[key] for key in sorted(decisions)],
        "trial_decision": trial_decision,
        "first_intervention": first_intervention,
        "replayed_event_count": len(sent_events),
        "input_mismatch_count": sum(not item["input_identical"] for item in sent_events),
        "replayed_events": sent_events,
        "side_effects_executed": False,
    }


def run_replay(run: Run, selection_path: Path, node: str, bridge_path: Path, disable_judge: bool) -> dict[str, Any]:
    if run.arm != "no-defense":
        raise ReplayError("observed-sink replay requires a no-defense source arm")
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    pair_meta = build_pair_metadata(selection)
    rows = analyze_run_rows(run, pair_meta)
    events = grouped_events(run.path)
    source_result_path = run.path / "result.public.json"
    source_result = json.loads(source_result_path.read_text(encoding="utf-8")) if source_result_path.exists() else {}
    targets = [row for row in rows if row["high_risk_effect"]]
    bridge = JsonlBridge(node, bridge_path, disable_judge=disable_judge)
    trial_results: list[dict[str, Any]] = []
    try:
        metadata = bridge.request({"op": "ping"})
        for row in targets:
            atom_by_call: dict[str, list[str]] = defaultdict(list)
            for item in row["executed_atoms"]:
                call_id = item.get("call_id")
                if isinstance(call_id, str):
                    atom_by_call[call_id].append(str(item["atom"]))
            target_call_ids = set(atom_by_call)
            if not target_call_ids:
                raise ReplayError(f"target trial {row['trial_id']} has no replayable sink call")
            result = replay_trial(bridge, row["trial_id"], events[row["trial_id"]], target_call_ids, atom_by_call)
            result.update(
                {
                    "user_task_id": row["user_task_id"],
                    "injection_task_id": row["injection_task_id"],
                    "seed": row["seed"],
                    "official_security": row["official_security"],
                    "executed_atoms": row["executed_atoms"],
                }
            )
            trial_results.append(result)
    finally:
        bridge.close()

    trial_decisions = Counter(row["trial_decision"] for row in trial_results)
    target_decisions = Counter(
        target["decision"]
        for row in trial_results
        for target in row["target_decisions"]
    )
    replay_transcript = [
        event
        for row in trial_results
        for event in row["replayed_events"]
    ]
    return {
        "protocol": {"name": "agentsentry.agentdojo.native-eval-replay", "version": "1.0.0"},
        "source": {
            "model": run.model,
            "arm": run.arm,
            "run_id": run.path.name,
            "private_run_directory": str(run.path),
            "selection": str(selection_path),
            "selection_sha256": canonical_sha256(selection),
            "release_commit": (source_result.get("run") or {}).get("release_commit"),
            "detector_transcript_sha256": file_sha256(run.path / "detector-events.private.jsonl"),
            "audit_scope": "observed attack-related high-risk side-effect trials",
        },
        "policy": {
            "profile": metadata.get("profile"),
            "enforcement_mode": metadata.get("enforcement_mode"),
            "manifest_mapping_version": metadata.get("manifest_mapping_version"),
            "manifest_file_sha256": metadata.get("manifest_file_sha256"),
            "judge_disabled": disable_judge,
            "policy_release_commit": git_head(bridge_path.parents[1]),
            "bridge_script_sha256": file_sha256(bridge_path),
            "plugin_dist_sha256": sha256_tree(bridge_path.parents[1] / "dist"),
            "replay_semantics": "enforced_prefix; skipped after_tool never executes a benchmark tool",
        },
        "coverage": {
            "observed_side_effect_trials": len(targets),
            "replayed_side_effect_trials": len(trial_results),
            "target_sink_calls": sum(row["target_call_count"] for row in trial_results),
            "target_sink_decisions": dict(sorted(target_decisions.items())),
            "trial_decisions": dict(sorted(trial_decisions.items())),
            "protected_trials": sum(row["trial_decision"] in {"deny", "ask", "unreachable"} for row in trial_results),
            "input_mismatch_count": sum(row["input_mismatch_count"] for row in trial_results),
            "replay_transcript_sha256": canonical_sha256(replay_transcript),
            "side_effects_executed": False,
        },
        "trials": trial_results,
    }


def public_aggregate(payload: dict[str, Any]) -> dict[str, Any]:
    """Project a replay result to the committed label-free aggregate schema."""

    source = payload["source"]
    policy = payload["policy"]
    coverage = payload["coverage"]
    required_commitments = ("release_commit", "selection_sha256", "detector_transcript_sha256")
    if any(not isinstance(source.get(key), str) for key in required_commitments):
        raise ReplayError("public replay output requires source commitments")
    policy_commitments = ("policy_release_commit", "bridge_script_sha256", "plugin_dist_sha256")
    if any(not isinstance(policy.get(key), str) for key in policy_commitments):
        raise ReplayError("public replay output requires frozen policy commitments; pass --bridge to a clean checkout")
    return {
        "$schema": "https://agentsentry.dev/schemas/agentdojo-native-replay-v1.json",
        "protocol": payload["protocol"],
        "visibility": "public_aggregate",
        "source": {
            "model": source["model"],
            "arm": source["arm"],
            "run_id": source["run_id"],
            "release_commit": source["release_commit"],
            "benchmark": "AgentDojo v1.2.2 workspace",
            "selection_sha256": source["selection_sha256"],
            "detector_transcript_sha256": source["detector_transcript_sha256"],
            "audit_scope": source["audit_scope"],
        },
        "policy": {
            "profile": policy["profile"],
            "enforcement_mode": policy["enforcement_mode"],
            "manifest_mapping_version": policy["manifest_mapping_version"],
            "manifest_file_sha256": policy["manifest_file_sha256"],
            "judge_disabled": policy["judge_disabled"],
            "policy_release_commit": policy["policy_release_commit"],
            "bridge_script_sha256": policy["bridge_script_sha256"],
            "plugin_dist_sha256": policy["plugin_dist_sha256"],
            "replay_semantics": policy["replay_semantics"],
        },
        "coverage": {
            "observed_side_effect_trials": coverage["observed_side_effect_trials"],
            "replayed_side_effect_trials": coverage["replayed_side_effect_trials"],
            "target_sink_calls": coverage["target_sink_calls"],
            "target_sink_decisions": coverage["target_sink_decisions"],
            "trial_decisions": coverage["trial_decisions"],
            "protected_trials": coverage["protected_trials"],
            "input_mismatch_count": coverage["input_mismatch_count"],
            "replay_transcript_sha256": coverage["replay_transcript_sha256"],
            "side_effects_executed": coverage["side_effects_executed"],
        },
        "interpretation": (
            "Trial-level observed-malicious-sink replay coverage counts trajectories intercepted at or before "
            "malicious-sink execution. Call-level deny counts only reached blocking boundaries; downstream target "
            "calls after the first intervention are unreachable, not independently executable policy decisions. "
            "This is not end-to-end ASR and not a matched generation replay."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", help="model|arm|private-run-directory", default=f"deepseek/deepseek-v4-pro|no-defense|{DEFAULT_SOURCE}")
    parser.add_argument("--selection", type=Path, default=DEFAULT_SELECTION)
    parser.add_argument("--node", default="node")
    parser.add_argument("--bridge", type=Path, default=BRIDGE, help="policy bridge; point at a frozen checkout for reproducible replay")
    parser.add_argument("--disable-judge", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--public-output", type=Path, help="write the schema-validated aggregate without private trials")
    args = parser.parse_args(argv)
    payload = run_replay(
        parse_run(args.run),
        args.selection.resolve(),
        args.node,
        args.bridge.resolve(),
        args.disable_judge,
    )
    output = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    if args.public_output:
        args.public_output.parent.mkdir(parents=True, exist_ok=True)
        args.public_output.write_text(
            json.dumps(public_aggregate(payload), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
