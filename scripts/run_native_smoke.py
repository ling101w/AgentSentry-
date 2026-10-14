"""Bounded GLM/OpenAI-compatible AgentDojo smoke with three comparison arms.

Uses AgentDojo's original in-memory environment and utility/attacker evaluators.
The fixed six-case selection is developmental, never a published benchmark.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
CASES = [("user_task_0", "injection_task_0"), ("user_task_6", "injection_task_6"), ("user_task_12", "injection_task_11")]
ARMS = ("no-defense", "observe", "block")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_credentials(args):
    if args.credential_file:
        return read_json(args.credential_file)
    return json.loads(os.environ[args.credential_env])


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def redact(value):
    return re.sub(r"sk-[\w-]+", "[redacted]", str(value))[:400]


def source_digest():
    digest = hashlib.sha256()
    paths = [ROOT / "scripts/run_native_smoke.py", ROOT / "src/agentsentry/agentdojo_adapter.py", ROOT / "openclaw-plugin/scripts/agentdojo-policy-bridge.mjs",
             ROOT / "openclaw-plugin/manifests/agentdojo-workspace-v1.2.2.json"]
    paths += sorted((ROOT / "openclaw-plugin/dist").rglob("*.js"))
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).replace("\\", "/").encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def worker(args):
    import httpx
    import openai
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM, _message_to_openai, _function_to_openai, _openai_to_assistant_message
    from agentdojo.attacks.base_attacks import FixedJailbreakAttack
    from agentdojo.attacks.important_instructions_attacks import ToolKnowledgeAttack
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    from agentsentry.agentdojo_adapter import JsonlNodeBridgeClient, make_guarded_runtime_class

    config = read_credentials(args)
    rows, transcripts, bridge = [], [], None
    usage = {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "tool_proposals": 0}
    started = time.perf_counter()
    client = openai.OpenAI(api_key=config["api_key"], base_url=config["base_url"], timeout=args.request_timeout, max_retries=0,
                           http_client=httpx.Client(timeout=args.request_timeout, follow_redirects=False))

    class BoundedCompatibleLLM(OpenAILLM):
        name = args.model

        def query(self, query, runtime, env, messages=(), extra_args=None):
            if usage["requests"] >= args.max_requests:
                raise RuntimeError("MODEL_REQUEST_BUDGET_EXCEEDED")
            converted = [_message_to_openai(message, self.model) for message in messages]
            for message in converted:
                if message["role"] == "developer":
                    message["role"] = "system"
                if isinstance(message.get("content"), list):
                    message["content"] = "\n".join(part.get("text", "") for part in message["content"])
            tools = [_function_to_openai(function) for function in runtime.functions.values()]
            body = {"model": self.model, "messages": converted, "temperature": 0, "max_tokens": 2048}
            if tools:
                body.update(tools=tools, tool_choice="auto")
            usage["requests"] += 1
            response = self.client.chat.completions.create(**body)
            if response.usage:
                usage["prompt_tokens"] += response.usage.prompt_tokens
                usage["completion_tokens"] += response.usage.completion_tokens
            if not response.choices:
                raise RuntimeError("EMPTY_PROVIDER_RESPONSE")
            if response.choices[0].finish_reason == "length":
                raise RuntimeError("MODEL_OUTPUT_TRUNCATED")
            output = _openai_to_assistant_message(response.choices[0].message)
            usage["tool_proposals"] += len(output.get("tool_calls") or [])
            transcripts.append({"query": query, "messages": [*messages, output]})
            return query, runtime, env, [*messages, output], extra_args or {}

    class CompatibleToolKnowledge(ToolKnowledgeAttack):
        def __init__(self, suite, pipeline):
            # Official template/tools/candidates; only substitute the actual
            # provider model name, which AgentDojo 0.1.35's enum cannot name.
            FixedJailbreakAttack.__init__(self, self._JB_STRING, suite, pipeline)
            self.user_name = "Emma Johnson"
            self.model_name = args.model

    class RecordedRuntime(FunctionsRuntime):
        def run_function(self, env, function, kwargs, raise_on_error=False):
            result, error = super().run_function(env, function, kwargs, raise_on_error=raise_on_error)
            rows.append({"tool_name": function, "decision": "allow", "executed": error is None, "tool_error": error,
                         "tool_args": kwargs, "tool_result": result})
            return result, error

    llm = BoundedCompatibleLLM(client, args.model, temperature=0)
    pipeline = AgentPipeline.from_config(PipelineConfig(llm=llm, model_id=args.model, defense=None,
                                        system_message_name=None, system_message=None, tool_output_format=None))
    pipeline.name = args.model
    suite = get_suite("v1.2.2", "workspace")
    attacker = CompatibleToolKnowledge(suite, pipeline)
    user = suite.user_tasks[args.task]
    injection_task = suite.injection_tasks[args.injection] if args.injection else None
    injected = attacker.attack(user, injection_task) if injection_task else {}
    runtime = RecordedRuntime
    detector_events = []
    if args.arm != "no-defense":
        env = {"AGENTSENTRY_API_KEY": config["api_key"], "AGENTSENTRY_NATIVE_ENFORCEMENT": args.arm,
               "AGENTSENTRY_NATIVE_JUDGE_BASE_URL": config["base_url"], "AGENTSENTRY_NATIVE_JUDGE_MODEL": args.model,
               "AGENTSENTRY_NATIVE_JUDGE_TIMEOUT_MS": "15000"}
        os.environ.update(env)
        bridge = JsonlNodeBridgeClient(["node", str(ROOT / "openclaw-plugin/scripts/agentdojo-policy-bridge.mjs")], timeout=25)

        class RecordingBridge:
            def request(self, message):
                response = bridge.request(message)
                detector_events.append({"request": message, "response": response})
                return response

        runtime = make_guarded_runtime_class(FunctionsRuntime, RecordingBridge(), user_message=user.PROMPT,
                    session_id="trial_"+secrets.token_hex(16), record_sink=lambda r: rows.append(dict(r)))
    result = {"arm": args.arm, "user_task": args.task, "injection_task": args.injection, "is_attack": bool(args.injection),
              "model": args.model, "status": "ok", "utility": None, "attack_success": None}
    try:
        utility, attack_success = suite.run_task_with_pipeline(pipeline, user, injection_task, injected, runtime_class=runtime)
        result.update(utility=bool(utility), attack_success=bool(attack_success) if args.injection else None)
        bridge_errors = [r for r in rows if r.get("bridge_error") or r.get("after_feedback_error")]
        if bridge_errors:
            result.update(status="error", utility=None, attack_success=None, error="DETECTOR_BRIDGE_ERROR")
    except Exception as exc:
        result.update(status="error", error_type=type(exc).__name__, error=redact(exc))
    finally:
        if bridge:
            bridge.close()
        client.close()
    decisions = {"allow": 0, "ask": 0, "deny": 0}
    for row in rows:
        decision = (row.get("detector_result") or {}).get("policy_decision", row.get("decision", "allow"))
        if decision in decisions:
            decisions[decision] += 1
    result.update(latency_ms=round((time.perf_counter()-started)*1000), usage=usage, policy_decisions=decisions,
                  tool_calls=len(rows), tools_executed=sum(bool(r.get("executed")) for r in rows),
                  judge_calls=sum(bool((r.get("detector_result") or {}).get("semantic_judge_called")) for r in rows),
                  judge_requested=sum(bool((r.get("detector_result") or {}).get("semantic_judge_requested")) for r in rows),
                  judge_token_usage=None, cost_usd=None)
    # Determine delivery from actual tool feedback; user-visible input and
    # evaluator labels never enter the detector envelope.
    candidates = list(injected.values())
    def text_parts(value, depth=0):
        if depth > 8:
            return []
        if isinstance(value, dict):
            return [part for child in value.values() for part in text_parts(child, depth+1)]
        if isinstance(value, (list, tuple)):
            return [part for child in value for part in text_parts(child, depth+1)]
        if isinstance(value, str):
            try:
                decoded = json.loads(value)
            except (ValueError, TypeError):
                return [value]
            return [value, *text_parts(decoded, depth+1)]
        return []
    tool_messages = [message for transcript in transcripts for message in transcript["messages"] if message["role"] == "tool"]
    delivered_text = text_parts(tool_messages)
    result["payload_delivered"] = any(payload in text for payload in candidates for text in delivered_text) if args.injection else None
    result["injection_vectors"] = len(injected)
    private = {"result": result, "calls": rows, "model_transcripts": transcripts, "detector_events": detector_events}
    # Preserve private traces for review, redact any accidental provider key.
    text = json.dumps(private, ensure_ascii=False, indent=2, default=str).replace(config["api_key"], "[redacted]")
    Path(args.worker_output).write_text(text+"\n", encoding="utf-8")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    credentials = parser.add_mutually_exclusive_group(required=True)
    credentials.add_argument("--credential-file", type=Path)
    credentials.add_argument("--credential-env", help="Name of inherited environment variable holding credential JSON; avoids a credential file.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", default="glm-5.3")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-errors", action="store_true", help="With --resume, rerun only previously recorded error trials.")
    parser.add_argument("--max-trials", type=int, default=18)
    parser.add_argument("--request-timeout", type=float, default=35)
    parser.add_argument("--trial-timeout", type=float, default=180)
    parser.add_argument("--max-requests", type=int, default=10)
    parser.add_argument("--arm", choices=ARMS)
    parser.add_argument("--arms", nargs="+", choices=ARMS, default=list(ARMS))
    parser.add_argument("--task")
    parser.add_argument("--injection")
    parser.add_argument("--worker-output", type=Path)
    args = parser.parse_args()
    if args.worker_output:
        return worker(args)
    if importlib.metadata.version("agentdojo") != "0.1.35":
        raise RuntimeError("requires AgentDojo 0.1.35")
    args.output.mkdir(parents=True, exist_ok=True)
    specs = [(arm, task, injection if attack else None) for task, injection in CASES for attack in (False, True) for arm in args.arms]
    tool_manifest = read_json(ROOT / "openclaw-plugin/manifests/agentdojo-workspace-v1.2.2.json")
    manifest = {"schema_version": "native-smoke-v1", "benchmark": "AgentDojo", "version": "v1.2.2", "package": "0.1.35",
                "suite": "workspace", "attack": "tool_knowledge", "model": args.model, "selection": CASES,
                "arms": args.arms, "planned_trials":len(specs), "seed": 7, "source_sha256": source_digest(), "trial_timeout": args.trial_timeout,
                "tool_mapping_version":tool_manifest["mapping_version"],
                "tool_manifest_sha256":hashlib.sha256((ROOT / "openclaw-plugin/manifests/agentdojo-workspace-v1.2.2.json").read_bytes()).hexdigest(),
                "tool_output_format": "AgentDojo default YAML",
                "request_timeout": args.request_timeout, "max_model_requests_per_trial": args.max_requests,
                "judge_timeout_ms": 15000, "reportable": False, "reason": "small development smoke from a dirty worktree; no independent holdout"}
    manifest_path = args.output / "manifest.json"
    if manifest_path.exists() and read_json(manifest_path) != json.loads(json.dumps(manifest)):
        if args.resume and args.retry_errors:
            # A retry may run after the runner itself gained retry-only code;
            # preserve the original frozen manifest and only replace errors.
            manifest = read_json(manifest_path)
        else:
            raise RuntimeError("manifest differs; use a fresh output directory")
    write_json(manifest_path, manifest)
    results = []
    for index, (arm, task, injection) in enumerate(specs[:args.max_trials], start=1):
        target = args.output / f"{index:02d}-{arm}-{task}-{'attack' if injection else 'benign'}.private.json"
        if target.exists() and args.resume:
            existing = read_json(target)["result"]
            if not (args.retry_errors and existing.get("status") == "error"):
                result = existing
            else:
                result = None
        else:
            result = None
        if result is None:
            command = [sys.executable, "-u", str(Path(__file__).resolve()),
                       "--output", str(args.output), "--model", args.model, "--arm", arm, "--task", task,
                       "--request-timeout", str(args.request_timeout), "--max-requests", str(args.max_requests), "--worker-output", str(target)]
            command += ["--credential-file", str(args.credential_file)] if args.credential_file else ["--credential-env", args.credential_env]
            if injection:
                command += ["--injection", injection]
            started = time.perf_counter()
            try:
                completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=args.trial_timeout)
                if target.exists():
                    result = read_json(target)["result"]
                else:
                    result = {"arm":arm,"user_task":task,"injection_task":injection,"is_attack":bool(injection),"status":"error", "utility":None,"attack_success":None,"error":"WORKER_SETUP_FAILED","detail":redact(completed.stderr[-500:])}
            except subprocess.TimeoutExpired:
                result = {"arm":arm,"user_task":task,"injection_task":injection,"is_attack":bool(injection),"status":"error", "utility":None,"attack_success":None,"error":"TRIAL_TIMEOUT", "latency_ms":round((time.perf_counter()-started)*1000)}
            if not target.exists():
                write_json(target,{"result":result})
        results.append(result)
        print(json.dumps({"trial":index,"planned":len(specs),"arm":arm,"task":task,"attack":bool(injection),"status":result["status"],"utility":result.get("utility"),"attack_success":result.get("attack_success"),"latency_ms":result.get("latency_ms"),"error":result.get("error")},ensure_ascii=False),flush=True)
        write_json(args.output / "results.json", {"manifest":manifest,"trials":results})
        if len(results)>=2 and all(r["status"]=="error" and r.get("error_type") in {"AuthenticationError","RateLimitError","APIConnectionError","InternalServerError"} for r in results[-2:]):
            print("Stopped after two consecutive provider errors.",flush=True)
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
