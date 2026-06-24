from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any

from .llm import ActionParseError, FakeLLM, LLMClient, OpenAICompatibleClient, parse_action
from .models import DataValue, Decision, Event, RunRequest, RunResponse, ToolAction, ToolResult, new_id
from .policy import Policy, PolicyEngine, combine_labels, derive_task_spec, unwrap_arg
from .sentry import BehaviorSentry
from .storage import Store
from .tools import SandboxTools


@dataclass(frozen=True)
class DefenseToggles:
    deterministic: bool = True
    sentry: bool = True
    feedback: bool = True


def toggles_for_mode(mode: str) -> DefenseToggles:
    return {
        "full": DefenseToggles(True, True, True),
        "no_deterministic": DefenseToggles(False, True, True),
        "no_sentry": DefenseToggles(True, False, False),
        "no_feedback": DefenseToggles(True, True, False),
        "none": DefenseToggles(False, False, False),
    }.get(mode, DefenseToggles(True, True, True))


class AgentSupervisor:
    def __init__(self, store: Store, policy: Policy, tools: SandboxTools, llm: LLMClient | None = None):
        self.store = store
        self.policy = policy
        self.tools = tools
        self.llm = llm

    def run(self, request: RunRequest) -> RunResponse:
        run_id = new_id("run")
        toggles = toggles_for_mode(request.defense_mode)
        task_spec = derive_task_spec(request.task, self.policy.sensitive_assets)
        engine = PolicyEngine(self.policy, deterministic_enabled=toggles.deterministic)
        sentry = BehaviorSentry(enabled=toggles.sentry, feedback_enabled=toggles.feedback)
        llm = FakeLLM(request.scenario) if request.use_fake_llm or request.scenario else self.llm or OpenAICompatibleClient()
        history: list[dict[str, Any]] = []
        decisions: list[dict[str, Any]] = []
        last_result: ToolResult | None = None
        final_output = ""

        self.store.create_run(run_id, request.task, request.scenario, request.defense_mode)
        self._event(run_id, "task_spec", task_spec.model_dump())

        for _ in range(request.max_steps):
            started = perf_counter()
            try:
                raw_action = llm.next_action(request.task, history)
                action = parse_action(raw_action)
            except (ActionParseError, RuntimeError) as exc:
                decision = {
                    "tool": "parse_error",
                    "decision": Decision.DENY.value,
                    "risk_score": 100,
                    "reasons": [str(exc)],
                    "latency_ms": 0,
                }
                decisions.append(decision)
                self._event(run_id, "alert", decision)
                final_output = "Denied malformed or unavailable model action."
                break

            action = self._resolve_last(action, last_result)

            if action.tool == "final_answer":
                final_output = str(unwrap_arg(action.args.get("answer", "")))
                self._event(run_id, "final_answer", {"answer": final_output})
                break

            sentry_score, sentry_reasons = sentry.score(action, task_spec, history)
            policy_decision = engine.decide(action, task_spec, sentry_score=sentry_score)
            policy_decision.reasons.extend(sentry_reasons)

            result: ToolResult | None = None
            if policy_decision.decision in {Decision.ALLOW, Decision.ASK}:
                # "ask" is recorded as human-in-the-loop, but demo mode executes safe sandbox tools so the trace is complete.
                result = self.tools.execute(action.tool, action.args)
                last_result = result
            else:
                last_result = ToolResult(ok=False, error="blocked by AgentSentry", label=combine_labels(list(action.args.values())))

            latency_ms = int((perf_counter() - started) * 1000)
            decision_record = {
                "tool": action.tool,
                "args": _serializable_args(action.args),
                "reason": action.reason,
                "decision": policy_decision.decision.value,
                "risk_score": policy_decision.risk_score,
                "sentry_score": policy_decision.sentry_score,
                "reasons": policy_decision.reasons,
                "violations": policy_decision.violations,
                "deterministic_block": policy_decision.deterministic_block,
                "result": result.model_dump() if result else None,
                "latency_ms": latency_ms,
            }
            decisions.append(decision_record)
            history.append(decision_record)
            self._event(run_id, "tool_decision", decision_record)
            self._emit_taint_edges(run_id, action, result)
            if policy_decision.decision in {Decision.ASK, Decision.DENY}:
                self._event(run_id, "alert", decision_record)
            if action.tool.startswith("memory_"):
                self._event(run_id, "memory_audit", decision_record)

        if not final_output:
            final_output = "Run ended without final answer."
        self.store.finish_run(run_id, final_output)
        return RunResponse(run_id=run_id, task=request.task, scenario=request.scenario, decisions=decisions, final_output=final_output)

    def _resolve_last(self, action: ToolAction, last_result: ToolResult | None) -> ToolAction:
        if not last_result:
            return action
        resolved: dict[str, Any] = {}
        for key, value in action.args.items():
            if value == "$last":
                resolved[key] = DataValue(value=last_result.output, label=last_result.label)
            else:
                resolved[key] = value
        return ToolAction(tool=action.tool, args=resolved, reason=action.reason)

    def _event(self, run_id: str, event_type: str, payload: dict[str, Any]) -> None:
        self.store.add_event(Event(run_id=run_id, type=event_type, payload=payload))

    def _emit_taint_edges(self, run_id: str, action: ToolAction, result: ToolResult | None) -> None:
        for name, value in action.args.items():
            if isinstance(value, DataValue):
                self._event(
                    run_id,
                    "taint_edge",
                    {
                        "from": value.label.source,
                        "to": f"{action.tool}.{name}",
                        "integrity": value.label.integrity.value,
                        "confidentiality": value.label.confidentiality.value,
                    },
                )
        if result and result.label.tainted:
            self._event(
                run_id,
                "taint_edge",
                {
                    "from": action.tool,
                    "to": result.label.source,
                    "integrity": result.label.integrity.value,
                    "confidentiality": result.label.confidentiality.value,
                },
            )


def _serializable_args(args: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in args.items():
        if isinstance(value, DataValue):
            clean[key] = value.model_dump()
        else:
            clean[key] = value
    return clean

