from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from time import perf_counter
from typing import Any

from .llm import ActionParseError, DeterministicLLM, LLMClient, OpenAICompatibleClient, parse_action
from .guard import HIGH_RISK_SINKS, GuardContext, GuardPipeline, heuristic_score, most_severe_verdict
from .models import Confidentiality, DataValue, Decision, DetectionVerdict, Event, ExecutionStatus, FindingType, GuardFinding, Integrity, Label, RunRequest, RunResponse, ToolAction, ToolResult, new_id
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
        run_id = request.run_id or new_id("run")
        toggles = toggles_for_mode(request.defense_mode)
        task_spec = derive_task_spec(request.task, self.policy.sensitive_assets)
        engine = PolicyEngine(self.policy, deterministic_enabled=toggles.deterministic, risk_scoring_enabled=toggles.sentry)
        guard = GuardPipeline(self.policy, enabled=toggles.sentry, feedback_enabled=toggles.feedback)
        foundation_guard = GuardPipeline(self.policy, enabled=toggles.deterministic or toggles.sentry, feedback_enabled=toggles.feedback)
        behavior_sentry = BehaviorSentry(enabled=toggles.sentry, feedback_enabled=toggles.feedback)
        llm = DeterministicLLM(request.scenario) if request.scripted_llm else self.llm or OpenAICompatibleClient()
        history: list[dict[str, Any]] = []
        decisions: list[dict[str, Any]] = []
        last_result: ToolResult | None = None
        final_output = ""
        context = GuardContext(task_spec=task_spec)
        exposures = ExposureTracker()

        self.store.create_run(run_id, request.task, request.scenario, request.defense_mode)
        self._event(run_id, "task_spec", task_spec.model_dump())
        foundation_findings = [
            finding
            for finding in foundation_guard.foundation_scan()
            if (toggles.deterministic or finding.finding_type != FindingType.DETERMINISTIC)
            and (toggles.sentry or finding.finding_type == FindingType.DETERMINISTIC)
        ]
        for finding in foundation_findings:
            context.record(finding)
            self._event(run_id, "foundation_scan", finding.model_dump(mode="json"))
            if finding.verdict == DetectionVerdict.BLOCK:
                self._event(run_id, "alert", finding.model_dump(mode="json"))

        if toggles.deterministic and any(
            finding.finding_type == FindingType.DETERMINISTIC and finding.verdict == DetectionVerdict.BLOCK
            for finding in foundation_findings
        ):
            final_output = "Denied by foundation scan."
            self.store.finish_run(run_id, final_output)
            return RunResponse(run_id=run_id, task=request.task, scenario=request.scenario, decisions=decisions, final_output=final_output)

        for _ in range(request.max_steps):
            started = perf_counter()
            raw_action = ""
            try:
                raw_action = llm.next_action(request.task, history)
                self._event(
                    run_id,
                    "llm_raw",
                    {
                        "raw": raw_action,
                        "preview": _preview_text(raw_action),
                        "step": len(history) + 1,
                    },
                )
                action = parse_action(raw_action)
            except RuntimeError as exc:
                self._event(
                    run_id,
                    "llm_raw",
                    {
                        "raw": "",
                        "preview": "",
                        "step": len(history) + 1,
                        "error": str(exc),
                    },
                )
                decision = {
                    "tool": "parse_error",
                    "decision": Decision.DENY.value,
                    "risk_score": 100,
                    "reasons": [str(exc)],
                    "raw_llm_output": "",
                    "raw_llm_preview": "",
                    "latency_ms": 0,
                }
                decisions.append(decision)
                self._event(run_id, "alert", decision)
                final_output = "Denied malformed or unavailable model action."
                break
            except ActionParseError as exc:
                decision = {
                    "tool": "parse_error",
                    "decision": Decision.DENY.value,
                    "risk_score": 100,
                    "reasons": [str(exc)],
                    "raw_llm_output": raw_action,
                    "raw_llm_preview": _preview_text(raw_action),
                    "latency_ms": 0,
                }
                decisions.append(decision)
                self._event(run_id, "alert", decision)
                final_output = "Denied malformed or unavailable model action."
                break

            action = _normalize_action(action)
            action = self._resolve_last(action, last_result)
            action, exposure_findings = exposures.apply(action) if toggles.deterministic else (action, [])

            if action.tool == "final_answer":
                final_output = str(unwrap_arg(action.args.get("answer", "")))
                self._event(run_id, "final_answer", {"answer": final_output})
                break

            step_findings = guard.before_action(action, context, history)
            for finding in exposure_findings:
                context.record(finding)
            step_findings.extend(exposure_findings)
            deterministic_findings = engine.deterministic_findings(action, task_spec)
            for finding in deterministic_findings:
                context.record(finding)
            step_findings.extend(deterministic_findings)

            sentry_score, sentry_reasons = behavior_sentry.score(action, task_spec, history)
            behavioral_findings = _behavioral_findings(sentry_score, sentry_reasons, action.tool) if toggles.sentry else []
            for finding in behavioral_findings:
                context.record(finding)
            step_findings.extend(behavioral_findings)
            h_score = heuristic_score(step_findings) if toggles.sentry else 0
            policy_decision = engine.decide(action, task_spec, sentry_score=h_score, findings=step_findings)
            policy_decision.reasons.extend(finding.reason for finding in step_findings if finding.finding_type != FindingType.DETERMINISTIC)

            result: ToolResult | None = None
            execution_status = ExecutionStatus.SKIPPED
            if policy_decision.decision == Decision.ALLOW:
                result = self.tools.execute(action.tool, action.args)
                last_result = result
                execution_status = ExecutionStatus.EXECUTED
                result_findings = guard.after_result(action, result, context)
                step_findings.extend(result_findings)
                exposures.record_result(action, result)
            else:
                last_result = ToolResult(ok=False, error="blocked by AgentSentry", label=combine_labels(list(action.args.values())))
                execution_status = ExecutionStatus.BLOCKED

            latency_ms = int((perf_counter() - started) * 1000)
            findings_json = [finding.model_dump(mode="json") for finding in step_findings]
            finding_type = _dominant_finding_type(step_findings)
            decision_record = {
                "tool": action.tool,
                "args": _serializable_args(action.args),
                "reason": action.reason,
                "raw_llm_output": raw_action,
                "raw_llm_preview": _preview_text(raw_action),
                "decision": policy_decision.decision.value,
                "risk_score": policy_decision.risk_score,
                "sentry_score": h_score,
                "heuristic_score": h_score,
                "reasons": policy_decision.reasons,
                "violations": policy_decision.violations,
                "deterministic_block": policy_decision.deterministic_block,
                "findings": findings_json,
                "finding_type": finding_type,
                "verdict": most_severe_verdict(step_findings).value,
                "execution_status": execution_status.value,
                "result": result.model_dump() if result else None,
                "latency_ms": latency_ms,
            }
            decisions.append(decision_record)
            history.append(decision_record)
            self._event(run_id, "tool_decision", decision_record)
            for finding in step_findings:
                self._event(run_id, "guard_finding", finding.model_dump(mode="json") | {"tool": action.tool})
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


@dataclass
class Exposure:
    source: str
    text: str
    label: Label


class ExposureTracker:
    """Tracks untrusted data the LLM has seen, even if it later inlines it as plain text."""

    def __init__(self) -> None:
        self._items: list[Exposure] = []

    @property
    def contaminated(self) -> bool:
        return bool(self._items)

    def record_result(self, action: ToolAction, result: ToolResult | None) -> None:
        if not result or not result.label.tainted:
            return
        text = _flatten_text(result.output)
        if not text.strip():
            return
        self._items.append(Exposure(source=result.label.source or action.tool, text=text, label=result.label))

    def apply(self, action: ToolAction) -> tuple[ToolAction, list[GuardFinding]]:
        if not self._items or action.tool not in HIGH_RISK_SINKS:
            return action, []

        args = dict(action.args)
        findings: list[GuardFinding] = []
        for key, value in list(args.items()):
            if isinstance(value, DataValue):
                continue
            text = _flatten_text(value)
            if not text.strip():
                continue
            exposure, mode = self._match(text)
            if exposure is None and self.contaminated and _is_sink_payload_arg(action.tool, key):
                exposure = self._combined_exposure()
                mode = "run_exposure_default"
            if exposure is None:
                continue
            args[key] = DataValue(value=value, label=exposure.label)
            findings.append(
                GuardFinding(
                    layer="Execution Control",
                    finding_type=FindingType.DETERMINISTIC,
                    verdict=DetectionVerdict.BLOCK,
                    reason="sink argument inherits untrusted run exposure",
                    score=100,
                    evidence={"tool": action.tool, "arg": key, "source": exposure.source, "match": mode},
                )
            )

        if not findings:
            return action, []
        return ToolAction(tool=action.tool, args=args, reason=action.reason), findings

    def _match(self, text: str) -> tuple[Exposure | None, str]:
        normalized = _normalize_text(text)
        for item in self._items:
            candidate = _normalize_text(item.text)
            if not normalized or not candidate:
                continue
            if normalized in candidate or candidate in normalized:
                return item, "substring"
            if min(len(normalized), len(candidate)) >= 32:
                ratio = SequenceMatcher(None, normalized[:1200], candidate[:1200]).ratio()
                if ratio >= 0.82:
                    return item, "fuzzy"
        return None, ""

    def _combined_exposure(self) -> Exposure:
        confidentiality = Confidentiality.PUBLIC
        sources: list[str] = []
        for item in self._items:
            sources.append(item.source)
            if item.label.confidentiality == Confidentiality.SECRET:
                confidentiality = Confidentiality.SECRET
            elif item.label.confidentiality == Confidentiality.INTERNAL and confidentiality != Confidentiality.SECRET:
                confidentiality = Confidentiality.INTERNAL
        source = "+".join(dict.fromkeys(sources))
        label = Label(source=source, integrity=Integrity.UNTRUSTED, confidentiality=confidentiality, tainted=True)
        return Exposure(source=source, text="", label=label)


def _behavioral_findings(score: int, reasons: list[str], tool: str) -> list[GuardFinding]:
    if score < 40:
        return []
    verdict = DetectionVerdict.BLOCK if score >= 70 else DetectionVerdict.REQUIRE_APPROVAL
    return [
        GuardFinding(
            layer="Behavior Sentry",
            finding_type=FindingType.BEHAVIORAL,
            verdict=verdict,
            reason="behavior sentry risk model flagged action",
            score=score,
            evidence={"tool": tool, "reasons": reasons},
        )
    ]


def _is_sink_payload_arg(tool: str, name: str) -> bool:
    payload_args = {
        "send_email": {"body", "content", "message"},
        "write_file": {"content", "body", "data"},
        "call_api": {"body", "payload", "data", "content"},
    }
    return name in payload_args.get(tool, set())


def _normalize_action(action: ToolAction) -> ToolAction:
    aliases = {
        "browser.open": "read_webpage",
        "browser_open": "read_webpage",
        "open_browser": "read_webpage",
        "fetch_url": "read_webpage",
        "web.open": "read_webpage",
    }
    tool = aliases.get(action.tool, action.tool)
    args = dict(action.args)
    if tool == "read_webpage" and "url" not in args:
        for key in ("uri", "href", "target"):
            if key in args:
                args["url"] = args[key]
                break
    return ToolAction(tool=tool, args=args, reason=action.reason)


def _dominant_finding_type(findings: list[GuardFinding]) -> str | None:
    if any(finding.finding_type == FindingType.DETERMINISTIC for finding in findings):
        return "deterministic"
    if any(finding.finding_type == FindingType.SEMANTIC for finding in findings):
        return "semantic"
    if any(finding.finding_type == FindingType.BEHAVIORAL for finding in findings):
        return "behavioral"
    if any(finding.finding_type == FindingType.LEARNED for finding in findings):
        return "learned"
    if any(finding.finding_type == FindingType.HEURISTIC for finding in findings):
        return "heuristic"
    return None


def _preview_text(value: str, limit: int = 500) -> str:
    text = value.replace("\r\n", "\n").strip()
    return text if len(text) <= limit else f"{text[:limit]}..."


def _flatten_text(value: Any) -> str:
    if isinstance(value, DataValue):
        return _flatten_text(value.value)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_flatten_text(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_text(item) for item in value)
    return str(value)


def _normalize_text(value: str) -> str:
    return " ".join(value.casefold().split())
