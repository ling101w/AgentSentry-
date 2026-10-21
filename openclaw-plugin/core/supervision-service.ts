import { performance } from "node:perf_hooks";
import type { PluginConfig } from "../config.ts";
import { detectToolCall, type DetectionContext, type DetectionResult } from "./detect.ts";
import { updateAfterDecision, updateActionGraphEnforcement, type PolicyDecision, type PolicyState } from "./policy.ts";
import {
  semanticBudgetMs, semanticGateForMemoryWrite, semanticGateForToolCall,
  semanticJudgeAmbiguousAction, semanticJudgeMemoryWrite, semanticJudgeToolCall,
} from "./semantic.ts";

export type SupervisionRequest = {
  toolName: string;
  params: Record<string, unknown>;
  state: PolicyState;
  config: PluginConfig;
  context?: DetectionContext;
  /** Adapters can retain their established Judge routes during migration. */
  judgeRoutes?: "full" | "ambiguous";
  onPreliminary?: (result: DetectionResult, snapshot: PolicyState) => void | Promise<void>;
};

/** Owns the deterministic -> semantic -> final decision pipeline. Evaluation is read-only. */
export class SupervisionService {
  async evaluate(request: SupervisionRequest) {
    const toolName = request.toolName;
    const state = structuredClone(request.state);
    const config = structuredClone(request.config);
    const params = structuredClone(request.params);
    const context = { ...request.context };
    const preliminaryStartedAt = performance.now();
    const preliminary = detectToolCall(toolName, params, config, state, [], context);
    const preliminaryPolicyMs = performance.now() - preliminaryStartedAt;
    await request.onPreliminary?.(preliminary, state);
    const skipSemantic = preliminary.policy.deterministic_block && preliminary.decision === "deny";
    const deadlineMs = Date.now() + semanticBudgetMs(config);
    const full = request.judgeRoutes === "full";
    const toolJudgeRouted = full && !skipSemantic && semanticGateForToolCall(toolName, params, config, {
      policyState: state, relatedFindings: preliminary.policy.findings,
    }).shouldJudge;
    const toolStartedAt = performance.now();
    const toolFindings = toolJudgeRouted ? await semanticJudgeToolCall(toolName, params, state.currentTask, config, {
      policyState: state, relatedFindings: preliminary.policy.findings, deadlineMs,
    }) : [];
    const semanticToolMs = performance.now() - toolStartedAt;
    const memoryContent = firstString(params, ["content", "body", "text", "value", "payload", "new_string", "replacement", "patch"]) || params;
    const memoryJudgeRouted = full && !skipSemantic && Date.now() < deadlineMs
      && preliminary.policy.action.tool === "memory_write" && semanticGateForMemoryWrite(memoryContent, config).shouldJudge;
    const memoryStartedAt = performance.now();
    const memoryFindings = memoryJudgeRouted ? await semanticJudgeMemoryWrite(memoryContent, state.currentTask, config, {
      policyState: state, relatedFindings: preliminary.policy.findings, deadlineMs,
    }) : [];
    const semanticMemoryMs = performance.now() - memoryStartedAt;
    const ambiguousJudgeRouted = !skipSemantic && Date.now() < deadlineMs && config.semantic.enabled
      && config.semantic.judgeToolCalls && config.semantic.mode !== "off"
      && preliminary.policy.deterministic_disposition === "ambiguous";
    const ambiguousStartedAt = performance.now();
    const ambiguousFindings = ambiguousJudgeRouted ? await semanticJudgeAmbiguousAction({
      action: preliminary.policy.action, taskSpec: preliminary.policy.task_spec, policyState: state, preliminary: preliminary.policy,
    }, config, { deadlineMs }) : [];
    const semanticAmbiguousMs = performance.now() - ambiguousStartedAt;
    const findings = [...toolFindings, ...memoryFindings, ...ambiguousFindings];
    const finalStartedAt = performance.now();
    const result = findings.length ? detectToolCall(toolName, params, config, state, findings, context) : preliminary;
    return {
      result, preliminary, config,
      timings: { preliminaryPolicyMs, semanticToolMs, semanticMemoryMs, semanticAmbiguousMs, finalPolicyMs: findings.length ? performance.now() - finalStartedAt : 0 },
      routes: { toolJudgeRouted, memoryJudgeRouted, ambiguousJudgeRouted },
    };
  }

  /** Must run synchronously after evaluation; effects enforce compare-and-swap. */
  commit(state: PolicyState, decision: PolicyDecision, config: PluginConfig, status: "executing" | "blocked" | "awaiting_approval"): void {
    updateAfterDecision(state, decision, config);
    updateActionGraphEnforcement(state, decision, status);
  }
}

function firstString(params: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    if (typeof params[key] === "string" && params[key].trim()) return params[key];
  }
  return "";
}

export const supervisionService = new SupervisionService();
