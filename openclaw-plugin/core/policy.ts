import { PluginConfig } from "../config.ts";
import type { DetectionFinding } from "./detect.ts";
import { deriveTaskSpecV2, type TaskSpec } from "./task-spec/index.ts";
import type { AgentSentryAction, PolicyState, PolicyDecision, PolicyEvaluation, PolicyDecisionContext } from "./policy/contracts.ts";
import { evaluateMutable } from "./policy/rules.ts";
import { normalizeFindingInput } from "./policy/support.ts";

export { createPolicyState, applyEffects, checkpointPolicyState, restorePolicyStateCheckpoint, PolicyStateConflictError } from "./policy/state.ts";
export type { AgentSentryAction, Label, RuntimeFeedbackProfile, IFCBranch, PolicyState, PolicyDecision, PolicyEffects, PolicyEvaluation, PolicyStateCheckpoint, PolicyDecisionContext, TaskSpec } from "./policy/contracts.ts";
export { targetMatches } from "./security/url.ts";
export { normalizeAction } from "./policy/actions.ts";
export { labelToolResult, resultFindings } from "./policy/results.ts";
export { applyExposureTaint } from "./policy/exposure.ts";
export { hydratePersistentMemoryLabels, updateTaskSpec, updateAfterMessage, updateAfterDecision, updateAfterRuntimeFindings, updateActionGraphEnforcement, policyTrustSnapshot } from "./policy/updates.ts";

export function decideAction(
  action: AgentSentryAction,
  state: PolicyState,
  config: PluginConfig,
  incomingFindings: DetectionFinding[],
  context: PolicyDecisionContext = {},
): PolicyDecision {
  const evaluation = evaluate(state, action, config, incomingFindings, context);
  return evaluation.decision;
}

export function evaluate(
  snapshot: PolicyState,
  action: AgentSentryAction,
  config: PluginConfig,
  incomingFindings: DetectionFinding[] = [],
  context: PolicyDecisionContext = {},
): PolicyEvaluation {
  const evaluationState = structuredClone(snapshot);
  const decision = evaluateMutable(action, evaluationState, config, incomingFindings, context);
  const effects = {
    baseRevision: snapshot.sessionRevision,
    semanticActionGraph: evaluationState.semanticActionGraph,
    apiCallCounts: evaluationState.apiCallCounts,
    dataProvenance: evaluationState.dataProvenance,
    taintFlows: evaluationState.taintFlows,
  };
  decision.effects = effects;
  return { decision, effects };
}

export function mostSevereVerdict(findings: DetectionFinding[]): "pass" | "require_approval" | "block" {
  const normalized = normalizeFindingInput(findings);
  if (normalized.invalidCount || normalized.findings.some((item) => item.verdict === "block")) return "block";
  if (normalized.findings.some((item) => item.verdict === "require_approval")) return "require_approval";
  return "pass";
}

export function deriveTaskSpec(task: string, sensitiveAssets: string[]): TaskSpec {
  return deriveTaskSpecV2(task, sensitiveAssets, "user");
}
