import { PluginConfig } from "../config.ts";
import type { SemanticGraph } from "./action-semantics.ts";
import { agentCommunicationFindings } from "./agent-trust.ts";
import type { DetectionFinding } from "./detect.ts";
import {
  createDynamicSecurityState,
  dynamicSecurityFindingsFor,
  dynamicSecuritySnapshot,
  recordDynamicSecurityEvent,
  type DynamicSecurityState,
} from "./dynamic-security.ts";
import { decisionFromRisk, mergeDecision } from "./judge/decision-merge.ts";
import { memoryContentHash, normalizeMemoryKey, type PersistentMemoryLabel } from "./memory-ifc.ts";
import {
  assessAction,
  assessActionWithSensitiveAssets,
  isOpenClawMemoryDocumentPath,
  isSensitivePath,
  isTrustSensitiveSink,
  shouldHardBlockTaskMismatch,
  sinkForAction,
  sourceForToolResult,
  type ActionAssessment,
} from "./policy/action-assessment.ts";
import { evaluateAbacDataFlow, type DataFlowTaintFlow } from "./policy/abac.ts";
import { behaviorAnomalyFindingsFor, updateBehaviorProfile, type BehaviorProfile } from "./policy/behavior-baseline.ts";
import { containsAny, flattenText as flattenValueText, hostFromUrl, isLabeledValue, readFirstString, unique } from "./policy/value-utils.ts";
import { clampText, safeStringify as redactSafeStringify } from "./redact.ts";
import { targetAllowed } from "./security/url.ts";
import { canonicalizePath, matchAllowedWritePath, matchWorkspaceReadPath } from "./path-security.ts";
import { isAbsolute, resolve } from "node:path";
import { createHash } from "node:crypto";
import {
  activateSemanticIntent,
  beginSemanticAction,
  completeSemanticAction,
  createSemanticActionGraph,
  markSemanticActionEnforcement,
  semanticActionGraphSnapshot,
  semanticActionResultContext,
  setSemanticActionDecision,
  type SemanticActionGraphState,
  type SemanticEvidenceBasis,
  type SemanticProvenanceLink,
} from "./semantic-action-graph.ts";
import {
  extractFieldProvenance,
  publicProvenance,
  semanticClaimsForValue,
  transformProvenance,
  type DataProvenance,
  type FieldProvenance,
  type SemanticClaim,
} from "./taint/provenance-graph.ts";
import {
  authorizeCapability,
  createAuthorizationState,
  deriveTaskSpecV2,
  updateAuthorizationState,
  isSideEffectToolCall,
  type AuthorizationState,
  type CapabilityAuthorization,
  type TaskSpec,
} from "./task-spec/index.ts";
import { resolveToolManifest, type ToolSecurityManifest } from "./tool-manifest.ts";
import {
  addRisk,
  analyzeTrustContent,
  createRiskVector,
  mergeRiskVectors,
  minimumTrustLabel,
  riskMax,
  sourceFromTool,
  taintProfileFromLabel,
  type RiskVector,
  type TaintProfile,
  type TrustLabel,
} from "./trust.ts";

export type AgentSentryAction = {
  tool: string;
  originalTool: string;
  args: Record<string, unknown>;
  reason: string;
};

export type { TaskSpec } from "./task-spec/index.ts";
export { targetMatches } from "./security/url.ts";

export type Label = {
  source: string;
  integrity: "trusted" | "untrusted";
  confidentiality: "public" | "internal" | "secret";
  tainted: boolean;
  provenance_untrusted?: boolean;
  influence?: "none" | "matched" | "payload_default";
  trust_label?: TrustLabel;
  risk_vector?: RiskVector;
  tags?: string[];
  /** Opaque, session-local correlation values for the data subject. */
  subject_scopes?: string[];
  taint_profile?: TaintProfile;
  provenance_ids?: string[];
};

export type RuntimeFeedbackProfile = {
  tool: string;
  runtime_alerts: number;
  risk_score: number;
  last_seen: string;
  reasons: string[];
  events: string[];
};

export type IFCBranch = {
  id: string;
  source: string;
  status: "isolated" | "merged";
  integrity: "system-trusted" | "user-trusted" | "untrusted-external";
  confidentiality: "public" | "internal" | "user-private" | "tenant-secret";
  purpose: string;
  summary: string;
  lifetime: "turn" | "session" | "memory" | "expired";
  createdAt: string;
  provenanceIds: string[];
  subjectScopes?: string[];
  risk: number;
  confidence: number;
};

export type PolicyState = {
  currentTask: string;
  taskSpec: TaskSpec;
  authorizationState: AuthorizationState;
  contaminated: boolean;
  provenanceBlocked: boolean;
  provenanceFindings: DetectionFinding[];
  history: Array<{
    tool: string;
    originalTool?: string;
    frequencyKey?: string;
    decision: "allow" | "ask" | "deny";
    risk_score: number;
  }>;
  toolResultLabels: Map<string, Label>;
  exposures: Array<{
    source: string;
    text: string;
    label: Label;
    provenanceId?: string;
    semanticClaims?: SemanticClaim[];
  }>;
  apiCallCounts: Map<string, number>;
  behaviorProfiles: Map<string, BehaviorProfile>;
  runtimeProfiles: Map<string, RuntimeFeedbackProfile>;
  trustLabels: TrustLabel[];
  aggregateRisk: RiskVector;
  taintedSources: string[];
  taintFlows: DataFlowTaintFlow[];
  dataProvenance: DataProvenance[];
  ifcBranches: IFCBranch[];
  persistentMemoryLabels: PersistentMemoryLabel[];
  semanticActionGraph: SemanticActionGraphState;
  dynamicSecurity: DynamicSecurityState;
};

export type PolicyDecision = {
  decision: "allow" | "ask" | "deny";
  risk_score: number;
  reasons: string[];
  violations: string[];
  deterministic_block: boolean;
  sentry_score: number;
  risk_vector: RiskVector;
  trust_labels: TrustLabel[];
  action: AgentSentryAction;
  task_spec: TaskSpec;
  findings: DetectionFinding[];
  action_graph_node_id: string;
  deterministic_disposition: "allow" | "deny" | "ambiguous";
  effects?: PolicyEffects;
};

export type PolicyEffects = {
  semanticActionGraph: SemanticActionGraphState;
  apiCallCounts: Map<string, number>;
  dataProvenance: DataProvenance[];
  taintFlows: PolicyState["taintFlows"];
};

export type PolicyEvaluation = { decision: PolicyDecision; effects: PolicyEffects };

export type PolicyStateCheckpoint = {
  version: 1;
  created_at: string;
  currentTask: string;
  taskSpec: TaskSpec;
  authorizationState: AuthorizationState;
  contaminated: boolean;
  provenanceBlocked: boolean;
  provenanceFindings: DetectionFinding[];
  history: PolicyState["history"];
  toolResultLabels: Array<[string, Label]>;
  exposures: PolicyState["exposures"];
  apiCallCounts: Array<[string, number]>;
  behaviorProfiles: Array<[string, BehaviorProfile]>;
  runtimeProfiles: Array<[string, RuntimeFeedbackProfile]>;
  trustLabels: TrustLabel[];
  aggregateRisk: RiskVector;
  taintedSources: string[];
  taintFlows: PolicyState["taintFlows"];
  dataProvenance: DataProvenance[];
  ifcBranches: IFCBranch[];
  persistentMemoryLabels: PersistentMemoryLabel[];
  semanticActionGraph: SemanticActionGraphState;
  dynamicSecurity: DynamicSecurityState;
};

export type PolicyDecisionContext = {
  toolCallId?: string;
  workspaceDir?: string;
  semanticGraph?: SemanticGraph;
  provenanceLinks?: SemanticProvenanceLink[];
  provenanceAdditions?: DataProvenance[];
};

const TOOL_ALIASES: Array<[RegExp, string]> = [
  [/^(browser\.open|browser_open|open_browser|fetch_url|web\.open|read_webpage)$/i, "read_webpage"],
  [/^(read|open)$/i, "read_file"],
  [/^(write|create|edit|replace|patch)$/i, "write_file"],
  [/(read|open|parse).*(email|mail)|email.*read|mail.*read/i, "read_webpage"],
  [/(read|parse|summarize).*pdf|pdf.*(read|parse|summarize)/i, "read_webpage"],
  [/(analy[sz]e|read|parse).*(image|picture|photo|ocr)|image.*(ocr|read|analy[sz]e)/i, "read_webpage"],
  [/(read|cat|get).*file|filesystem.*read/i, "read_file"],
  [/(write|create|edit).*file|filesystem.*write|apply_patch/i, "write_file"],
  [/(send).*email|mail/i, "send_email"],
  [/^(sessions_send|agent\.send|send_to_agent|handoff_message|agent_message)$/i, "sessions_send"],
  [/(fetch|request|http|api|curl|wget|browser)/i, "call_api"],
  [/(webhook|hooks?[./_-]?wake|wake_hook)/i, "memory_write"],
  [/(memory|remember).*write|write.*memory/i, "memory_write"],
  [/(memory|remember).*read|read.*memory/i, "memory_read"],
  [/(shell|command|exec|terminal|powershell|cmd)/i, "shell_exec"],
];

const HIGH_RISK_SINKS = new Set(["send_email", "call_api", "shell_exec", "memory_write"]);
const EXPLICIT_NO_EMAIL = ["do not email", "don't email", "no email", "不要发", "别发", "不要发送", "不要给任何人发"];

export function createPolicyState(): PolicyState {
  const taskSpec = deriveTaskSpec("", []);
  const authorizationState = createAuthorizationState([]);
  const semanticActionGraph = createSemanticActionGraph();
  activateSemanticIntent(semanticActionGraph, taskSpec);

  return {
    currentTask: "",
    taskSpec,
    authorizationState: { ...authorizationState, taskSpec },
    contaminated: false,
    provenanceBlocked: false,
    provenanceFindings: [],
    history: [],
    toolResultLabels: new Map(),
    exposures: [],
    apiCallCounts: new Map(),
    behaviorProfiles: new Map(),
    runtimeProfiles: new Map(),
    trustLabels: [],
    aggregateRisk: createRiskVector(),
    taintedSources: [],
    taintFlows: [],
    dataProvenance: [],
    ifcBranches: [],
    persistentMemoryLabels: [],
    semanticActionGraph,
    dynamicSecurity: createDynamicSecurityState(),
  };
}

export function hydratePersistentMemoryLabels(state: PolicyState, labels: PersistentMemoryLabel[]): void {
  const byKey = new Map<string, PersistentMemoryLabel>();
  for (const label of [...state.persistentMemoryLabels, ...labels].filter(isPersistentMemoryLabel)) {
    byKey.set(`${label.key}:${label.content_sha256}`, label);
  }
  state.persistentMemoryLabels = [...byKey.values()].slice(-400);
}

export function updateTaskSpec(state: PolicyState, messages: unknown, config: PluginConfig): void {
  const task = extractLatestUserText(messages);
  if (task === null || task === state.currentTask) return;
  const update = updateAuthorizationState(state.authorizationState, task, config.policy.sensitiveAssets);
  state.authorizationState = update.state;
  state.currentTask = update.state.lastMessage;
  // Keep the authoritative request available even when the structured
  // extractor cannot derive a concrete capability from natural language.
  // An empty TaskSpec must not turn a registered public read into an
  // unknown-capability approval.  The read result remains untrusted and is
  // still checked before every sensitive sink.
  state.taskSpec = update.state.taskSpec.task
    ? update.state.taskSpec
    : { ...update.state.taskSpec, task };
  if (update.changed && !["chatter", "confirmation", "data_only"].includes(update.kind)) {
    activateSemanticIntent(state.semanticActionGraph, state.taskSpec);
  }
}

export function normalizeAction(toolName: string, params: Record<string, unknown>): AgentSentryAction {
  const originalTool = typeof toolName === "string" && toolName.trim() ? toolName : "unknown_tool";
  let input: Record<string, unknown> = {};
  try {
    if (params && typeof params === "object" && !Array.isArray(params)) input = params;
  } catch {
    input = {};
  }
  let tool = normalizeToolName(originalTool);
  let args: Record<string, unknown>;
  try {
    args = normalizeArgs(tool, input);
  } catch {
    args = {};
  }
  tool = specializeStateTool(tool, args);
  const reason = typeof input.reason === "string" ? input.reason : "";
  return { tool, originalTool, args, reason };
}

function specializeStateTool(tool: string, args: Record<string, unknown>): string {
  const path = readFirstString(args, ["path", "file", "filename", "target"]);
  if (!isOpenClawMemoryDocumentPath(path)) return tool;
  if (tool === "read_file") return "memory_read";
  if (tool === "write_file") return "memory_write";
  return tool;
}

export function applyExposureTaint(action: AgentSentryAction, state: PolicyState, config: PluginConfig): {
  action: AgentSentryAction;
  findings: DetectionFinding[];
  links: SemanticProvenanceLink[];
  additions: DataProvenance[];
} {
  if (!config.detection.enabled || !config.policy.deterministic || !state.exposures.length) {
    return { action, findings: [], links: [], additions: [] };
  }

  const args = { ...action.args };
  const findings: DetectionFinding[] = [];
  const links: SemanticProvenanceLink[] = [];
  const additions: DataProvenance[] = [];
  const blocksTaintedInput = HIGH_RISK_SINKS.has(action.tool);
  let matchedAny = false;
  for (const [key, value] of Object.entries(args)) {
    if (isControlArg(key)) continue;
    if (isLabeledValue(value)) continue;
    const text = flattenText(value);
    if (!text.trim()) continue;
    const match = matchExposure(text, state.exposures);
    let exposure = match?.exposure || null;
    let mode = match?.mode || "";
    if (!exposure) continue;
    const matchEvidence = provenanceEvidenceForMatch(mode);
    matchedAny = true;
    const inheritedLabel: Label = {
      ...exposure.label,
      influence: mode === "run_exposure_default" ? "payload_default" : "matched",
    };
    args[key] = { value, label: inheritedLabel };
    const parent = exposure.provenanceId
      ? state.dataProvenance.find((item) => item.id === exposure.provenanceId)
      : null;
    const lineage = parent
      ? transformProvenance({
        parents: [parent],
        source: `tool:${action.originalTool || action.tool}`,
        path: provenanceArgPath(key),
        transformation: mode,
        content: value,
      })
      : null;
    if (lineage) {
      additions.push(publicProvenance(lineage));
      links.push({ provenanceId: lineage.id, argPath: provenanceArgPath(key), match: mode, ...matchEvidence });
    } else if (exposure.provenanceId) {
      links.push({ provenanceId: exposure.provenanceId, argPath: provenanceArgPath(key), match: mode, ...matchEvidence });
    }
    if (blocksTaintedInput) {
      const observed = matchEvidence.basis !== "conservative";
      findings.push(finding(
        "Tool Boundary",
        observed ? "deterministic" : "heuristic",
        observed ? "block" : "require_approval",
        observed
          ? "sink argument inherits malicious or secret taint"
          : "sink argument may inherit malicious or secret taint through an inferred match",
        observed ? 100 : 60,
        {
          tool: action.tool,
          arg: key,
          source: exposure.source,
          match: mode,
          evidence_basis: matchEvidence.basis,
          confidence: matchEvidence.confidence,
          semantic_claims: exposure.semanticClaims || [],
          provenance_id: lineage?.id || exposure.provenanceId || "",
          parent_ids: lineage?.parentIds || [],
          provenance_path: lineage?.path || "",
        },
      ));
    }
  }

  if (!matchedAny) return { action, findings, links, additions };
  return { action: { ...action, args }, findings, links, additions };
}

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
    semanticActionGraph: evaluationState.semanticActionGraph,
    apiCallCounts: evaluationState.apiCallCounts,
    dataProvenance: evaluationState.dataProvenance,
    taintFlows: evaluationState.taintFlows,
  };
  decision.effects = effects;
  return { decision, effects };
}

export function applyEffects(state: PolicyState, effects: PolicyEffects): void {
  state.semanticActionGraph = structuredClone(effects.semanticActionGraph);
  state.apiCallCounts = new Map(effects.apiCallCounts);
  state.dataProvenance = structuredClone(effects.dataProvenance);
  state.taintFlows = structuredClone(effects.taintFlows);
}

export function checkpointPolicyState(state: PolicyState): PolicyStateCheckpoint {
  return structuredClone({
    version: 1,
    created_at: new Date().toISOString(),
    currentTask: state.currentTask,
    taskSpec: state.taskSpec,
    authorizationState: state.authorizationState,
    contaminated: state.contaminated,
    provenanceBlocked: state.provenanceBlocked,
    provenanceFindings: state.provenanceFindings,
    history: state.history,
    toolResultLabels: [...state.toolResultLabels.entries()],
    exposures: state.exposures,
    apiCallCounts: [...state.apiCallCounts.entries()],
    behaviorProfiles: [...state.behaviorProfiles.entries()],
    runtimeProfiles: [...state.runtimeProfiles.entries()],
    trustLabels: state.trustLabels,
    aggregateRisk: state.aggregateRisk,
    taintedSources: state.taintedSources,
    taintFlows: state.taintFlows,
    dataProvenance: state.dataProvenance,
    ifcBranches: state.ifcBranches,
    persistentMemoryLabels: state.persistentMemoryLabels,
    semanticActionGraph: state.semanticActionGraph,
    dynamicSecurity: state.dynamicSecurity,
  } satisfies PolicyStateCheckpoint);
}

export function restorePolicyStateCheckpoint(state: PolicyState, checkpoint: PolicyStateCheckpoint | null | undefined): boolean {
  if (!checkpoint || checkpoint.version !== 1) return false;
  state.currentTask = checkpoint.currentTask;
  state.taskSpec = structuredClone(checkpoint.taskSpec);
  state.authorizationState = structuredClone(checkpoint.authorizationState);
  state.contaminated = checkpoint.contaminated;
  state.provenanceBlocked = checkpoint.provenanceBlocked;
  state.provenanceFindings = structuredClone(checkpoint.provenanceFindings);
  state.history = structuredClone(checkpoint.history);
  state.toolResultLabels = new Map(structuredClone(checkpoint.toolResultLabels));
  state.exposures = structuredClone(checkpoint.exposures);
  state.apiCallCounts = new Map(structuredClone(checkpoint.apiCallCounts));
  state.behaviorProfiles = new Map(structuredClone(checkpoint.behaviorProfiles));
  state.runtimeProfiles = new Map(structuredClone(checkpoint.runtimeProfiles));
  state.trustLabels = structuredClone(checkpoint.trustLabels);
  state.aggregateRisk = structuredClone(checkpoint.aggregateRisk);
  state.taintedSources = structuredClone(checkpoint.taintedSources);
  state.taintFlows = structuredClone(checkpoint.taintFlows);
  state.dataProvenance = structuredClone(checkpoint.dataProvenance);
  state.ifcBranches = structuredClone(checkpoint.ifcBranches);
  state.persistentMemoryLabels = structuredClone(checkpoint.persistentMemoryLabels);
  state.semanticActionGraph = restoreSemanticActionGraphMaps(structuredClone(checkpoint.semanticActionGraph));
  state.dynamicSecurity = structuredClone(checkpoint.dynamicSecurity);
  return true;
}

function restoreSemanticActionGraphMaps(graph: SemanticActionGraphState): SemanticActionGraphState {
  const pending = graph.pendingCalls instanceof Map
    ? graph.pendingCalls
    : new Map(Object.entries(graph.pendingCalls || {}) as Array<[string, string[]]>);
  const settled = graph.settledCalls instanceof Map
    ? graph.settledCalls
    : new Map(Object.entries(graph.settledCalls || {}) as Array<[string, string]>);
  return {
    ...graph,
    pendingCalls: pending,
    settledCalls: settled,
  };
}

function evaluateMutable(
  action: AgentSentryAction,
  state: PolicyState,
  config: PluginConfig,
  incomingFindings: DetectionFinding[],
  context: PolicyDecisionContext,
): PolicyDecision {
  if (context.provenanceAdditions?.length) rememberDataProvenance(state, context.provenanceAdditions);
  const normalizedAction = normalizePolicyAction(action);
  action = normalizedAction.action;
  const normalizedFindings = normalizeFindingInput(incomingFindings);
  const findings = [...normalizedFindings.findings];
  if (normalizedAction.issue) {
    findings.push(finding("Tool Boundary", "deterministic", "block", "tool action input could not be safely analyzed; policy failed closed", 100, {
      issue: normalizedAction.issue,
      tool: action.tool,
    }));
  }
  if (normalizedFindings.invalidCount) {
    findings.push(finding("Tool Boundary", "deterministic", "block", "security finding input failed validation; policy failed closed", 100, {
      invalid_findings: normalizedFindings.invalidCount,
    }));
  }
  const reasons: string[] = [];
  const violations: string[] = [];
  const riskScoringEnabled = config.detection.enabled;
  let risk = riskScoringEnabled ? baseToolRisk(action.tool) : 0;

  const taskSpec = state.taskSpec;
  const assessment = assessPolicyAction(action, config);
  const extractedAuthorization = authorizeCapability(taskSpec, action, { taskMode: taskSpec.task_mode });
  // Capability contracts can prove that a call is a caller-bound, read-only
  // query. Treat that as a scoped authorization so downstream risk, graph and
  // dynamic-security stages do not repeatedly reinterpret an already proven
  // safe read as an unknown high-impact action.
  const implicitManifestRead = !extractedAuthorization.authorized && manifestAllowsImplicitRead(action, taskSpec);
  const capabilityAuthorization: CapabilityAuthorization = implicitManifestRead
    ? { action: "allow", authorized: true, reason: "manifest_bound_read" }
    : extractedAuthorization;
  let actionGraphNodeId = "";
  try {
    const graphAttempt = beginSemanticAction(state.semanticActionGraph, {
      toolCallId: context.toolCallId,
      tool: action.tool,
      originalTool: action.originalTool,
      authorization: capabilityAuthorization,
      sink: sinkForAction(action, assessment),
      effects: {
        external: assessment.externalSink,
        persistence: assessment.persistence || assessment.systemMutation,
        execution: action.tool === "shell_exec" || assessment.dangerousCommand,
        sensitive: assessment.sensitive,
        sideEffect: isSideEffectToolCall(action),
      },
      semantic: context.semanticGraph,
      provenance: state.dataProvenance,
      consumes: context.provenanceLinks,
    });
    actionGraphNodeId = graphAttempt.actionNodeId;
    for (const violation of graphAttempt.violations) {
      const observedPath = violation.path.certainty === "observed";
      const blockingPath = violation.path.verdict === "block";
      findings.push(finding(
        "Semantic Action Graph",
        observedPath ? "deterministic" : "heuristic",
        blockingPath ? "block" : "require_approval",
        violation.reason,
        blockingPath ? 100 : 65,
        {
        graph_version: state.semanticActionGraph.version,
        path_id: violation.path.id,
        risk: violation.path.risk,
        path_verdict: violation.path.verdict,
        path_certainty: violation.path.certainty,
        path_confidence: violation.path.confidence,
        source_node_id: violation.path.sourceNodeId,
        action_node_id: violation.path.actionNodeId,
        sink_node_id: violation.path.sinkNodeId,
        node_count: violation.path.nodeIds.length,
        edge_count: violation.path.edgeIds.length,
        node_ids: compactEvidenceList(violation.path.nodeIds, 32),
        edge_ids: compactEvidenceList(violation.path.edgeIds, 32),
        causal_chain: compactEvidenceList(violation.path.steps, 24),
        },
      ));
      if (blockingPath) violations.push(violation.reason);
    }
  } catch {
    findings.push(finding("Semantic Action Graph", "deterministic", "block", "semantic action graph evaluation failed; policy failed closed", 100, {
      tool: action.tool,
    }));
    violations.push("semantic action graph evaluation failed");
  }
  if (!capabilityAuthorization.authorized && !allowsImplicitLowRiskRead(action, assessment, capabilityAuthorization.reason)) {
    const verdict = capabilityAuthorization.action === "deny" ? "block" : "require_approval";
    const reason = capabilityAuthorizationReason(capabilityAuthorization.reason, action.tool);
    findings.push(finding("Intent Authorization", "deterministic", verdict, reason, verdict === "block" ? 100 : 45, {
      tool: action.tool,
      authorization_reason: capabilityAuthorization.reason,
      expected_target: capabilityAuthorization.expectedTarget || "",
      actual_target: capabilityAuthorization.actualTarget || "",
      capability: capabilityAuthorization.capability || null,
    }));
    if (verdict === "block") violations.push(reason);
  }
  if (riskScoringEnabled && action.tool === "shell_exec" && !assessment.highRisk) {
    risk = 8;
  }
  const directProvenanceRisk = config.policy.deterministic && state.provenanceBlocked
    ? provenanceRiskForAction(action, state)
    : null;
  if (directProvenanceRisk) {
    const isolatedRead = action.tool === "read_file" && !assessment.sensitive && !assessment.systemMutation;
    findings.push(finding(
      "Context Provenance",
      "deterministic",
      isolatedRead ? "pass" : "block",
      isolatedRead
        ? "tool reads a risky workspace item for isolated analysis; downstream high-risk sinks remain restricted"
        : "tool call directly references a workspace item marked risky by provenance scan",
      isolatedRead ? 10 : 100,
      directProvenanceRisk,
    ));
    if (!isolatedRead) violations.push("tool call directly references risky workspace item");
  }

  const ifcExecutionFindings = config.policy.deterministic
    ? ifcExecutionBoundaryFindings(action, assessment, state, capabilityAuthorization, context.provenanceLinks || [])
    : [];
  for (const ifcFinding of ifcExecutionFindings) {
    findings.push(ifcFinding);
    if (ifcFinding.verdict === "block") violations.push(ifcFinding.reason);
  }

  const memoryIfcFindings = config.policy.deterministic ? persistentMemoryIFCFindings(action, assessment, state) : [];
  for (const memoryFinding of memoryIfcFindings) {
    findings.push(memoryFinding);
    if (memoryFinding.verdict === "block") violations.push(memoryFinding.reason);
  }

  const outsideTaskSpec = !implicitManifestRead
    && (taskSpec.forbidden_tools.includes(action.tool) || !taskSpec.allowed_tools.includes(action.tool));
  if (config.policy.deterministic && outsideTaskSpec && shouldHardBlockTaskMismatch(action, assessment, state)) {
    const reason = authorizationBoundaryReason(action, assessment, "deny");
    violations.push(reason);
    findings.push(finding("Tool Boundary", "deterministic", "block", reason, 100, { tool: action.tool, assessment, authorization_gap: "unauthorized_high_risk" }));
  } else if (riskScoringEnabled && outsideTaskSpec) {
    risk += assessment.highRisk ? 40 : 12;
    const implicit = allowsImplicitLowRiskRead(action, assessment, "missing_explicit_authorization");
    findings.push(finding(
      "Tool Boundary",
      "heuristic",
      implicit ? "pass" : assessment.highRisk ? "require_approval" : "pass",
      authorizationBoundaryReason(action, assessment, implicit ? "allow" : "ask"),
      implicit ? 0 : assessment.highRisk ? 35 : 8,
      { tool: action.tool, assessment, authorization_gap: implicit ? "implicit_low_risk_read" : "needs_clarification" },
    ));
  } else {
    reasons.push("tool is allowed by TaskSpec");
  }

  if (riskScoringEnabled) {
    const alignmentFindings = decisionAlignment(action, taskSpec);
    findings.push(...alignmentFindings);
  }

  const policyViolations = config.policy.deterministic
    ? deterministicViolations(action, taskSpec, state, config, context.workspaceDir || "")
    : [];
  for (const violation of policyViolations) {
    violations.push(violation);
    findings.push(finding("Tool Boundary", "deterministic", "block", violation, 100, { tool: action.tool }));
  }
  for (const reason of findings
    .filter((item) => item.finding_type === "deterministic" && item.verdict === "block")
    .map((item) => item.reason)) {
    violations.push(reason);
  }

  const agentFindings = config.multiAgentSecurity.enabled
    ? agentCommunicationFindings(action, config)
    : [];
  findings.push(...agentFindings);
  for (const finding of agentFindings) {
    if (finding.verdict === "block") violations.push(finding.reason);
  }

  if (riskScoringEnabled) {
    const trajectoryFindings = trajectoryFindingsFor(action, state, config);
    findings.push(...trajectoryFindings);

    const behaviorFindings = behaviorAnomalyFindingsFor(action, state, config);
    findings.push(...behaviorFindings);

    const runtimeFeedbackFindings = runtimeFeedbackFindingsFor(action, state, config);
    findings.push(...runtimeFeedbackFindings);

    const abacFindings = abacFindingsFor(action, state);
    findings.push(...abacFindings);

    const taskSpecFindings = taskSpecBoundaryFindings(action, state, config);
    findings.push(...taskSpecFindings);

    const manifestPurposeFindings = manifestPurposeBoundaryFindings(action, state);
    findings.push(...manifestPurposeFindings);

    const dynamicFindings = dynamicSecurityFindingsFor(action, assessment, state.dynamicSecurity, config);
    findings.push(...dynamicFindings);
  }

  const actionRisk = riskVectorFromFindings(findings);
  const combinedRisk = mergeRiskVectors(state.aggregateRisk, actionRisk);
  const blockedTaintForRisk = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (riskScoringEnabled && blockedTaintForRisk) {
    risk += Math.min(35, Math.max(15, Math.trunc(blockedTaintForRisk.confidence / 3)));
  }
  if (riskScoringEnabled && (assessment.highRisk || isTrustSensitiveSink(action, assessment))) {
    risk += Math.min(45, Math.trunc(riskMax(actionRisk) / 2));
  }
  const sentryScore = riskScoringEnabled ? heuristicScore(findings) : 0;
  if (riskScoringEnabled) {
    risk += sentryScore;
    risk += taintRisk(action, state, config);
  }
  const deterministicBlock = violations.length > 0 || findings.some((item) => item.finding_type === "deterministic" && item.verdict === "block");
  if (deterministicBlock) risk = Math.max(risk + 35, 100);
  const deterministicDecision = deterministicBlock
    ? "deny"
    : findings.some((item) => item.finding_type === "deterministic" && item.verdict === "require_approval")
      ? "ask"
      : "allow";
  const additionalDecision = riskScoringEnabled
    ? decisionFromRisk({
      hasBlock: findings.some((item) => item.verdict === "block"),
      hasApproval: findings.some((item) => item.verdict === "require_approval"),
      riskScore: risk,
      askThreshold: config.detection.askThreshold,
      denyThreshold: config.detection.denyThreshold,
    })
    : "allow";
  const decision = mergeDecision(deterministicDecision, additionalDecision);
  if (actionGraphNodeId) setSemanticActionDecision(state.semanticActionGraph, actionGraphNodeId, decision);

  return {
    decision,
    risk_score: Math.min(risk, 150),
    reasons,
    violations: unique(violations),
    deterministic_block: deterministicBlock,
    sentry_score: sentryScore,
    risk_vector: combinedRisk,
    trust_labels: state.trustLabels.slice(-8),
    action,
    task_spec: taskSpec,
    findings: dedupeFindings(findings),
    action_graph_node_id: actionGraphNodeId,
    deterministic_disposition: deterministicBlock
      ? "deny"
      : findings.some((item) => item.verdict !== "pass") || decision !== "allow"
        ? "ambiguous"
        : "allow",
  };
}

export function updateAfterMessage(state: PolicyState, findings: DetectionFinding[]): void {
  const normalized = normalizeFindingInput(findings);
  if (normalized.invalidCount) {
    normalized.findings.push(finding("Context Provenance", "deterministic", "block", "message security findings failed validation; state marked contaminated", 100, {
      invalid_findings: normalized.invalidCount,
    }));
  }
  if (shouldMarkMainContextContaminated(normalized.findings)) {
    state.contaminated = true;
  }
  mergeFindingTrust(state, normalized.findings);
}

export function updateAfterDecision(state: PolicyState, decision: PolicyDecision, config: PluginConfig = new PluginConfig()): void {
  if (!isPolicyDecisionForUpdate(decision)) {
    state.history.push({ tool: "unknown_tool", decision: "deny", risk_score: 100 });
    if (state.history.length > 80) state.history = state.history.slice(-80);
    state.contaminated = true;
    state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, createRiskVector({ tool_hijack: 100, privilege: 100 }));
    return;
  }
  const effects = decision.effects;
  if (effects) {
    applyEffects(state, effects);
  }
  state.history.push({
    tool: decision.action.tool,
    originalTool: decision.action.originalTool,
    frequencyKey: toolFrequencyKey(decision.action),
    decision: decision.decision,
    risk_score: decision.risk_score,
  });
  if (state.history.length > 80) state.history = state.history.slice(-80);
  if (decision.findings.some((finding) => finding.layer === "Context Provenance" || finding.layer === "State Integrity")) {
    if (shouldMarkMainContextContaminated(decision.findings)) state.contaminated = true;
  }
  if (decision.decision === "allow") updateBehaviorProfile(state, decision.action);
  state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, decision.risk_vector);
  mergeFindingTrust(state, decision.findings);
  state.dynamicSecurity = recordDynamicSecurityEvent(
    state.dynamicSecurity,
    decision.decision,
    decision.risk_score,
    decision.findings,
    config,
    decision.action.tool,
  );
}

export function updateAfterRuntimeFindings(state: PolicyState, toolName: string, findings: DetectionFinding[]): void {
  const runtimeFindings = normalizeFindingInput(findings).findings.filter(isRuntimeAuditFinding);
  if (!runtimeFindings.length) return;

  const tool = normalizeToolName(toolName || "unknown_tool");
  const existing = state.runtimeProfiles.get(tool);
  const reasons = unique([
    ...(existing?.reasons || []),
    ...runtimeFindings.map((item) => item.reason).filter(Boolean),
  ]).slice(-8);
  const events = unique([
    ...(existing?.events || []),
    ...runtimeFindings.map((item) => {
      const audit = (item.evidence || {}).runtime_audit as Record<string, unknown> | undefined;
      return String(audit?.event || "runtime");
    }),
  ]).slice(-8);

  state.runtimeProfiles.set(tool, {
    tool,
    runtime_alerts: (existing?.runtime_alerts || 0) + runtimeFindings.length,
    risk_score: Math.max(existing?.risk_score || 0, ...runtimeFindings.map((item) => item.score)),
    last_seen: new Date().toISOString(),
    reasons,
    events,
  });
  state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, riskVectorFromFindings(runtimeFindings));
  mergeFindingTrust(state, runtimeFindings);
}

function shouldMarkMainContextContaminated(findings: DetectionFinding[]): boolean {
  return findings.some((finding) => {
    const reason = `${finding.reason} ${safeStringify(finding.evidence || {})}`.toLowerCase();
    const highSignal = /prompt injection|exfiltrat|hidden content|memory poison|persistence poison|tool hijack|secret-taint|tainted data|bypass security|override policy/i.test(reason);
    const provenanceSignal = /untrusted|provenance|prompt injection|hidden content|memory poison|persistence poison|tool hijack|secret-taint|tainted data|bypass security|override policy|invalid|malformed|failed validation|security/i.test(reason);
    const boundary = finding.layer === "Context Provenance" || finding.layer === "State Integrity";
    if (finding.layer === "State Integrity" && finding.verdict === "block") return true;
    if (finding.layer === "Context Provenance" && provenanceSignal) return true;
    return boundary && highSignal && finding.verdict === "block";
  });
}

export function updateActionGraphEnforcement(
  state: PolicyState,
  decision: PolicyDecision,
  status: "awaiting_approval" | "blocked" | "executing",
): void {
  if (!decision.action_graph_node_id) return;
  const graph = decision.effects?.semanticActionGraph || state.semanticActionGraph;
  markSemanticActionEnforcement(graph, decision.action_graph_node_id, {
    decision: decision.decision,
    status,
  });
  state.semanticActionGraph = structuredClone(graph);
}

type ToolResultLifecycle = {
  disposition: "process" | "duplicate_terminal" | "executed_after_block";
  graphContext: ReturnType<typeof semanticActionResultContext>;
  actionNodeId: string;
  callIdHash: string;
};

function inspectToolResultLifecycle(
  state: PolicyState,
  toolCallId: string,
  toolName: string,
  outcome: "succeeded" | "failed",
): ToolResultLifecycle {
  const graphContext = semanticActionResultContext(state.semanticActionGraph, { toolCallId, tool: toolName });
  const actionNodeId = graphContext?.actionNodeId || "";
  const action = actionNodeId
    ? state.semanticActionGraph.nodes.find((node) => node.id === actionNodeId && node.kind === "action")
    : null;
  if (action?.status === "blocked" && outcome === "succeeded") {
    return {
      disposition: "executed_after_block",
      graphContext,
      actionNodeId,
      callIdHash: action.callIdHash || "",
    };
  }
  if (action?.status && ["blocked", "succeeded", "failed", "observed"].includes(action.status)) {
    return {
      disposition: "duplicate_terminal",
      graphContext,
      actionNodeId,
      callIdHash: action.callIdHash || "",
    };
  }
  return {
    disposition: "process",
    graphContext,
    actionNodeId,
    callIdHash: action?.callIdHash || "",
  };
}

function enforcementBypassFinding(lifecycle: ToolResultLifecycle, toolName: string): DetectionFinding {
  return finding(
    "Tool Boundary",
    "deterministic",
    "block",
    "tool execution was observed after AgentSentry blocked the call",
    100,
    {
      event: "enforcement_bypass",
      execution_status: "executed_after_block",
      tool: normalizeToolName(toolName || "unknown_tool"),
      action_node_id: lifecycle.actionNodeId,
      call_id_hash: lifecycle.callIdHash,
    },
  );
}

export function labelToolResult(
  toolCallId: string,
  result: unknown,
  state: PolicyState,
  config: PluginConfig,
  toolName = "",
  toolArgs: Record<string, unknown> = {},
): Label {
  const lifecycle = inspectToolResultLifecycle(state, toolCallId, toolName, "succeeded");
  if (lifecycle.disposition === "duplicate_terminal") {
    return state.toolResultLabels.get(toolCallId) || {
      source: toolCallId ? `tool:${toolCallId}` : "tool:unknown",
      integrity: "untrusted",
      confidentiality: "public",
      tainted: false,
      provenance_untrusted: true,
      influence: "none",
      tags: ["duplicate_terminal_result_ignored"],
    };
  }
  const graphContext = lifecycle.graphContext;
  if (!config.detection.enabled) {
    const label = trustedToolLabel(toolCallId);
    if (toolCallId) state.toolResultLabels.set(toolCallId, label);
    completeSemanticAction(state.semanticActionGraph, { toolCallId, tool: toolName, status: "succeeded" });
    return label;
  }
  const text = safeStringify(result);
  const prepared = analyzePolicyResult(toolCallId, result, config, toolName);
  const { analysis, source } = prepared;
  let incompleteReason = prepared.incompleteReason;
  let fieldProvenance: ReturnType<typeof extractFieldProvenance> = [];
  if (!incompleteReason) {
    try {
      fieldProvenance = extractFieldProvenance({
        value: result,
        source,
        sourceId: toolCallId || toolName || "tool_result",
        toolName,
        previewChars: config.capture.previewChars,
      });
      if (graphContext?.consumedProvenanceIds.length) {
        fieldProvenance = inheritResultProvenance(
          fieldProvenance,
          graphContext.consumedProvenanceIds,
          state,
          toolCallId || toolName || "tool_result",
          toolName,
        );
      }
    } catch {
      incompleteReason = "field provenance extraction failed";
    }
  }
  const persistentMemoryMatches = source === "memory" ? matchingPersistentMemoryLabels(state, result, fieldProvenance) : [];
  const memoryLowTrust = persistentMemoryMatches.some((item) => item.integrity === "untrusted-external" || item.confidentiality === "tenant-secret" || riskMax(item.risk_vector) >= 50);
  const provenanceUntrusted = !toolName || ["external_web", "email_html", "pdf_text", "image_metadata", "webhook", "unknown"].includes(source);
  const maliciousTaint = Boolean(incompleteReason) || memoryLowTrust || analysis.label.tainted || hasInjectionSignal(text) || riskMax(analysis.risk_vector) >= 50;
  const manifest = resolveToolManifest(toolName);
  const manifestClassification = manifest?.manifest.dataClassification || "unknown";
  const subjectScopes = manifest ? subjectScopesForAction(manifest.manifest, {
    tool: toolName,
    originalTool: toolName,
    args: toolArgs,
    reason: "tool result label",
  }) : [];
  fieldProvenance = elevateManifestConfidentiality(fieldProvenance, manifestClassification);
  const label: Label = {
    source: toolCallId ? `tool:${toolCallId}` : "tool:unknown",
    integrity: "untrusted",
    confidentiality: "public",
    tainted: false,
    provenance_untrusted: provenanceUntrusted,
    influence: "none",
    trust_label: analysis.label,
    risk_vector: analysis.risk_vector,
    tags: unique([...analysis.tags, ...persistentMemoryMatches.flatMap((item) => item.tags), ...(memoryLowTrust ? ["persistent_memory_low_trust"] : []), ...(incompleteReason ? ["analysis_incomplete"] : [])]),
    subject_scopes: subjectScopes,
    taint_profile: taintProfileFromLabel(analysis.label) || undefined,
    provenance_ids: fieldProvenance.map((field) => field.id),
  };
  if (manifestClassification === "secret") label.confidentiality = "secret";
  if (manifestClassification === "user_private" && label.confidentiality === "public") label.confidentiality = "internal";
  if (manifestClassification === "user_private" || manifestClassification === "secret") {
    label.tags = unique([...(label.tags || []), `manifest:${manifestClassification}`]);
  }
  if (provenanceUntrusted || maliciousTaint || analysis.label.confidentiality !== "public") {
    const branchStatus: IFCBranch["status"] = provenanceUntrusted || maliciousTaint || analysis.label.confidentiality !== "public"
      ? "isolated"
      : "merged";
    rememberIFCBranch(state, {
      id: `ifc:${toolCallId || toolName || "tool"}:${Date.now()}:${state.ifcBranches.length}`,
      source,
      status: branchStatus,
      integrity: provenanceUntrusted || maliciousTaint ? "untrusted-external" : "system-trusted",
      confidentiality: ifcConfidentiality(analysis.label.confidentiality),
      purpose: state.taskSpec.capabilities.map((item) => `${item.resourceType}:${item.action}`).join("+") || "unscoped",
      summary: `${source}; ${branchStatus}; ${analysis.label.integrity}/${analysis.label.confidentiality}; ${analysis.tags.slice(0, 4).join(",")}`,
      subjectScopes,
      lifetime: source === "memory" ? "memory" : "turn",
      createdAt: new Date().toISOString(),
      provenanceIds: fieldProvenance.map((field) => field.id),
      risk: Math.max(riskMax(analysis.risk_vector), ...persistentMemoryMatches.map((item) => riskMax(item.risk_vector))),
      confidence: Math.max(0, Math.min(1, (Math.max(riskMax(analysis.risk_vector), ...persistentMemoryMatches.map((item) => riskMax(item.risk_vector))) || 0) / 100)),
    });
  }
  if ((manifestClassification === "user_private" || manifestClassification === "secret")
    && analysis.label.confidentiality === "public") {
    rememberIFCBranch(state, {
      id: `ifc:manifest:${toolCallId || toolName || "tool"}:${Date.now()}:${state.ifcBranches.length}`,
      source,
      status: "isolated",
      integrity: provenanceUntrusted ? "untrusted-external" : "system-trusted",
      confidentiality: manifestClassification === "secret" ? "tenant-secret" : "user-private",
      purpose: state.taskSpec.capabilities.map((item) => `${item.resourceType}:${item.action}`).join("+") || "unscoped",
      summary: `tool manifest classification: ${manifestClassification}`,
      subjectScopes,
      lifetime: source === "memory" ? "memory" : "turn",
      createdAt: new Date().toISOString(),
      provenanceIds: fieldProvenance.map((field) => field.id),
      risk: manifestClassification === "secret" ? 70 : 35,
      confidence: 1,
    });
  }
  if (!provenanceUntrusted
    && !maliciousTaint
    && analysis.label.confidentiality === "public"
    && (manifestClassification === "public" || manifestClassification === "unknown")) {
    promoteIFCBranches(state, source, fieldProvenance.flatMap((field) => [field.id, ...field.parentIds]));
  }
  if (maliciousTaint || analysis.label.confidentiality === "secret") {
    label.integrity = "untrusted";
    label.tainted = true;
    state.contaminated = true;
  } else if (!provenanceUntrusted) {
    label.integrity = "trusted";
  }
  if (analysis.label.confidentiality === "secret" || config.policy.sensitiveAssets.some((asset) => asset && text.toLowerCase().includes(asset.toLowerCase()))) {
    label.confidentiality = "secret";
  }
  for (const field of fieldProvenance) {
    rememberTrustLabel(state, field.trustLabel);
    const claimConfidentiality = strongestSemanticClaimConfidentiality(field.semanticClaims);
    if (field.integrity === "tainted" || field.confidentiality === "secret" || claimConfidentiality !== "public") {
      const fieldLabel: Label = {
        source: `${toolCallId ? `tool:${toolCallId}` : "tool:unknown"}::${field.path}`,
        integrity: field.integrity === "trusted" ? "trusted" : "untrusted",
        confidentiality: strongerConfidentiality(field.confidentiality, claimConfidentiality === "tenant-secret" || claimConfidentiality === "user-private" ? "secret" : claimConfidentiality),
        tainted: field.integrity === "tainted" || field.semanticClaims.some((claim) => claim.confidentiality === "secret"),
        provenance_untrusted: provenanceUntrusted,
        influence: "none",
        trust_label: field.trustLabel,
        risk_vector: field.riskVector,
        tags: unique([...field.tags, ...field.semanticClaims.flatMap((claim) => claim.tags)]),
        taint_profile: taintProfileFromLabel(field.trustLabel) || undefined,
      };
      state.exposures.push({ source: fieldLabel.source, text: field.value, label: fieldLabel, provenanceId: field.id, semanticClaims: field.semanticClaims });
    }
  }
  const publicFields = fieldProvenance.map(publicProvenance);
  const completeProvenance = mergeDataProvenance(state.dataProvenance, publicFields);
  completeSemanticAction(state.semanticActionGraph, {
    toolCallId,
    tool: toolName,
    status: "succeeded",
    produced: publicFields,
    provenance: completeProvenance,
  });
  rememberDataProvenance(state, publicFields);
  state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, analysis.risk_vector);
  if (toolCallId) state.toolResultLabels.set(toolCallId, label);
  if (!fieldProvenance.length && label.tainted && text.trim()) {
    state.exposures.push({ source: label.source, text, label: { ...label }, semanticClaims: semanticClaimsForValue({ value: text, tags: label.tags, confidentiality: label.confidentiality }) });
  }
  if (state.exposures.length > 80) state.exposures = state.exposures.slice(-80);
  return label;
}

export function resultFindings(
  toolCallId: string,
  result: unknown,
  state: PolicyState,
  config: PluginConfig,
  toolName = "",
  options: { error?: unknown; toolArgs?: Record<string, unknown> } = {},
): DetectionFinding[] {
  const failed = options.error !== undefined && options.error !== null && Boolean(String(options.error).trim());
  const lifecycle = inspectToolResultLifecycle(state, toolCallId, toolName, failed ? "failed" : "succeeded");
  if (lifecycle.disposition === "duplicate_terminal") return [];
  if (failed) {
    completeSemanticAction(state.semanticActionGraph, { toolCallId, tool: toolName, status: "failed" });
    return [];
  }
  if (!config.detection.enabled) {
    labelToolResult(toolCallId, result, state, config, toolName, options.toolArgs);
    return lifecycle.disposition === "executed_after_block"
      ? [enforcementBypassFinding(lifecycle, toolName)]
      : [];
  }
  const { analysis } = analyzePolicyResult(toolCallId, result, config, toolName);
  const label = labelToolResult(toolCallId, result, state, config, toolName, options.toolArgs);
  const findings = [...analysis.findings];
  if (lifecycle.disposition === "executed_after_block") {
    findings.unshift(enforcementBypassFinding(lifecycle, toolName));
  }
  const injectionSignal = hasInjectionSignal(safeStringify(result));
  const incomplete = label.tags?.includes("analysis_incomplete") || false;
  const lowTrustPersistentMemory = label.tags?.includes("persistent_memory_low_trust") || false;
  if (!findings.length && !injectionSignal && !incomplete && !lowTrustPersistentMemory) return [];
  return [
    ...findings,
    ...(injectionSignal
      ? [finding("Context Provenance", "heuristic", "pass", "untrusted tool output contains prompt-injection indicators; taint is preserved for sink checks", 25, {
        source: label.source,
        preview: clampText(safeStringify(result), config.capture.previewChars),
        trust_label: label.trust_label || null,
        risk_vector: label.risk_vector || createRiskVector(),
        tags: label.tags || [],
        taint_profile: label.taint_profile || null,
      })]
      : []),
    ...(incomplete
      ? [finding("Context Provenance", "deterministic", "block", "tool result could not be completely analyzed; taint is preserved and policy failed closed", 100, {
        source: label.source,
        tags: label.tags || [],
      })]
      : []),
    ...(lowTrustPersistentMemory
      ? [finding("Memory IFC", "deterministic", "require_approval", "persistent memory label was restored from the IFC ledger and kept in an isolated branch", 55, {
        source: label.source,
        tags: label.tags || [],
        trust_label: label.trust_label || null,
      })]
      : []),
  ];
}

function inheritResultProvenance(
  fields: FieldProvenance[],
  parentIds: string[],
  state: PolicyState,
  sourceId: string,
  toolName: string,
): FieldProvenance[] {
  const provenanceById = new Map(state.dataProvenance.map((item) => [item.id, item]));
  const parents = Array.from(new Set(parentIds))
    .map((id) => provenanceById.get(id))
    .filter((item): item is DataProvenance => Boolean(item));
  if (!parents.length) return fields;

  const ancestorIds = provenanceAncestors(parentIds, provenanceById);
  const inheritedExposure = [...state.exposures]
    .reverse()
    .find((item) => item.provenanceId && ancestorIds.has(item.provenanceId));

  return fields.map((field) => {
    const derived = transformProvenance({
      parents,
      source: sourceId,
      path: field.path,
      transformation: `tool:${normalizeToolName(toolName || "unknown_tool")}`,
      content: field.value,
    });
    const confidentiality = strongerConfidentiality(field.confidentiality, derived.confidentiality);
    const integrity = weakerIntegrity(field.integrity, derived.integrity);
    const inheritedRisk = inheritedExposure?.label.risk_vector || createRiskVector();
    return {
      ...field,
      id: derived.id,
      parentIds: [...derived.parentIds],
      source: derived.source,
      confidentiality,
      integrity,
      transformations: [...derived.transformations],
      contentFingerprint: derived.contentFingerprint,
      trustLabel: inheritedExposure?.label.trust_label || field.trustLabel,
      riskVector: mergeRiskVectors(field.riskVector, inheritedRisk),
      tags: unique([...field.tags, ...(inheritedExposure?.label.tags || []), "derived_tool_output"]),
    };
  });
}

function provenanceAncestors(ids: string[], provenanceById: Map<string, DataProvenance>): Set<string> {
  const ancestors = new Set<string>();
  const pending = [...ids];
  while (pending.length && ancestors.size < 256) {
    const id = pending.pop()!;
    if (!id || ancestors.has(id)) continue;
    ancestors.add(id);
    const node = provenanceById.get(id);
    if (node) pending.push(...node.parentIds);
  }
  return ancestors;
}

function strongerConfidentiality(
  left: DataProvenance["confidentiality"],
  right: DataProvenance["confidentiality"],
): DataProvenance["confidentiality"] {
  const rank = { public: 0, internal: 1, secret: 2 } as const;
  return rank[left] >= rank[right] ? left : right;
}

function weakerIntegrity(
  left: DataProvenance["integrity"],
  right: DataProvenance["integrity"],
): DataProvenance["integrity"] {
  const rank = { tainted: 0, untrusted: 1, trusted: 2 } as const;
  return rank[left] <= rank[right] ? left : right;
}

function mergeDataProvenance(current: DataProvenance[], additions: DataProvenance[]): DataProvenance[] {
  const ordered = new Map<string, DataProvenance>();
  for (const node of [...current, ...additions]) {
    ordered.delete(node.id);
    ordered.set(node.id, publicProvenance(node));
  }
  return [...ordered.values()];
}

function rememberDataProvenance(state: PolicyState, additions: DataProvenance[]): void {
  const merged = mergeDataProvenance(state.dataProvenance, additions);
  if (merged.length <= 240) {
    state.dataProvenance = merged;
    return;
  }

  const byId = new Map(merged.map((node) => [node.id, node]));
  const protectedIds = new Set<string>(additions.map((node) => node.id));
  for (const exposure of state.exposures.slice(-80)) {
    if (exposure.provenanceId) protectedIds.add(exposure.provenanceId);
  }
  const pending = [...protectedIds];
  while (pending.length && protectedIds.size < 240) {
    const id = pending.pop()!;
    for (const parentId of byId.get(id)?.parentIds || []) {
      if (!protectedIds.has(parentId)) {
        protectedIds.add(parentId);
        pending.push(parentId);
      }
    }
  }

  const protectedNodes = merged.filter((node) => protectedIds.has(node.id)).slice(-240);
  const remainingBudget = Math.max(0, 240 - protectedNodes.length);
  const remainingCandidates = merged.filter((node) => !protectedIds.has(node.id));
  const remaining = remainingBudget > 0 ? remainingCandidates.slice(-remainingBudget) : [];
  const order = new Map(merged.map((node, index) => [node.id, index]));
  const kept = [...protectedNodes, ...remaining].sort((left, right) =>
    (order.get(left.id) || 0) - (order.get(right.id) || 0)
  );
  const keptIds = new Set(kept.map((node) => node.id));
  state.dataProvenance = kept.map((node) => ({
    ...node,
    parentIds: node.parentIds.filter((id) => keptIds.has(id)),
    transformations: [...node.transformations],
  }));
  state.exposures = state.exposures.filter((exposure) =>
    !exposure.provenanceId || keptIds.has(exposure.provenanceId)
  );
}

export function policyTrustSnapshot(state: PolicyState): Record<string, unknown> {
  const labels = state.trustLabels.slice(-10);
  const lowest = minimumTrustLabel(labels);
  return {
    contaminated: state.contaminated,
    aggregate_risk: state.aggregateRisk,
    tainted_sources: state.taintedSources.slice(-12),
    taint_flows: state.taintFlows.slice(-12),
    ifc_branches: state.ifcBranches.slice(-12),
    persistent_memory_labels: state.persistentMemoryLabels.slice(-12).map(publicPersistentMemoryLabel),
    provenance: state.dataProvenance.slice(-20),
    semantic_action_graph: semanticActionGraphSnapshot(state.semanticActionGraph),
    runtime_feedback: Array.from(state.runtimeProfiles.values()).slice(-10),
    dynamic_security: dynamicSecuritySnapshot(state.dynamicSecurity),
    lowest_trust: lowest
      ? {
        source: lowest.source,
        integrity: lowest.integrity,
        confidentiality: lowest.confidentiality,
        tainted: lowest.tainted,
      }
      : null,
    labels: labels.map((label) => ({
      id: label.id,
      source: label.source,
      integrity: label.integrity,
      confidentiality: label.confidentiality,
      tainted: label.tainted,
      tags: label.evidence?.tags || [],
      signed_at: label.signed_at,
    })),
  };
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

function capabilityAuthorizationReason(reason: string, tool: string): string {
  if (reason === "unknown_tool_capability" && (resolveToolManifest(tool) || resolveToolManifest(normalizeToolName(tool)))) {
    return `已注册工具 ${tool} 的能力已完成基线登记，但当前任务没有覆盖它的目标或副作用范围，需要确认`;
  }
  const messages: Record<string, string> = {
    explicit_user_denial: `用户明确禁止 ${tool} 动作`,
    missing_explicit_authorization: `${tool} 缺少明确授权，属于授权不明确`,
    authorization_parse_failed: `${tool} 的任务意图解析失败，建议先确认输入属于说明、数据还是实际授权`,
    non_authoritative_context_cannot_grant_side_effects: "记忆或工具返回内容不能授予新的外部副作用权限",
    non_authoritative_context: "非用户上下文不能建立该工具权限",
    recipient_outside_authorization: "邮件收件人不在用户明确授权范围内",
    attachment_outside_authorization: "邮件附件不在用户明确授权文件范围内",
    path_outside_authorization: "文件路径不在用户明确授权路径范围内",
    target_outside_authorization: "网络目标不在用户明确授权目标范围内",
    host_outside_authorization: "网络主机不在用户明确授权主机范围内",
    method_outside_authorization: "HTTP 方法不在用户明确授权方法范围内",
    command_outside_authorization: "Shell 命令不在用户明确授权命令范围内",
    unknown_tool_capability: `${tool} 没有已注册的能力模型，需要确认`,
  };
  return messages[reason] || `${tool} 能力授权校验未通过：${reason}`;
}

function allowsImplicitLowRiskRead(action: AgentSentryAction, assessment: ActionAssessment, reason: string): boolean {
  if (reason !== "missing_explicit_authorization" && reason !== "unknown_tool_capability") return false;
  if (assessment.highRisk || assessment.sensitive || assessment.persistence || assessment.systemMutation || assessment.externalSink) return false;
  if (action.tool === "read_file" || action.tool === "memory_read") return true;
  if (action.tool !== "call_api") return false;
  const method = readFirstString(action.args, ["method", "httpMethod", "verb"]).toUpperCase() || "GET";
  return ["GET", "HEAD", "OPTIONS"].includes(method);
}

function authorizationBoundaryReason(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  disposition: "allow" | "ask" | "deny",
): string {
  if (disposition === "allow") {
    return `低风险只读动作 ${action.tool} 未命中显式授权，按最小权限记录审计后放行`;
  }
  if (disposition === "ask") {
    return `授权不明确：${action.tool} 未在当前任务授权范围内，执行前需要确认目标、数据范围和副作用`;
  }
  const detail = assessment.reasons.length ? `；风险原因：${assessment.reasons.join("；")}` : "";
  return `未授权高风险动作：${action.tool} 超出当前任务授权范围${detail}`;
}

function deterministicViolations(
  action: AgentSentryAction,
  taskSpec: TaskSpec,
  state: PolicyState,
  config: PluginConfig,
  workspaceDir: string,
): string[] {
  const violations: string[] = [];
  const assessment = assessAction(action, config);
  const argsAnalysis = analyzeTrustContent(action.args, {
    source: sourceFromTool(action.tool),
    sourceId: action.originalTool,
    toolName: action.originalTool,
    previewChars: config.capture.previewChars,
  });
  if (action.tool === "read_webpage") {
    const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
    if (!targetAllowed(url, taskSpec.allowed_targets)) {
      violations.push(`target ${url || "<empty>"} is outside allowed_targets`);
    }
  }

  const blockedTaint = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (blockedTaint) {
    violations.push(`ABAC blocked high-risk sink because taint profile disallows flow to ${blockedTaint.sink}`);
  }
  if (isTrustSensitiveSink(action, assessment) && argsAnalysis.label.confidentiality === "secret") {
    violations.push("tool arguments carry secret-tainted data");
  }
  if (argsAnalysis.findings.some((finding) => finding.verdict === "block" && finding.finding_type === "deterministic")) {
    violations.push("tool arguments match deterministic trust-risk policy");
  }

  if (action.tool === "send_email") {
    const recipients = readStringValues(action.args, ["recipient", "recipients", "to", "target", "email"]);
    const body = readFirstString(action.args, ["body", "content", "message", "text"]);
    const unauthorizedRecipient = recipients.find((recipient) => !config.policy.allowlistedRecipients.includes(recipient));
    if (config.policy.allowlistedRecipients.length && unauthorizedRecipient) {
      violations.push(`recipient ${unauthorizedRecipient} is not allowlisted`);
    }
    if (config.policy.sensitiveAssets.some((asset) => asset && body.toLowerCase().includes(asset.toLowerCase()))) {
      violations.push("body contains secret-tainted data");
    }
    if (!taskSpec.allowed_tools.includes("send_email") && config.policy.sensitiveAssets.some((asset) => asset && body.toLowerCase().includes(asset.toLowerCase()))) {
      violations.push("邮件正文包含敏感资产且当前任务没有邮件发送授权");
    }
  }

  if (action.tool === "write_file") {
    const requestedPath = readFirstString(action.args, ["path", "file", "filename", "target"]);
    const content = readFirstString(action.args, ["content", "body", "text", "patch"]);
    let effectivePath = requestedPath;
    if (!requestedPath.trim()) violations.push("missing write path");
    if (config.policy.restrictWritesToAllowedRoots) {
      const needsWorkspace = !isAbsolute(requestedPath) || config.policy.allowedWriteRoots.some((root) => !isAbsolute(root));
      if (needsWorkspace && !workspaceDir.trim()) {
        violations.push("write path cannot be authorized without a workspace root");
      } else {
        const writeBaseDir = workspaceDir || process.cwd();
        const allowedRoots = config.policy.allowedWriteRoots.map((root) => isAbsolute(root) ? root : resolve(writeBaseDir, root));
        const boundary = matchAllowedWritePath(requestedPath, allowedRoots, writeBaseDir);
        if (!boundary.allowed) violations.push(boundary.reason || "write path is outside allowed roots");
        else effectivePath = boundary.target;
      }
    } else if (requestedPath.trim()) {
      if (!isAbsolute(requestedPath) && !workspaceDir.trim()) {
        violations.push("write path cannot be canonicalized without a workspace root");
      } else {
        try {
          effectivePath = canonicalizePath(isAbsolute(requestedPath) ? requestedPath : resolve(workspaceDir, requestedPath));
        } catch (error) {
          violations.push(`cannot canonicalize write path: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
    const path = effectivePath.replace(/\\/g, "/").toLowerCase();
    const effectiveAssessment = effectivePath === requestedPath
      ? assessment
      : assessAction({ ...action, args: { ...action.args, path: effectivePath } }, config);
    if (effectiveAssessment.systemMutation) violations.push("write path targets protected system path");
    if (isSensitivePath(path, config)) violations.push("write path references sensitive asset");
    if (config.policy.sensitiveAssets.some((asset) => asset && content.toLowerCase().includes(asset.toLowerCase()))) {
      violations.push("content contains secret-tainted data");
    }
    const skillSurface = /(^|\/)(?:skills)(?:\/|$)/i.test(path) || /(^|\/)skill\.md$/i.test(path);
    if (/(^|\/)(memory\.md|agents\.md|soul\.md|user\.md|openclaw\.json)$/i.test(path) || /(^|\/)(?:cron\.d|systemd|startup)(?:\/|$)/i.test(path)) {
      violations.push("write path targets memory, configuration, startup, or skill surface");
    }
    const writeContentAnalysis = analyzeTrustContent(content, { source: path.includes("skill") ? "skill" : "memory", path, previewChars: config.capture.previewChars });
    if (writeContentAnalysis.findings.some((finding) => finding.verdict === "block")) {
      violations.push("write content contains persistence or skill hijack instructions");
    }
    if (skillSurface && !taskSpec.allowed_tools.includes("write_file")) {
      violations.push("Skill 写入缺少用户明确授权");
    }
    if (!taskSpec.allowed_tools.includes("write_file") && effectiveAssessment.highRisk) {
      violations.push("task intent does not allow file write");
    }
  }

  if (action.tool === "read_file") {
    const requestedPath = readFirstString(action.args, ["path", "file", "filename", "target"]);
    const boundary = matchWorkspaceReadPath(requestedPath, workspaceDir);
    if (!boundary.allowed) violations.push(boundary.reason || "read path is outside workspace root");
    const effectivePath = boundary.allowed ? boundary.target : requestedPath;
    const path = effectivePath.replace(/\\/g, "/").toLowerCase();
    if (isSensitivePath(path, config)) {
      violations.push("read path references sensitive asset");
    }
  }

  if (action.tool === "call_api") {
    const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
    const host = hostFromUrl(url);
    let apiTargetAllowed = true;
    if (!targetAllowed(url, taskSpec.allowed_targets)) {
      violations.push(`target ${url || "<empty>"} is outside allowed_targets`);
      apiTargetAllowed = false;
    }
    if (host) {
      if (config.policy.allowlistedApiHosts.length && !config.policy.allowlistedApiHosts.includes(host)) {
        violations.push(`api host ${host} is not allowlisted`);
      }
      if (apiTargetAllowed && (!config.policy.allowlistedApiHosts.length || config.policy.allowlistedApiHosts.includes(host))) {
        state.apiCallCounts.set(host, (state.apiCallCounts.get(host) || 0) + 1);
      }
      if ((state.apiCallCounts.get(host) || 0) > 10) violations.push("api rate exceeds configured limit");
    }
    if (/[?&]gatewayURL\s*=\s*wss?:\/\//i.test(url) && !/[?&]gatewayURL\s*=\s*wss?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(url)) {
      violations.push("api call includes non-local Control UI gateway override");
    }
  }

  if (action.tool === "shell_exec") {
    const command = readFirstString(action.args, ["command", "cmd", "script", "input"]);
    if (command && assessment.highRisk) violations.push("shell command requires explicit review");
  }

  if (action.tool === "memory_write") {
    const content = readFirstString(action.args, ["content", "body", "text", "value"]);
    const analysis = analyzeTrustContent(content, { source: "memory", sourceId: "memory_write", previewChars: config.capture.previewChars });
    if (analysis.findings.some((finding) => finding.verdict === "block")) {
      violations.push("memory write contains privileged persistent instruction");
    }
    if (!taskSpec.allowed_tools.includes("memory_write") && analysis.findings.some((finding) => finding.verdict === "block")) {
      violations.push("高风险记忆写入缺少用户明确授权");
    }
  }

  return unique(violations);
}

function decisionAlignment(action: AgentSentryAction, taskSpec: TaskSpec): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const loweredTask = taskSpec.task.toLowerCase();
  const assessment = assessActionWithSensitiveAssets(action, taskSpec.sensitive_assets);
  if (action.tool === "send_email" && containsAny(loweredTask, EXPLICIT_NO_EMAIL)) {
    findings.push(finding("Intent Authorization", "heuristic", "require_approval", "email action conflicts with explicit user constraint", 35, { tool: action.tool }));
  }
  if ((assessment.highRisk || isTrustSensitiveSink(action, assessment)) && !taskSpec.allowed_tools.includes(action.tool)) {
    findings.push(finding("Intent Authorization", "heuristic", "require_approval", "high-risk action deviates from task intent", 30, { tool: action.tool }));
  }
  return findings;
}

function trajectoryFindingsFor(action: AgentSentryAction, state: PolicyState, config: PluginConfig): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const frequencyKey = toolFrequencyKey(action);
  const count = state.history.filter((item) => (item.frequencyKey || item.originalTool || item.tool) === frequencyKey).length;
  if (count >= 3) {
    const assessment = assessAction(action, config);
    const budget = workflowFrequencyBudget(action, state, assessment, count + 1);
    findings.push(finding(
      "Evidence Feedback",
      "heuristic",
      budget.requiresApproval ? "require_approval" : "pass",
      budget.reason,
      budget.requiresApproval ? 20 : 0,
      {
        tool: action.tool,
        original_tool: action.originalTool,
        frequency_key: frequencyKey,
        count: count + 1,
        workflow_budget: budget,
      },
    ));
  }
  const assessment = assessAction(action, config);
  findings.push(...sensitiveReadAggregationFindings(action, state));
  const blockedTaint = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (blockedTaint) {
    findings.push(finding("Evidence Feedback", "heuristic", "require_approval", "taint profile tightens this high-risk sink", 20, {
      tool: action.tool,
      sink: blockedTaint.sink,
      taint: blockedTaint,
    }));
  }
  const readOnlyTask = /summari[sz]e|总结|概括|查看|阅读|看看|分析/.test(state.currentTask.toLowerCase())
    && !/(发送|发邮件|email|mail|写入|保存|执行|运行|记住|memory|remember|shell|command)/i.test(state.currentTask);
  const lastRead = state.history.slice(-4).some((item) => item.tool === "read_webpage" || item.tool === "read_file" || item.tool === "call_api");
  if (readOnlyTask && lastRead && isTrustSensitiveSink(action, assessment)) {
    findings.push(finding("Intent Authorization", "deterministic", "block", "dynamic intent tracking detected drift from read-only task to high-risk action", 100, {
      task: state.currentTask,
      tool: action.tool,
      recent_tools: state.history.slice(-4).map((item) => item.tool),
    }));
  }
  return findings;
}

function sensitiveReadAggregationFindings(action: AgentSentryAction, state: PolicyState): DetectionFinding[] {
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!envelope || !isReadOnlyManifest(envelope.manifest)) return [];
  const currentClassification = envelope.manifest.dataClassification;
  if (currentClassification !== "user_private" && currentClassification !== "secret") return [];

  const prior = [...state.toolResultLabels.values()]
    .filter((label) => (label.tags || []).some((tag) => tag === "manifest:user_private" || tag === "manifest:secret"));
  const currentScopes = subjectScopesForAction(envelope.manifest, action);
  if (sameSubjectScope(currentScopes, prior)) return [];
  const sourceCount = new Set(prior.map((label) => label.source)).size;
  if (!sourceCount) return [];

  return [finding(
    "Data Aggregation",
    "deterministic",
    "require_approval",
    "连续读取已形成敏感数据聚合，需要确认当前读取是否仍符合最小必要范围",
    currentClassification === "secret" || sourceCount >= 2 ? 45 : 30,
    {
      basis: "cross_tool_sensitive_read_aggregation",
      current_classification: currentClassification,
      prior_sensitive_source_count: sourceCount,
      prior_classifications: unique(prior.flatMap((label) => (label.tags || [])
        .filter((tag) => tag.startsWith("manifest:"))
        .map((tag) => tag.slice("manifest:".length)))),
      current_subject_scope_count: currentScopes.length,
      prior_subject_scope_count: unique(prior.flatMap((label) => label.subject_scopes || [])).length,
    },
  )];
}

function subjectScopesForAction(manifest: ToolSecurityManifest, action: AgentSentryAction): string[] {
  if (manifest.dataSubjects?.length === 1 && manifest.dataSubjects[0] === "caller") return ["caller"];
  const values = (manifest.subjectFields || []).flatMap((field) => readValuesAtField(action.args[field]));
  return unique(values.map((value) => createHash("sha256")
    .update(`agentsentry-subject-v1\u0000${value.normalize("NFKC").trim()}`, "utf8")
    .digest("base64url")
    .slice(0, 24)));
}

function sameSubjectScope(currentScopes: string[], prior: Label[]): boolean {
  if (!currentScopes.length || !prior.length) return false;
  const priorScopes = prior.map((label) => label.subject_scopes || []);
  if (priorScopes.some((scopes) => !scopes.length)) return false;
  return priorScopes.every((scopes) => scopes.some((scope) => currentScopes.includes(scope)));
}

function isReadOnlyManifest(manifest: ToolSecurityManifest): boolean {
  return manifest.sideEffects.length > 0
    && manifest.sideEffects.every((effect) => effect === "none" || effect === "file_read" || effect === "network_read")
    && !manifest.canExfiltrate;
}

function elevateManifestConfidentiality(
  fields: ReturnType<typeof extractFieldProvenance>,
  classification: ToolSecurityManifest["dataClassification"] | "unknown",
): ReturnType<typeof extractFieldProvenance> {
  if (classification !== "user_private" && classification !== "secret") return fields;
  const confidentiality = classification === "secret" ? "secret" : "internal";
  return fields.map((field) => {
    if (labelConfidentialityRank(field.confidentiality) >= labelConfidentialityRank(confidentiality)) return field;
    return {
      ...field,
      confidentiality,
      transformations: unique([...field.transformations, `manifest:${classification}`]),
      trustLabel: { ...field.trustLabel, confidentiality },
      semanticClaims: field.semanticClaims.map((claim) => ({
        ...claim,
        confidentiality: labelConfidentialityRank(claim.confidentiality) >= labelConfidentialityRank(confidentiality)
          ? claim.confidentiality
          : confidentiality,
      })),
    };
  });
}

function labelConfidentialityRank(value: "public" | "internal" | "secret"): number {
  return value === "secret" ? 3 : value === "internal" ? 2 : 1;
}

function toolFrequencyKey(action: AgentSentryAction): string {
  return stableToolKey(action.originalTool || action.tool || "unknown_tool");
}

function stableToolKey(value: string): string {
  return String(value || "unknown_tool")
    .normalize("NFKC")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    || "unknown_tool";
}

function workflowFrequencyBudget(
  action: AgentSentryAction,
  state: PolicyState,
  assessment: ActionAssessment,
  count: number,
): { requiresApproval: boolean; reason: string; basis: string; count: number } {
  if (isLowImpactWorkflowRead(action, assessment)) {
    return {
      requiresApproval: false,
      reason: "同一只读业务工具调用次数偏多，已记录审计，不打断正常多步任务",
      basis: "read_only_workflow_budget",
      count,
    };
  }
  if (isExplicitWorkflowSideEffect(action, state, assessment)) {
    return {
      requiresApproval: false,
      reason: "显式授权的工作流副作用工具调用次数偏多，参数仍在业务边界内，已记录审计",
      basis: "explicit_side_effect_workflow_budget",
      count,
    };
  }
  return {
    requiresApproval: true,
    reason: "同一高影响工具调用次数偏多，需要确认是否仍属于当前任务",
    basis: "high_impact_frequency_review",
    count,
  };
}

function isLowImpactWorkflowRead(action: AgentSentryAction, assessment: ActionAssessment): boolean {
  if (assessment.highRisk || assessment.sensitive || assessment.persistence || assessment.systemMutation || assessment.dangerousCommand) return false;
  if (["external_api_read", "read_webpage", "read_file", "memory_read"].includes(action.tool)) return true;
  const manifest = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!manifest) return false;
  const sideEffects = manifest.manifest.sideEffects || [];
  return !manifest.manifest.requiresExplicitAuthorization
    && !manifest.manifest.canExfiltrate
    && !manifest.manifest.acceptsSensitiveData
    && sideEffects.every((effect) => effect === "none" || effect === "file_read" || effect === "network_read");
}

function isExplicitWorkflowSideEffect(action: AgentSentryAction, state: PolicyState, assessment: ActionAssessment): boolean {
  if (assessment.sensitive || assessment.persistence || assessment.systemMutation || assessment.dangerousCommand) return false;
  if (!isApiLikeWorkflowTool(action)) return false;
  if (!hasTaskToolOverlap(state.currentTask || state.taskSpec.task, action)) return false;
  if (!numericArgumentsInsideWorkflowBudget(action.args)) return false;
  return true;
}

function isApiLikeWorkflowTool(action: AgentSentryAction): boolean {
  if (["call_api", "registered_effect_api", "registered_sensitive_read_api", "registered_privileged_api", "registered_persistent_api", "external_api_read"].includes(action.tool)) return true;
  const manifest = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  return Boolean(manifest?.manifest.sideEffects.some((effect) => effect === "network_read" || effect === "network_write"));
}

function hasTaskToolOverlap(task: string, action: AgentSentryAction): boolean {
  const taskTokens = new Set(semanticWorkflowTokens(task));
  if (!taskTokens.size) return false;
  const toolTokens = semanticWorkflowTokens(action.originalTool || action.tool);
  let overlap = 0;
  for (const token of toolTokens) {
    if (taskTokens.has(token)) overlap += 1;
    if (overlap >= 1 && token.length >= 5) return true;
    if (overlap >= 2) return true;
  }
  return false;
}

function semanticWorkflowTokens(value: string): string[] {
  const normalized = String(value || "")
    .normalize("NFKC")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase();
  const stop = new Set(["get", "set", "list", "search", "find", "check", "verify", "current", "conditions", "api", "tool", "data", "info", "the", "and", "for", "with", "from", "that", "this", "please"]);
  return normalized
    .split(/[^a-z0-9\u4e00-\u9fa5]+/u)
    .map((token) => token.trim())
    .filter((token) => token.length >= 3 && !stop.has(token))
    .slice(0, 48);
}

function numericArgumentsInsideWorkflowBudget(args: Record<string, unknown>): boolean {
  for (const [key, value] of Object.entries(args)) {
    const lowered = key.toLowerCase();
    const amountLike = /(amount|price|cost|charge|payment|usd|total|quantity|count|emissions)/i.test(lowered);
    if (!amountLike) continue;
    const numeric = typeof value === "number" ? value : typeof value === "string" ? Number(value.replace(/,/g, "")) : Number.NaN;
    if (!Number.isFinite(numeric)) continue;
    if (/(amount|price|cost|charge|payment|usd|total)/i.test(lowered) && numeric > 1000) return false;
    if (/(quantity|count)/i.test(lowered) && numeric > 100) return false;
    if (numeric < 0) return false;
  }
  return true;
}

function runtimeFeedbackFindingsFor(action: AgentSentryAction, state: PolicyState, config: PluginConfig): DetectionFinding[] {
  if (!config.runtimeIsolation.auditAfterExecution) return [];
  const profile = state.runtimeProfiles.get(action.tool) || state.runtimeProfiles.get(normalizeToolName(action.originalTool || action.tool));
  if (!profile || profile.runtime_alerts <= 0) return [];

  const assessment = assessAction(action, config);
  const sensitiveSink = assessment.highRisk || isTrustSensitiveSink(action, assessment);
  if (!sensitiveSink) return [];

  const critical = criticalRuntimeFeedback(profile);
  const score = Math.min(70, Math.max(25, critical ? profile.risk_score : Math.trunc(profile.risk_score / 2)));
  const verdict: "block" | "require_approval" = critical || profile.runtime_alerts >= 2 ? "block" : "require_approval";
  return [finding(
    "Evidence Feedback",
    "learned",
    verdict,
    critical
      ? "runtime feedback observed a critical kernel anomaly and blocks recurring high-risk tool use"
      : profile.runtime_alerts >= 2
        ? "runtime feedback observed repeated kernel anomalies and blocks recurring high-risk tool use"
        : "runtime feedback downgraded repeated high-risk tool use after a previous eBPF anomaly",
    score,
    {
      tool: action.tool,
      runtime_feedback: {
        alerts: profile.runtime_alerts,
        last_seen: profile.last_seen,
        reasons: profile.reasons.slice(-4),
        events: profile.events.slice(-4),
      },
    },
  )];
}

function criticalRuntimeFeedback(profile: RuntimeFeedbackProfile): boolean {
  const text = `${profile.reasons.join("\n")}\n${profile.events.join("\n")}`.toLowerCase();
  return /execution was observed after agentsentry blocked|unexpected process execution|unexpected sensitive file access/.test(text)
    && profile.risk_score >= 70;
}

function abacFindingsFor(action: AgentSentryAction, state: PolicyState): DetectionFinding[] {
  const assessment = assessActionWithSensitiveAssets(action, []);
  const decision = evaluateAbacDecision(action, assessment, state);
  if (decision.blockedFlow) rememberTaintFlow(state, decision.blockedFlow);
  return decision.findings;
}

function taskSpecBoundaryFindings(action: AgentSentryAction, state: PolicyState, config: PluginConfig): DetectionFinding[] {
  const taskSpec = state.taskSpec;
  const assessment = assessAction(action, config);
  if (!isTrustSensitiveSink(action, assessment)) return [];

  const family = taskSpec.task_family || "unknown";
  const mode = taskSpec.task_mode || "unknown";
  const confidence = Number.isFinite(taskSpec.task_confidence) ? (taskSpec.task_confidence || 0) : 0;
  const reasons: string[] = [];

  if (mode === "data_only" || mode === "chatter") {
    reasons.push(`task mode ${mode} does not grant side-effect authority`);
  }
  if ((family === "analysis" || family === "read_only") && confidence < 0.7) {
    reasons.push(`task family ${family} is not a stable side-effect boundary`);
  }
  if (family === "mixed" && confidence < 0.5) {
    reasons.push("mixed task spec has low confidence for side-effect approval");
  }
  if (taskSpec.capabilities.length > 4 && confidence < 0.8) {
    reasons.push("task spec contains several capability clauses and benefits from semantic review");
  }
  if (taskSpec.allowed_tools.some((tool) => ["send_email", "write_file", "call_api", "memory_write", "shell_exec"].includes(tool)) && confidence < 0.75) {
    reasons.push("task spec includes side-effect tools with uncertain scope");
  }
  if (!reasons.length) return [];

  const verdict: "block" | "require_approval" = mode === "data_only" || mode === "chatter" ? "require_approval" : "require_approval";
  return [finding(
    "Intent Authorization",
    "heuristic",
    verdict,
    reasons.join("；"),
    mode === "data_only" || mode === "chatter" ? 35 : 22,
    {
      tool: action.tool,
      task_mode: mode,
      task_family: family,
      task_confidence: confidence,
      task_spec: {
        allowed_tools: taskSpec.allowed_tools.slice(0, 8),
        denied_tools: taskSpec.denied_tools.slice(0, 8),
        forbidden_tools: taskSpec.forbidden_tools.slice(0, 8),
      },
    },
  )];
}

/**
 * Enforces the part of a signed tool contract that cannot be inferred from a
 * prompt: a private lookup about another person must name a subject and be
 * attached to an active user task. It deliberately produces approval rather
 * than denial. A legitimate investigation can continue after its scope is
 * made explicit; an unscoped dossier-building workflow cannot silently grow.
 */
function manifestPurposeBoundaryFindings(action: AgentSentryAction, state: PolicyState): DetectionFinding[] {
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!envelope) return [];
  const manifest = envelope.manifest;
  const privateData = manifest.dataClassification === "user_private" || manifest.dataClassification === "secret";
  const thirdPartyData = manifest.dataSubjects?.some((subject) => subject === "named_subject" || subject === "third_party");
  if (!privateData || !thirdPartyData || manifest.purposeBinding !== "task_bound") return [];

  const mode = state.taskSpec.task_mode || "unknown";
  if (!state.taskSpec.task.trim() || mode === "chatter" || mode === "data_only") {
    return [finding(
      "Intent Authorization",
      "deterministic",
      "require_approval",
      "私密第三方数据查询缺少可执行的用户任务范围，需要说明业务目的和数据主体",
      40,
      {
        tool: action.tool,
        tool_id: manifest.toolId,
        data_classification: manifest.dataClassification,
        data_subjects: manifest.dataSubjects,
        purpose_binding: manifest.purposeBinding,
        task_mode: mode,
      },
    )];
  }

  const targetFields = manifest.targetFields || [];
  if (!targetFields.length) {
    return [finding(
      "Tool Manifest",
      "deterministic",
      "require_approval",
      "私密第三方数据工具缺少主体绑定字段声明，无法验证本次查询对象是否属于当前任务",
      35,
      {
        tool: action.tool,
        tool_id: manifest.toolId,
        data_classification: manifest.dataClassification,
        data_subjects: manifest.dataSubjects,
        missing_contract_field: "targetFields",
      },
    )];
  }

  const subjectValues = targetFields.flatMap((field) => readValuesAtField(action.args[field]));
  if (subjectValues.length) return [];
  return [finding(
    "Intent Authorization",
    "deterministic",
    "require_approval",
    "私密第三方数据查询未提供工具契约声明的主体标识，需要确认查询对象",
    35,
    {
      tool: action.tool,
      tool_id: manifest.toolId,
      target_fields: targetFields,
      data_classification: manifest.dataClassification,
      data_subjects: manifest.dataSubjects,
    },
  )];
}

function ifcExecutionBoundaryFindings(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  state: PolicyState,
  authorization: CapabilityAuthorization,
  provenanceLinks: SemanticProvenanceLink[],
): DetectionFinding[] {
  const sink = sinkForAction(action, assessment);
  if (!sink || !isTrustSensitiveSink(action, assessment) || !provenanceLinks.length) return [];

  const consumedIds = provenanceLinks.map((link) => link.provenanceId).filter(Boolean);
  const consumedLineage = provenanceClosure(consumedIds, state.dataProvenance);
  if (!consumedLineage.size) return [];

  const branches = state.ifcBranches
    .filter((branch) => branch.status === "isolated")
    .filter((branch) => branch.provenanceIds.some((id) => consumedLineage.has(id)));
  if (!branches.length) return [];

  const strongest = [...branches].sort((left, right) =>
    confidentialityRank(right.confidentiality) - confidentialityRank(left.confidentiality)
    || right.risk - left.risk
    || right.confidence - left.confidence
  )[0];
  const severe = branches.some((branch) =>
    branch.confidentiality === "tenant-secret"
    || branch.risk >= 80
    || branch.integrity === "untrusted-external" && branch.risk >= 65
  );
  const strongAuthorization = hasStrongUserAuthorization(authorization);
  const verdict: "block" | "require_approval" = severe || !strongAuthorization ? "block" : "require_approval";
  const reason = verdict === "block"
    ? "IFC 执行边界阻断：高风险工具正在消费未清洗的低信任数据分支"
    : "IFC 执行边界要求审批：高风险工具消费了隔离分支数据，需要确认清洗结果和用途";

  return [finding(
    "IFC Execution Boundary",
    "deterministic",
    verdict,
    reason,
    verdict === "block" ? 100 : 70,
    {
      tool: action.tool,
      sink,
      authorization_reason: authorization.reason,
      authorized: authorization.authorized,
      consumed_provenance_ids: consumedIds.slice(0, 12),
      consumed_lineage_ids: Array.from(consumedLineage).slice(0, 16),
      strongest_branch: {
        id: strongest.id,
        source: strongest.source,
        integrity: strongest.integrity,
        confidentiality: strongest.confidentiality,
        purpose: strongest.purpose,
        risk: strongest.risk,
        confidence: strongest.confidence,
      },
      branches: branches.slice(0, 6).map((branch) => ({
        id: branch.id,
        source: branch.source,
        integrity: branch.integrity,
        confidentiality: branch.confidentiality,
        risk: branch.risk,
        confidence: branch.confidence,
      })),
    },
  )];
}

function hasStrongUserAuthorization(authorization: CapabilityAuthorization): boolean {
  const capability = authorization.capability;
  return Boolean(authorization.authorized
    && capability
    && capability.evidence.source === "user"
    && capability.evidence.explicitAuthorization
    && !capability.evidence.insideQuotation
    && !capability.evidence.negated
    && capability.evidence.targetIsConcrete
    && capability.evidence.confidence >= 0.82);
}

function provenanceClosure(ids: string[], provenance: DataProvenance[]): Set<string> {
  const byId = new Map(provenance.map((item) => [item.id, item]));
  const closure = new Set<string>();
  const pending = ids.filter(Boolean);
  while (pending.length && closure.size < 512) {
    const id = pending.pop()!;
    if (!id || closure.has(id)) continue;
    closure.add(id);
    const node = byId.get(id);
    if (node) pending.push(...node.parentIds);
  }
  return closure;
}

function confidentialityRank(value: IFCBranch["confidentiality"]): number {
  return { public: 0, internal: 1, "user-private": 2, "tenant-secret": 3 }[value] ?? 0;
}

function strongestSemanticClaimConfidentiality(claims: SemanticClaim[]): IFCBranch["confidentiality"] {
  return claims.reduce<IFCBranch["confidentiality"]>((strongest, claim) => {
    const next: IFCBranch["confidentiality"] = claim.confidentiality === "secret" ? "tenant-secret" : claim.confidentiality;
    return confidentialityRank(next) > confidentialityRank(strongest) ? next : strongest;
  }, "public");
}

function matchingPersistentMemoryLabels(
  state: PolicyState,
  result: unknown,
  fields: FieldProvenance[],
): PersistentMemoryLabel[] {
  if (!state.persistentMemoryLabels.length) return [];
  const hashes = new Set<string>([
    memoryContentHash(result),
    ...fields.map((field) => field.contentFingerprint),
  ]);
  return state.persistentMemoryLabels.filter((label) => hashes.has(label.content_sha256)).slice(-12);
}

function persistentMemoryIFCFindings(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  state: PolicyState,
): DetectionFinding[] {
  if (!state.persistentMemoryLabels.length) return [];
  const key = memoryKeyForAction(action);
  if (!key) return [];
  const labels = state.persistentMemoryLabels.filter((label) => memoryKeysOverlap(label.key, key)).slice(-12);
  if (!labels.length) return [];
  const lowTrust = labels.filter((label) =>
    label.integrity === "untrusted-external"
    || label.confidentiality === "tenant-secret"
    || riskMax(label.risk_vector) >= 50
  );
  if (!lowTrust.length) return [];
  if (action.tool === "memory_read" || action.tool === "read_file") {
    return [finding(
      "Memory IFC",
      "deterministic",
      "require_approval",
      "跨会话记忆标签提示：读取的长期记忆包含低信任或高风险来源，读取后只能进入隔离分析分支",
      55,
      {
        key,
        labels: lowTrust.map(publicPersistentMemoryLabel),
      },
    )];
  }
  if (!isTrustSensitiveSink(action, assessment)) return [];
  return [finding(
    "Memory IFC",
    "deterministic",
    "block",
    "跨会话记忆标签阻断：低信任长期记忆不能直接授权高风险工具动作",
    100,
    {
      key,
      tool: action.tool,
      labels: lowTrust.map(publicPersistentMemoryLabel),
    },
  )];
}

function memoryKeyForAction(action: AgentSentryAction): string {
  if (action.tool !== "memory_read" && action.tool !== "memory_write" && action.tool !== "read_file" && action.tool !== "write_file") return "";
  const path = readFirstString(action.args, ["key", "name", "path", "file", "filename", "target"]);
  return path ? normalizeMemoryKey(path) : action.tool.startsWith("memory_") ? "memory" : "";
}

function memoryKeysOverlap(left: string, right: string): boolean {
  const a = normalizeMemoryKey(left).toLowerCase();
  const b = normalizeMemoryKey(right).toLowerCase();
  if (a === b) return true;
  const abase = a.split("/").pop();
  const bbase = b.split("/").pop();
  return Boolean(abase && bbase && abase === bbase);
}

function publicPersistentMemoryLabel(label: PersistentMemoryLabel): Record<string, unknown> {
  return {
    id: label.id,
    key: label.key,
    source_class: label.source_class,
    integrity: label.integrity,
    confidentiality: label.confidentiality,
    purpose: label.purpose,
    lifetime: label.lifetime,
    tags: label.tags.slice(0, 8),
    risk_vector: label.risk_vector,
    updated_at: label.updated_at,
  };
}

function isPersistentMemoryLabel(value: unknown): value is PersistentMemoryLabel {
  return Boolean(value
    && typeof value === "object"
    && typeof (value as PersistentMemoryLabel).id === "string"
    && typeof (value as PersistentMemoryLabel).key === "string"
    && typeof (value as PersistentMemoryLabel).content_sha256 === "string"
    && typeof (value as PersistentMemoryLabel).integrity === "string"
    && typeof (value as PersistentMemoryLabel).confidentiality === "string");
}

function isRuntimeAuditFinding(item: DetectionFinding): boolean {
  const audit = (item.evidence || {}).runtime_audit as Record<string, unknown> | undefined;
  return item.layer === "Tool Boundary"
    && audit?.source === "ebpf"
    && (item.verdict === "require_approval" || item.verdict === "block")
    && item.score >= 50;
}

function taintRisk(action: AgentSentryAction, state: PolicyState, config: PluginConfig): number {
  let risk = 0;
  const assessment = assessPolicyAction(action, config);
  const argsText = safeStringify(action.args).toLowerCase();
  const blockedTaint = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (!isManifestBoundReadRequestForAction(action) && action.tool !== "memory_write" && config.policy.sensitiveAssets.some((asset) => asset && argsText.includes(asset.toLowerCase()))) risk += 45;
  if (blockedTaint) risk += Math.min(45, Math.max(20, Math.trunc(blockedTaint.confidence / 2)));
  return Math.min(risk, 80);
}

function isManifestBoundReadRequestForAction(action: AgentSentryAction): boolean {
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  return Boolean(envelope && isManifestBoundReadRequest(action, envelope.manifest));
}

function provenanceRiskForAction(action: AgentSentryAction, state: PolicyState): Record<string, unknown> | null {
  if (!state.provenanceFindings.length) return null;
  const argsText = normalizeExposureText(safeStringify(action.args));
  if (!argsText) return null;
  const matched = state.provenanceFindings.filter((item) => {
    const evidence = (item.evidence || {}) as Record<string, unknown>;
    const rawPath = String(evidence.path || evidence.file || "").replace(/\\/g, "/").toLowerCase();
    if (!rawPath || item.verdict !== "block") return false;
    const base = rawPath.split("/").filter(Boolean).pop() || rawPath;
    return (rawPath.length >= 6 && argsText.includes(rawPath))
      || (base.length >= 6 && argsText.includes(base));
  });
  if (!matched.length) return null;
  return {
    matched_paths: matched.map((item) => String(((item.evidence || {}) as Record<string, unknown>).path || ((item.evidence || {}) as Record<string, unknown>).file || "")).slice(0, 5),
    blocked_findings: matched.map((item) => item.reason).slice(0, 5),
  };
}

function taintFlowForAction(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  state: PolicyState,
): PolicyState["taintFlows"][number] | null {
  const flow = evaluateAbacDecision(action, assessment, state).blockedFlow;
  if (!flow) return null;
  rememberTaintFlow(state, flow);
  return flow;
}

function evaluateAbacDecision(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  state: PolicyState,
) {
  return evaluateAbacDataFlow({
    action,
    assessment,
    sink: sinkForAction(action, assessment),
    labels: trustLabelsForAction(action, state),
    isolatedBranches: state.ifcBranches,
    taskSpec: state.taskSpec,
    aggregateRisk: state.aggregateRisk,
    taintedSources: state.taintedSources,
  });
}

function trustLabelsForAction(action: AgentSentryAction, state: PolicyState): TrustLabel[] {
  const labels: TrustLabel[] = [];
  collectActionTrustLabels(action.args, labels);
  const argsText = flattenText(action.args);
  const matched = matchExposure(argsText, state.exposures);
  if (matched?.exposure.label.trust_label) {
    const evidence = provenanceEvidenceForMatch(matched.mode);
    if (evidence.basis !== "conservative" && evidence.confidence >= 0.95) {
      labels.push(matched.exposure.label.trust_label);
    }
  }
  return labels;
}

function collectActionTrustLabels(value: unknown, labels: TrustLabel[], visited = new WeakSet<object>(), depth = 0): void {
  if (depth > 64) return;
  if (value && typeof value === "object") {
    if (visited.has(value)) return;
    visited.add(value);
  }
  if (isLabeledValue(value)) {
    if (value.label.trust_label) labels.push(value.label.trust_label);
    collectActionTrustLabels(value.value, labels, visited, depth + 1);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => collectActionTrustLabels(item, labels, visited, depth + 1));
    return;
  }
  if (!value || typeof value !== "object") return;
  try {
    Object.values(value as Record<string, unknown>).forEach((item) => collectActionTrustLabels(item, labels, visited, depth + 1));
  } catch {
    // Malformed action values are rejected by normalizePolicyAction before this traversal.
  }
}

function rememberTaintFlow(state: PolicyState, flow: PolicyState["taintFlows"][number]): void {
  const key = `${flow.label_id}:${flow.sink}:${flow.blocked}`;
  if (!state.taintFlows.some((item) => `${item.label_id}:${item.sink}:${item.blocked}` === key)) {
    state.taintFlows.push(flow);
  }
  if (state.taintFlows.length > 80) state.taintFlows = state.taintFlows.slice(-80);
}

function inspectPolicyValue(value: unknown): string {
  if (!value || typeof value !== "object") return "";
  const pending: Array<{ value: object; depth: number; exit?: boolean }> = [{ value, depth: 0 }];
  const active = new WeakSet<object>();
  const completed = new WeakSet<object>();
  let nodes = 0;
  while (pending.length) {
    const current = pending.pop()!;
    if (current.exit) {
      active.delete(current.value);
      completed.add(current.value);
      continue;
    }
    if (completed.has(current.value)) continue;
    if (active.has(current.value)) return "cyclic object reference";
    active.add(current.value);
    nodes += 1;
    if (nodes > 4096) return "structured value exceeds node limit";
    if (current.depth > 64) return "structured value exceeds depth limit";
    let children: unknown[];
    try {
      children = Object.values(current.value as Record<string, unknown>);
    } catch {
      return "structured value properties could not be read";
    }
    pending.push({ ...current, exit: true });
    for (const child of children) {
      if (child && typeof child === "object") pending.push({ value: child, depth: current.depth + 1 });
    }
  }
  return "";
}

function safeStringify(value: unknown): string {
  try {
    const serialized = redactSafeStringify(value);
    if (typeof serialized === "string") return serialized;
    return value === undefined ? "undefined" : String(value);
  } catch {
    try {
      return String(value);
    } catch {
      return "[unserializable value]";
    }
  }
}

function flattenText(value: unknown): string {
  if (inspectPolicyValue(value)) return safeStringify(value);
  try {
    const flattened = flattenValueText(value);
    return typeof flattened === "string" ? flattened : safeStringify(flattened);
  } catch {
    return safeStringify(value);
  }
}

function normalizePolicyAction(value: unknown): { action: AgentSentryAction; issue: string } {
  const fallback: AgentSentryAction = { tool: "unknown_tool", originalTool: "unknown_tool", args: {}, reason: "" };
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { action: fallback, issue: "action must be an object" };
    }
    const input = value as Partial<AgentSentryAction>;
    const tool = typeof input.tool === "string" && input.tool.trim() ? input.tool : "unknown_tool";
    const originalTool = typeof input.originalTool === "string" && input.originalTool.trim() ? input.originalTool : tool;
    const reason = typeof input.reason === "string" ? input.reason : "";
    if (!input.args || typeof input.args !== "object" || Array.isArray(input.args)) {
      return { action: { tool, originalTool, args: {}, reason }, issue: "action args must be an object" };
    }
    const issue = inspectPolicyValue(input.args);
    return {
      action: { tool, originalTool, args: issue ? {} : input.args, reason },
      issue,
    };
  } catch {
    return { action: fallback, issue: "action properties could not be read" };
  }
}

function normalizeFindingInput(value: unknown): { findings: DetectionFinding[]; invalidCount: number } {
  const findings: DetectionFinding[] = [];
  let invalidCount = 0;
  try {
    if (!Array.isArray(value)) return { findings, invalidCount: 1 };
    const declaredLength = value.length;
    if (!Number.isSafeInteger(declaredLength) || declaredLength < 0) return { findings, invalidCount: 1 };
    const length = Math.min(declaredLength, 2048);
    if (declaredLength > length) invalidCount += 1;
    for (let index = 0; index < length; index += 1) {
      let item: unknown;
      try {
        item = value[index];
      } catch {
        invalidCount += 1;
        continue;
      }
      if (isDetectionFinding(item)) findings.push(item);
      else invalidCount += 1;
    }
  } catch {
    return { findings: [], invalidCount: Math.max(1, invalidCount) };
  }
  return { findings, invalidCount };
}

function isDetectionFinding(value: unknown): value is DetectionFinding {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const item = value as Partial<DetectionFinding>;
    const evidence = item.evidence;
    return typeof item.layer === "string"
      && typeof item.reason === "string"
      && typeof item.score === "number"
      && Number.isFinite(item.score)
      && item.score >= 0
      && (item.finding_type === "deterministic"
        || item.finding_type === "heuristic"
        || item.finding_type === "behavioral"
        || item.finding_type === "semantic"
        || item.finding_type === "learned")
      && (item.verdict === "pass" || item.verdict === "require_approval" || item.verdict === "block")
      && Boolean(evidence && typeof evidence === "object" && !Array.isArray(evidence) && !inspectPolicyValue(evidence));
  } catch {
    return false;
  }
}

function isPolicyDecisionForUpdate(value: unknown): value is PolicyDecision {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const item = value as Partial<PolicyDecision>;
    if (item.decision !== "allow" && item.decision !== "ask" && item.decision !== "deny") return false;
    if (typeof item.risk_score !== "number" || !Number.isFinite(item.risk_score)) return false;
    if (normalizePolicyAction(item.action).issue) return false;
    if (!item.risk_vector || inspectPolicyValue(item.risk_vector) || !isRiskVector(item.risk_vector)) return false;
    return normalizeFindingInput(item.findings).invalidCount === 0;
  } catch {
    return false;
  }
}

function analyzePolicyResult(
  toolCallId: string,
  result: unknown,
  config: PluginConfig,
  toolName: string,
): {
  analysis: ReturnType<typeof analyzeTrustContent>;
  source: ReturnType<typeof sourceFromTool>;
  incompleteReason: string;
} {
  const failures: string[] = [];
  let source: ReturnType<typeof sourceFromTool> = "tool_result";
  try {
    source = toolName ? sourceForToolResult(toolName, result) : "tool_result";
    if (toolName && !resolveToolManifest(toolName) && source === "tool_result") source = "unknown";
  } catch {
    failures.push("tool result source classification failed");
    source = sourceFromTool(typeof toolName === "string" ? toolName : "unknown_tool");
    if (toolName && !resolveToolManifest(toolName) && source === "tool_result") source = "unknown";
  }
  const structuralIssue = inspectPolicyValue(result);
  if (structuralIssue) failures.push(structuralIssue);
  const options = {
    source,
    sourceId: toolCallId || toolName || "tool_result",
    toolName,
    previewChars: config.capture.previewChars,
  };
  let analysis: ReturnType<typeof analyzeTrustContent>;
  try {
    analysis = analyzeTrustContent(structuralIssue ? safeStringify(result) : result, options);
  } catch {
    failures.push("trust analysis failed");
    analysis = analyzeTrustContent(safeStringify(result), options);
  }
  return { analysis, source, incompleteReason: unique(failures).join("; ") };
}

function normalizeToolName(toolName: string): string {
  const registered = resolveToolManifest(toolName);
  if (registered) return registered.manifest.toolId;
  for (const [pattern, mapped] of TOOL_ALIASES) {
    if (pattern.test(toolName)) return mapped;
  }
  return toolName;
}

function normalizeArgs(tool: string, params: Record<string, unknown>): Record<string, unknown> {
  const args = { ...params };
  if (tool === "read_webpage" || tool === "call_api") {
    promote(args, "url", ["uri", "href", "target", "endpoint"]);
  }
  if (tool === "read_file" || tool === "write_file") {
    promote(args, "path", ["file", "filename", "target"]);
  }
  if (tool === "send_email") {
    promote(args, "recipient", ["recipients", "to", "target", "email"]);
    promote(args, "body", ["content", "message", "text"]);
  }
  return args;
}

function manifestAllowsImplicitRead(action: AgentSentryAction, taskSpec: TaskSpec): boolean {
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!envelope) return false;
  const manifest = envelope.manifest;
  const readOnly = manifest.sideEffects.every((effect) => effect === "none" || effect === "file_read" || effect === "network_read");
  if (!readOnly || manifest.canExfiltrate) return false;
  const targetInScope = manifestTargetIsInsideTaskScope(action, manifest, taskSpec);
  const publicReadWithoutConcreteTarget = manifest.dataClassification === "public"
    && manifest.accessScope === "explicit_target"
    && manifest.sensitiveInputHandling === "none"
    && Boolean(taskSpec.task?.trim())
    && !taskSpec.denied_tools.includes(action.tool);
  // A user request such as "verify this article" can authorize a public
  // lookup without naming the provider's exact endpoint. The response is
  // still an untrusted ingress and cannot authorize a later sink.
  if (!targetInScope && !publicReadWithoutConcreteTarget) return false;
  if (targetInScope) return true;
  if (!manifest.requiresExplicitAuthorization) return true;

  // An onboarded non-secret read produces data for the current task and has
  // no execution, persistence or egress capability. Its result remains
  // labeled and is checked again before any later sink. This prevents a
  // missing natural-language tool name from turning ordinary research or
  // account inspection into repeated approval prompts.
  if (manifest.dataClassification === "public"
    && manifest.sensitiveInputHandling !== "business_payload"
    && ["caller_bound", "explicit_target", "unscoped"].includes(manifest.accessScope || "unknown")) {
    return true;
  }

  // A caller-bound query can use an authentication credential to retrieve the
  // current caller's own data. It cannot name another subject, carry a
  // business payload, write state, or send data away. The contract is signed
  // at onboarding and therefore does not rely on the tool name.
  return manifest.accessScope === "caller_bound"
    && manifest.sensitiveInputHandling === "authentication_only"
    && !manifest.canExfiltrate
    && readOnly
    && isManifestBoundReadRequest(action, manifest);
}

function manifestTargetIsInsideTaskScope(action: AgentSentryAction, manifest: ToolSecurityManifest, taskSpec: TaskSpec): boolean {
  const targetFields = manifest.targetFields || [];
  if (!targetFields.length) return true;
  const values = targetFields.flatMap((field) => readValuesAtField(action.args[field]));
  const networkTargets = values.filter((value) => /^https?:\/\//i.test(value));
  if (!networkTargets.length) return true;
  return networkTargets.every((target) => targetAllowed(target, taskSpec.allowed_targets));
}

function readValuesAtField(value: unknown): string[] {
  if (typeof value === "string" && value.trim()) return [value.trim()];
  if (Array.isArray(value)) return value.flatMap(readValuesAtField);
  return [];
}

function assessPolicyAction(action: AgentSentryAction, config: PluginConfig): ActionAssessment {
  const assessment = assessAction(action, config);
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!envelope || !isManifestBoundReadRequest(action, envelope.manifest)) return assessment;

  // Authentication material passed only to the verified provider must not be
  // treated as an attempted exfiltration. Payload, write, execution and
  // cross-subject fields fail isManifestBoundReadRequest and retain the
  // regular high-risk assessment.
  return {
    ...assessment,
    highRisk: assessment.persistence || assessment.systemMutation || assessment.dangerousCommand,
    sensitive: false,
    reasons: assessment.reasons.filter((reason) => reason !== "arguments reference sensitive asset"),
  };
}

function isManifestBoundReadRequest(action: AgentSentryAction, manifest: ToolSecurityManifest): boolean {
  if (manifest.accessScope !== "caller_bound" || manifest.sensitiveInputHandling !== "authentication_only") return false;
  if (manifest.canExfiltrate || manifest.sideEffects.some((effect) => !["none", "file_read", "network_read"].includes(effect))) return false;
  const credentials = new Set((manifest.credentialFields || []).map((field) => field.toLowerCase()));
  const targets = new Set((manifest.targetFields || []).map((field) => field.toLowerCase()));
  if (!credentials.size) return false;
  const keys = Object.keys(action.args).filter((key) => !key.startsWith("__"));
  if (!keys.length || !keys.some((key) => credentials.has(key.toLowerCase()))) return false;
  return keys.every((key) => credentials.has(key.toLowerCase()) || targets.has(key.toLowerCase()));
}

function readStringValues(args: Record<string, unknown>, keys: string[]): string[] {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) return [value.trim()];
    if (Array.isArray(value)) {
      const values = value.map((item) => flattenValueText(item).trim()).filter(Boolean);
      if (values.length) return values;
    }
    if (isLabeledValue(value)) {
      const text = flattenValueText(value.value).trim();
      if (text) return [text];
    }
  }
  return [];
}

function promote(args: Record<string, unknown>, target: string, sources: string[]): void {
  if (args[target] !== undefined) return;
  for (const source of sources) {
    if (args[source] !== undefined) {
      args[target] = args[source];
      return;
    }
  }
}

function extractLatestUserText(messages: unknown): string | null {
  if (!Array.isArray(messages)) return null;
  for (let i = messages.length - 1; i >= 0; i--) {
    try {
      const message = messages[i] as Record<string, unknown>;
      if (!message || typeof message !== "object" || message.role !== "user") continue;
      return flattenText(message.content).trim();
    } catch {
      return "[unreadable user message]";
    }
  }
  return null;
}

function finding(
  layer: string,
  findingType: DetectionFinding["finding_type"],
  verdict: "pass" | "require_approval" | "block",
  reason: string,
  score: number,
  evidence: Record<string, unknown>,
): DetectionFinding {
  return { layer, finding_type: findingType, verdict, reason, score, evidence };
}

function trustedToolLabel(toolCallId: string): Label {
  return {
    source: toolCallId ? `tool:${toolCallId}` : "tool:unknown",
    integrity: "trusted",
    confidentiality: "public",
    tainted: false,
  };
}

function heuristicScore(findings: DetectionFinding[]): number {
  return Math.min(
    findings
      .filter((finding) => finding.finding_type !== "deterministic" && finding.verdict !== "pass")
      .reduce((total, finding) => total + finding.score, 0),
    100,
  );
}

function baseToolRisk(tool: string): number {
  return {
    read_file: 18,
    write_file: 22,
    send_email: 25,
    call_api: 20,
    memory_write: 25,
    memory_read: 10,
    read_webpage: 10,
    shell_exec: 25,
  }[tool] ?? 20;
}

function hasInjectionSignal(text: string): boolean {
  text = textVariants(text).join("\n");
  return /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|commands?)|system.{0,40}prompt|developer.{0,40}prompt|exfiltrate|api[_ -]?key|token|secret|password|bypass\s+(policy|guardrail|safety|restriction)|系统提示|开发者提示|内部配置/i.test(text);
}

function mergeFindingTrust(state: PolicyState, findings: DetectionFinding[]): void {
  state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, riskVectorFromFindings(findings));
  for (const item of findings) {
    const evidence = item.evidence || {};
    const label = evidence.trust_label;
    if (isTrustLabel(label)) rememberTrustLabel(state, label);
  }
}

function riskVectorFromFindings(findings: DetectionFinding[]): RiskVector {
  let vector = createRiskVector();
  for (const item of findings) {
    const evidence = item.evidence || {};
    const riskVector = evidence.risk_vector;
    if (isRiskVector(riskVector)) vector = mergeRiskVectors(vector, riskVector);
    if (item.layer === "State Integrity") vector = addRisk(vector, createRiskVector({ persistence: item.score }));
    if (item.layer === "Context Provenance") {
      const reason = String(item.reason || "").toLowerCase();
      vector = addRisk(vector, createRiskVector({
        prompt_injection: /(prompt|injection|hidden|pdf|image|message|content)/i.test(reason) ? item.score : 0,
        supply_chain: /(skill|configuration|workspace|provenance|provenance)/i.test(reason) ? item.score : 0,
      }));
    }
    if (item.layer === "Tool Boundary") vector = addRisk(vector, createRiskVector({ privilege: item.score }));
  }
  return vector;
}

function rememberTrustLabel(state: PolicyState, label: TrustLabel): void {
  if (!state.trustLabels.some((item) => item.id === label.id)) {
    state.trustLabels.push(label);
    if (state.trustLabels.length > 80) state.trustLabels = state.trustLabels.slice(-80);
  }
  if (label.tainted) {
    const source = `${label.source}:${label.evidence?.path || label.evidence?.toolName || label.id}`;
    if (!state.taintedSources.includes(source)) state.taintedSources.push(source);
    if (state.taintedSources.length > 80) state.taintedSources = state.taintedSources.slice(-80);
    state.contaminated = true;
  }
}

function rememberIFCBranch(state: PolicyState, branch: IFCBranch): void {
  const existing = state.ifcBranches.findIndex((item) => item.id === branch.id);
  if (existing >= 0) {
    state.ifcBranches[existing] = branch;
  } else {
    state.ifcBranches.push(branch);
    if (state.ifcBranches.length > 80) state.ifcBranches = state.ifcBranches.slice(-80);
  }
}

function promoteIFCBranches(state: PolicyState, source: string, provenanceIds: string[]): void {
  const idSet = new Set(provenanceIds.filter(Boolean));
  const target = [...state.ifcBranches].reverse().find((branch) =>
    branch.status === "isolated"
    && branch.source === source
    && (!idSet.size || branch.provenanceIds.some((id) => idSet.has(id)))
  );
  if (!target) return;
  target.status = "merged";
  target.summary = `${target.summary}; merged_after_cleanup`;
  target.confidence = Math.max(target.confidence, 0.85);
}

function ifcConfidentiality(value: string): IFCBranch["confidentiality"] {
  if (value === "secret") return "tenant-secret";
  if (value === "internal") return "internal";
  return "public";
}

function isTrustLabel(value: unknown): value is TrustLabel {
  return Boolean(value && typeof value === "object" && typeof (value as TrustLabel).source === "string" && typeof (value as TrustLabel).signature === "string");
}

function isRiskVector(value: unknown): value is RiskVector {
  if (!value || typeof value !== "object") return false;
  return "prompt_injection" in value && "sensitive_data" in value && "tool_hijack" in value;
}

function textVariants(text: string): string[] {
  const normalized = canonicalText(text);
  return unique([normalized, ...decodedTextCandidates(normalized)].filter(Boolean)).slice(0, 12);
}

function canonicalText(text: string): string {
  return text.normalize("NFKC").replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00ad]/g, "");
}

function decodedTextCandidates(text: string): string[] {
  const tokens = text.match(/[A-Za-z0-9+/_=-]{16,}|(?:[0-9A-Fa-f]{2}){8,}/g) || [];
  const out: string[] = [];
  const percent = decodePercentText(text);
  if (percent) out.push(percent);
  for (const token of tokens.slice(0, 24)) {
    if (token.length > 4096) continue;
    const b64 = decodeBase64Text(token);
    if (b64) out.push(b64);
    const hex = decodeHexText(token);
    if (hex) out.push(hex);
  }
  return out;
}

function decodePercentText(text: string): string {
  if (!/%[0-9A-Fa-f]{2}/.test(text)) return "";
  try {
    return printableText(decodeURIComponent(text.replace(/\+/g, "%20")));
  } catch {
    return "";
  }
}

function decodeBase64Text(token: string): string {
  if (token.length < 16) return "";
  try {
    const normalized = token.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    return printableText(Buffer.from(padded, "base64").toString("utf8"));
  } catch {
    return "";
  }
}

function decodeHexText(token: string): string {
  if (token.length < 16 || token.length % 2) return "";
  if (!/^[0-9A-Fa-f]+$/.test(token)) return "";
  try {
    return printableText(Buffer.from(token, "hex").toString("utf8"));
  } catch {
    return "";
  }
}

function printableText(value: string): string {
  if (!value || value.length > 4096) return "";
  let printable = 0;
  for (const char of value) {
    if (/\s/.test(char) || char >= " ") printable += 1;
  }
  return printable / Math.max(value.length, 1) >= 0.85 ? canonicalText(value) : "";
}

function matchExposure(text: string, exposures: PolicyState["exposures"]): { exposure: PolicyState["exposures"][number]; mode: string } | null {
  const normalizedVariants = exposureTextVariants(text);
  if (!normalizedVariants.length) return null;
  const targetClaims = semanticClaimsForValue({ value: text });
  for (let exposureIndex = exposures.length - 1; exposureIndex >= 0; exposureIndex -= 1) {
    const exposure = exposures[exposureIndex];
    const candidateVariants = exposureTextVariants(exposure.text);
    for (let textIndex = 0; textIndex < normalizedVariants.length; textIndex += 1) {
      const normalized = normalizedVariants[textIndex];
      for (let candidateIndex = 0; candidateIndex < candidateVariants.length; candidateIndex += 1) {
        const candidate = candidateVariants[candidateIndex];
        const minLength = Math.min(normalized.length, candidate.length);
        const transformed = textIndex > 0 || candidateIndex > 0;
        if (minLength >= 8 && normalized === candidate) {
          return { exposure, mode: transformed ? "encoded_exact" : "exact" };
        }
        if (minLength >= 24 && (normalized.includes(candidate) || candidate.includes(normalized))) {
          return { exposure, mode: transformed ? "encoded_substring" : "substring" };
        }
        if (minLength >= 32 && similarity(normalized.slice(0, 1200), candidate.slice(0, 1200)) >= 0.82) {
          return { exposure, mode: transformed ? "encoded_fuzzy" : "fuzzy" };
        }
      }
    }
    const semanticMatch = matchSemanticClaims(targetClaims, exposure.semanticClaims || []);
    if (semanticMatch) return { exposure, mode: semanticMatch };
  }
  return null;
}

function provenanceEvidenceForMatch(mode: string): { basis: SemanticEvidenceBasis; confidence: number } {
  if (mode === "exact") return { basis: "observed", confidence: 1 };
  if (mode === "encoded_exact") return { basis: "decoded", confidence: 0.98 };
  if (mode === "substring") return { basis: "conservative", confidence: 0.9 };
  if (mode === "encoded_substring") return { basis: "conservative", confidence: 0.86 };
  if (mode === "fuzzy") return { basis: "conservative", confidence: 0.82 };
  if (mode === "encoded_fuzzy") return { basis: "conservative", confidence: 0.78 };
  if (mode === "semantic_derivation") return { basis: "conservative", confidence: 0.72 };
  return { basis: "conservative", confidence: 0.7 };
}

function matchSemanticClaims(targetClaims: SemanticClaim[], sourceClaims: SemanticClaim[]): "semantic_derivation" | "" {
  if (!targetClaims.length || !sourceClaims.length) return "";
  for (const source of sourceClaims) {
    for (const target of targetClaims) {
      if (source.kind !== target.kind) continue;
      if (source.kind === "financial_band" && source.value === target.value && Math.min(source.confidence, target.confidence) >= 0.68) {
        return "semantic_derivation";
      }
      if (source.kind === "credential_reference" && target.value === "credential_material" && Math.min(source.confidence, target.confidence) >= 0.82) {
        return "semantic_derivation";
      }
      if (source.kind === "privileged_access" && target.value === "privileged_system_surface" && Math.min(source.confidence, target.confidence) >= 0.78) {
        return "semantic_derivation";
      }
    }
  }
  return "";
}

function compactEvidenceList(values: string[], limit: number): string[] {
  if (values.length <= limit) return [...values];
  const head = Math.ceil(limit / 2);
  const tail = Math.floor(limit / 2);
  return [...values.slice(0, head), ...values.slice(-tail)];
}

function isControlArg(name: string): boolean {
  return /^(timeout|timeoutms|max_?tokens?|limit|page|pagesize|offset|cursor|count|retries|retry|temperature|top_p|stream)$/i.test(String(name || ""));
}

function normalizeExposureText(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}

function exposureTextVariants(value: string): string[] {
  return unique(textVariants(value).map(normalizeExposureText).filter(Boolean));
}

function provenanceArgPath(key: string): string {
  return /^[A-Za-z_$][\w$]*$/.test(key) ? `$.args.${key}` : `$.args[${JSON.stringify(key)}]`;
}

function similarity(left: string, right: string): number {
  const leftTokens = new Set(left.split(/\s+/).filter(Boolean));
  const rightTokens = new Set(right.split(/\s+/).filter(Boolean));
  if (!leftTokens.size || !rightTokens.size) return 0;
  let intersection = 0;
  for (const token of leftTokens) {
    if (rightTokens.has(token)) intersection += 1;
  }
  return intersection / Math.max(leftTokens.size, rightTokens.size);
}

function dedupeFindings(findings: DetectionFinding[]): DetectionFinding[] {
  const seen = new Set<string>();
  const out: DetectionFinding[] = [];
  for (const item of findings) {
    const key = `${item.layer}:${item.finding_type}:${item.verdict}:${item.reason}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}
