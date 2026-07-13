import type { PluginConfig } from "../config.ts";
import type { SemanticGraph } from "./action-semantics.ts";
import type { DetectionFinding } from "./detect.ts";
import { decisionFromRisk, mergeDecision } from "./judge/decision-merge.ts";
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
import { behaviorAnomalyFindingsFor, updateBehaviorProfile, type BehaviorProfile } from "./policy/behavior-baseline.ts";
import { containsAny, flattenText as flattenValueText, hostFromUrl, isLabeledValue, readFirstString, unique } from "./policy/value-utils.ts";
import { clampText, safeStringify as redactSafeStringify } from "./redact.ts";
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
  transformProvenance,
  type DataProvenance,
  type FieldProvenance,
} from "./taint/provenance-graph.ts";
import { authorizeCapability, deriveTaskSpecV2, isSideEffectToolCall, type TaskSpec } from "./task-spec/index.ts";
import { resolveToolManifest } from "./tool-manifest.ts";
import {
  addRisk,
  analyzeTrustContent,
  createRiskVector,
  mergeRiskVectors,
  minimumTrustLabel,
  riskMax,
  sourceFromTool,
  taintBlockedForSink,
  taintProfileFromLabel,
  type RiskVector,
  type TaintProfile,
  type TaintSink,
  type TrustLabel,
} from "./trust.ts";

export type AgentSentryAction = {
  tool: string;
  originalTool: string;
  args: Record<string, unknown>;
  reason: string;
};

export type { TaskSpec } from "./task-spec/index.ts";

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
  taint_profile?: TaintProfile;
  provenance_ids?: string[];
};

export type PolicyState = {
  currentTask: string;
  taskSpec: TaskSpec;
  contaminated: boolean;
  provenanceBlocked: boolean;
  provenanceFindings: DetectionFinding[];
  history: Array<{
    tool: string;
    decision: "allow" | "ask" | "deny";
    risk_score: number;
  }>;
  toolResultLabels: Map<string, Label>;
  exposures: Array<{
    source: string;
    text: string;
    label: Label;
    provenanceId?: string;
  }>;
  apiCallCounts: Map<string, number>;
  behaviorProfiles: Map<string, BehaviorProfile>;
  trustLabels: TrustLabel[];
  aggregateRisk: RiskVector;
  taintedSources: string[];
  taintFlows: Array<{
    label_id: string;
    source: string;
    sink: TaintSink;
    blocked: boolean;
    confidence: number;
    reason: string;
    tags: string[];
  }>;
  dataProvenance: DataProvenance[];
  semanticActionGraph: SemanticActionGraphState;
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
};

export type PolicyDecisionContext = {
  toolCallId?: string;
  semanticGraph?: SemanticGraph;
  provenanceLinks?: SemanticProvenanceLink[];
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
  const semanticActionGraph = createSemanticActionGraph();
  activateSemanticIntent(semanticActionGraph, taskSpec);

  return {
    currentTask: "",
    taskSpec,
    contaminated: false,
    provenanceBlocked: false,
    provenanceFindings: [],
    history: [],
    toolResultLabels: new Map(),
    exposures: [],
    apiCallCounts: new Map(),
    behaviorProfiles: new Map(),
    trustLabels: [],
    aggregateRisk: createRiskVector(),
    taintedSources: [],
    taintFlows: [],
    dataProvenance: [],
    semanticActionGraph,
  };
}

export function updateTaskSpec(state: PolicyState, messages: unknown, config: PluginConfig): void {
  const task = extractLatestUserText(messages);
  if (task === null || task === state.currentTask) return;
  state.currentTask = task;
  state.taskSpec = deriveTaskSpec(task, config.policy.sensitiveAssets);
  activateSemanticIntent(state.semanticActionGraph, state.taskSpec);
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
} {
  if (!config.detection.enabled || !config.policy.deterministic || !state.exposures.length) {
    return { action, findings: [], links: [] };
  }

  const args = { ...action.args };
  const findings: DetectionFinding[] = [];
  const links: SemanticProvenanceLink[] = [];
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
    if (lineage && !state.dataProvenance.some((item) => item.id === lineage.id)) {
      rememberDataProvenance(state, [publicProvenance(lineage)]);
    }
    if (lineage) {
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
        provenance_id: lineage?.id || exposure.provenanceId || "",
        parent_ids: lineage?.parentIds || [],
        provenance_path: lineage?.path || "",
        },
      ));
    }
  }

  if (!matchedAny) return { action, findings, links };
  return { action: { ...action, args }, findings, links };
}

export function decideAction(
  action: AgentSentryAction,
  state: PolicyState,
  config: PluginConfig,
  incomingFindings: DetectionFinding[],
  context: PolicyDecisionContext = {},
): PolicyDecision {
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
  const assessment = assessAction(action, config);
  const capabilityAuthorization = authorizeCapability(taskSpec, action);
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
  if (!capabilityAuthorization.authorized && !manifestAllowsUnscopedRead(action)) {
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
    findings.push(finding(
      "Context Provenance",
      "deterministic",
      "block",
      "tool call directly references a workspace item marked risky by provenance scan",
      100,
      directProvenanceRisk,
    ));
    violations.push("tool call directly references risky workspace item");
  }

  const outsideTaskSpec = taskSpec.forbidden_tools.includes(action.tool) || !taskSpec.allowed_tools.includes(action.tool);
  if (config.policy.deterministic && outsideTaskSpec && shouldHardBlockTaskMismatch(action, assessment, state)) {
    violations.push(`tool ${action.tool} is outside TaskSpec`);
    findings.push(finding("Tool Boundary", "deterministic", "block", `tool ${action.tool} is outside TaskSpec`, 100, { tool: action.tool, assessment }));
  } else if (riskScoringEnabled && outsideTaskSpec) {
    risk += assessment.highRisk ? 40 : 12;
    findings.push(finding("Tool Boundary", "heuristic", assessment.highRisk ? "require_approval" : "pass", `tool ${action.tool} is outside TaskSpec`, assessment.highRisk ? 35 : 8, { tool: action.tool, assessment }));
  } else {
    reasons.push("tool is allowed by TaskSpec");
  }

  if (riskScoringEnabled) {
    const alignmentFindings = decisionAlignment(action, taskSpec);
    findings.push(...alignmentFindings);
  }

  const policyViolations = config.policy.deterministic ? deterministicViolations(action, taskSpec, state, config) : [];
  for (const violation of policyViolations) {
    violations.push(violation);
    findings.push(finding("Tool Boundary", "deterministic", "block", violation, 100, { tool: action.tool }));
  }
  for (const reason of findings
    .filter((item) => item.finding_type === "deterministic" && item.verdict === "block")
    .map((item) => item.reason)) {
    violations.push(reason);
  }

  if (riskScoringEnabled) {
    const trajectoryFindings = trajectoryFindingsFor(action, state, config);
    findings.push(...trajectoryFindings);

    const behaviorFindings = behaviorAnomalyFindingsFor(action, state, config);
    findings.push(...behaviorFindings);

    const trustFindings = trustFindingsFor(action, state);
    findings.push(...trustFindings);
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
  };
}

export function updateAfterMessage(state: PolicyState, findings: DetectionFinding[]): void {
  const normalized = normalizeFindingInput(findings);
  if (normalized.invalidCount) {
    normalized.findings.push(finding("Context Provenance", "deterministic", "block", "message security findings failed validation; state marked contaminated", 100, {
      invalid_findings: normalized.invalidCount,
    }));
  }
  if (normalized.findings.some((item) => item.layer === "Context Provenance" || item.layer === "State Integrity")) {
    state.contaminated = true;
  }
  mergeFindingTrust(state, normalized.findings);
}

export function updateAfterDecision(state: PolicyState, decision: PolicyDecision): void {
  if (!isPolicyDecisionForUpdate(decision)) {
    state.history.push({ tool: "unknown_tool", decision: "deny", risk_score: 100 });
    if (state.history.length > 80) state.history = state.history.slice(-80);
    state.contaminated = true;
    state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, createRiskVector({ tool_hijack: 100, privilege: 100 }));
    return;
  }
  state.history.push({
    tool: decision.action.tool,
    decision: decision.decision,
    risk_score: decision.risk_score,
  });
  if (state.history.length > 80) state.history = state.history.slice(-80);
  if (decision.findings.some((finding) => finding.layer === "Context Provenance" || finding.layer === "State Integrity")) {
    state.contaminated = true;
  }
  if (decision.decision === "allow") updateBehaviorProfile(state, decision.action);
  state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, decision.risk_vector);
  mergeFindingTrust(state, decision.findings);
}

export function updateActionGraphEnforcement(
  state: PolicyState,
  decision: PolicyDecision,
  status: "awaiting_approval" | "blocked" | "executing",
): void {
  if (!decision.action_graph_node_id) return;
  markSemanticActionEnforcement(state.semanticActionGraph, decision.action_graph_node_id, {
    decision: decision.decision,
    status,
  });
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

export function labelToolResult(toolCallId: string, result: unknown, state: PolicyState, config: PluginConfig, toolName = ""): Label {
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
  const provenanceUntrusted = !toolName || ["external_web", "email_html", "pdf_text", "image_metadata", "webhook"].includes(source);
  const maliciousTaint = Boolean(incompleteReason) || analysis.label.tainted || hasInjectionSignal(text) || riskMax(analysis.risk_vector) >= 50;
  const label: Label = {
    source: toolCallId ? `tool:${toolCallId}` : "tool:unknown",
    integrity: "untrusted",
    confidentiality: "public",
    tainted: false,
    provenance_untrusted: provenanceUntrusted,
    influence: "none",
    trust_label: analysis.label,
    risk_vector: analysis.risk_vector,
    tags: unique([...analysis.tags, ...(incompleteReason ? ["analysis_incomplete"] : [])]),
    taint_profile: taintProfileFromLabel(analysis.label) || undefined,
    provenance_ids: fieldProvenance.map((field) => field.id),
  };
  if (maliciousTaint) {
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
    if (field.integrity === "tainted" || field.confidentiality === "secret") {
      const fieldLabel: Label = {
        source: `${toolCallId ? `tool:${toolCallId}` : "tool:unknown"}::${field.path}`,
        integrity: field.integrity === "trusted" ? "trusted" : "untrusted",
        confidentiality: field.confidentiality,
        tainted: field.integrity === "tainted",
        provenance_untrusted: provenanceUntrusted,
        influence: "none",
        trust_label: field.trustLabel,
        risk_vector: field.riskVector,
        tags: field.tags,
        taint_profile: taintProfileFromLabel(field.trustLabel) || undefined,
      };
      state.exposures.push({ source: fieldLabel.source, text: field.value, label: fieldLabel, provenanceId: field.id });
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
    state.exposures.push({ source: label.source, text, label: { ...label } });
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
  options: { error?: unknown } = {},
): DetectionFinding[] {
  const failed = options.error !== undefined && options.error !== null && Boolean(String(options.error).trim());
  const lifecycle = inspectToolResultLifecycle(state, toolCallId, toolName, failed ? "failed" : "succeeded");
  if (lifecycle.disposition === "duplicate_terminal") return [];
  if (failed) {
    completeSemanticAction(state.semanticActionGraph, { toolCallId, tool: toolName, status: "failed" });
    return [];
  }
  if (!config.detection.enabled) {
    labelToolResult(toolCallId, result, state, config, toolName);
    return lifecycle.disposition === "executed_after_block"
      ? [enforcementBypassFinding(lifecycle, toolName)]
      : [];
  }
  const { analysis } = analyzePolicyResult(toolCallId, result, config, toolName);
  const label = labelToolResult(toolCallId, result, state, config, toolName);
  const findings = [...analysis.findings];
  if (lifecycle.disposition === "executed_after_block") {
    findings.unshift(enforcementBypassFinding(lifecycle, toolName));
  }
  const injectionSignal = hasInjectionSignal(safeStringify(result));
  const incomplete = label.tags?.includes("analysis_incomplete") || false;
  if (!findings.length && !injectionSignal && !incomplete) return [];
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
    provenance: state.dataProvenance.slice(-20),
    semantic_action_graph: semanticActionGraphSnapshot(state.semanticActionGraph),
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
  const messages: Record<string, string> = {
    explicit_user_denial: `user explicitly denied ${tool}`,
    missing_explicit_authorization: `tool ${tool} lacks explicit capability authorization`,
    non_authoritative_context_cannot_grant_side_effects: "memory or tool content cannot authorize a new side effect",
    non_authoritative_context: "non-user context cannot establish this capability",
    recipient_outside_authorization: "email recipient is outside the explicitly authorized recipients",
    attachment_outside_authorization: "email attachment is outside the explicitly authorized files",
    path_outside_authorization: "file path is outside the explicitly authorized paths",
    target_outside_authorization: "network target is outside the explicitly authorized targets",
    host_outside_authorization: "network host is outside the explicitly authorized hosts",
    method_outside_authorization: "HTTP method is outside the explicitly authorized methods",
    command_outside_authorization: "shell command is outside the explicitly authorized command",
    unknown_tool_capability: `tool ${tool} has no registered capability model`,
  };
  return messages[reason] || `tool ${tool} failed capability authorization: ${reason}`;
}

function deterministicViolations(action: AgentSentryAction, taskSpec: TaskSpec, state: PolicyState, config: PluginConfig): string[] {
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
    if (!taskSpec.allowed_tools.includes("send_email")) {
      violations.push("task intent does not allow email");
    }
  }

  if (action.tool === "write_file") {
    const path = readFirstString(action.args, ["path", "file", "filename", "target"]).replace(/\\/g, "/").toLowerCase();
    const content = readFirstString(action.args, ["content", "body", "text", "patch"]);
    if (!path) violations.push("missing write path");
    if (path.includes("..")) violations.push("write path contains traversal");
    if (assessment.systemMutation) violations.push("write path targets protected system path");
    if (config.policy.sensitiveAssets.some((asset) => asset && path.includes(asset.toLowerCase()))) violations.push("write path references sensitive asset");
    if (config.policy.restrictWritesToAllowedRoots && config.policy.allowedWriteRoots.length) {
      const root = path.split("/", 1)[0];
      if (!config.policy.allowedWriteRoots.includes(root)) violations.push(`write root ${root || "<empty>"} is not allowlisted`);
    }
    if (config.policy.sensitiveAssets.some((asset) => asset && content.toLowerCase().includes(asset.toLowerCase()))) {
      violations.push("content contains secret-tainted data");
    }
    if (/(^|\/)(memory\.md|agents\.md|soul\.md|user\.md|openclaw\.json|skill\.md)$/i.test(path) || /(^|\/)(?:cron\.d|systemd|startup|skills)(?:\/|$)/i.test(path)) {
      violations.push("write path targets memory, configuration, startup, or skill surface");
    }
    const writeContentAnalysis = analyzeTrustContent(content, { source: path.includes("skill") ? "skill" : "memory", path, previewChars: config.capture.previewChars });
    if (writeContentAnalysis.findings.some((finding) => finding.verdict === "block")) {
      violations.push("write content contains persistence or skill hijack instructions");
    }
    if (!taskSpec.allowed_tools.includes("write_file") && assessment.highRisk) {
      violations.push("task intent does not allow file write");
    }
  }

  if (action.tool === "read_file") {
    const path = readFirstString(action.args, ["path", "file", "filename", "target"]).replace(/\\/g, "/").toLowerCase();
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
    if (!taskSpec.allowed_tools.includes("memory_write")) {
      violations.push("task intent does not allow memory write");
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
  const count = state.history.filter((item) => item.tool === action.tool).length;
  if (count >= 3) {
    findings.push(finding("Evidence Feedback", "heuristic", "require_approval", "tool frequency is unusually high", 20, { tool: action.tool, count: count + 1 }));
  }
  const assessment = assessAction(action, config);
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

function trustFindingsFor(action: AgentSentryAction, state: PolicyState): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const assessment = assessActionWithSensitiveAssets(action, []);
  const blockedTaint = taintFlowForAction(action, assessment, state);
  if (blockedTaint) {
    findings.push(finding("Intent Authorization", "deterministic", "block", "high-risk tool call requires trusted context, but taint profile blocks this sink", 100, {
      tool: action.tool,
      sink: blockedTaint.sink,
      taint: blockedTaint,
      aggregate_risk: state.aggregateRisk,
      tainted_sources: state.taintedSources.slice(-8),
    }));
  }
  return findings;
}

function taintRisk(action: AgentSentryAction, state: PolicyState, config: PluginConfig): number {
  let risk = 0;
  const assessment = assessAction(action, config);
  const argsText = safeStringify(action.args).toLowerCase();
  const blockedTaint = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (action.tool !== "memory_write" && config.policy.sensitiveAssets.some((asset) => asset && argsText.includes(asset.toLowerCase()))) risk += 45;
  if (blockedTaint) risk += Math.min(45, Math.max(20, Math.trunc(blockedTaint.confidence / 2)));
  return Math.min(risk, 80);
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
  const sink = sinkForAction(action, assessment);
  if (!sink) return null;
  const selected = trustLabelsForAction(action, state)
    .filter((label) => taintBlockedForSink(label, sink))
    .map((label) => ({ label, profile: taintProfileFromLabel(label)! }))
    .sort((left, right) => right.profile.confidence - left.profile.confidence)[0];
  if (!selected) return null;
  const flow = {
    label_id: selected.label.id,
    source: `${selected.label.source}:${selected.label.evidence?.path || selected.label.evidence?.toolName || selected.label.id}`,
    sink,
    blocked: true,
    confidence: selected.profile.confidence,
    reason: selected.profile.reasons.join("; ") || "taint profile blocks this sink",
    tags: selected.profile.tags,
  };
  rememberTaintFlow(state, flow);
  return flow;
}

function trustLabelsForAction(action: AgentSentryAction, state: PolicyState): TrustLabel[] {
  const labels: TrustLabel[] = [];
  collectActionTrustLabels(action.args, labels);
  const argsText = flattenText(action.args);
  const matched = matchExposure(argsText, state.exposures);
  if (matched?.exposure.label.trust_label) labels.push(matched.exposure.label.trust_label);
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
  } catch {
    failures.push("tool result source classification failed");
    source = sourceFromTool(typeof toolName === "string" ? toolName : "unknown_tool");
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

function manifestAllowsUnscopedRead(action: AgentSentryAction): boolean {
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!envelope) return false;
  const manifest = envelope.manifest;
  return !manifest.requiresExplicitAuthorization
    && !manifest.canExfiltrate
    && manifest.sideEffects.every((effect) => effect === "none" || effect === "file_read" || effect === "network_read");
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

function targetAllowed(target: string, allowedTargets: string[]): boolean {
  if (!allowedTargets.length) return true;
  const normalizedTarget = normalizeTarget(target);
  if (!normalizedTarget) return false;
  return allowedTargets.some((allowed) => targetMatches(normalizedTarget, allowed));
}

function targetMatches(target: string, allowed: string): boolean {
  const normalizedAllowed = normalizeTarget(allowed);
  if (!normalizedAllowed) return false;
  if (target === normalizedAllowed) return true;
  try {
    const targetUrl = new URL(target);
    const allowedUrl = new URL(normalizedAllowed);
    if (targetUrl.protocol !== allowedUrl.protocol) return false;
    if (targetUrl.protocol === "mock:") return target === normalizedAllowed;
    if (targetUrl.hostname !== allowedUrl.hostname) return false;
    const allowedPath = allowedUrl.pathname.replace(/\/$/, "") || "/";
    const targetPath = targetUrl.pathname.replace(/\/$/, "") || "/";
    return allowedPath === "/" || targetPath === allowedPath || targetPath.startsWith(`${allowedPath}/`);
  } catch {
    return target === normalizedAllowed;
  }
}

function normalizeTarget(value: string): string {
  const text = value.trim();
  if (!text) return "";
  try {
    const parsed = new URL(text);
    if (parsed.protocol === "mock:") return text.replace(/\/$/, "");
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    parsed.pathname = parsed.pathname.replace(/\/$/, "") || "/";
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return text.replace(/\/$/, "");
  }
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
  return { basis: "conservative", confidence: 0.7 };
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
