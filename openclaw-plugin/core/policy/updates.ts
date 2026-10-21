import { applyEffects } from "./state.ts";
import { PluginConfig } from "../../config.ts";
import type { DetectionFinding } from "../detect.ts";
import { dynamicSecuritySnapshot, recordDynamicSecurityEvent } from "../dynamic-security.ts";
import type { PersistentMemoryLabel } from "../memory-ifc.ts";
import { updateBehaviorProfile } from "./behavior-baseline.ts";
import { unique } from "./value-utils.ts";
import { activateSemanticIntent, markSemanticActionEnforcement, semanticActionGraphSnapshot } from "../semantic-action-graph.ts";
import { recordCapabilityUse, updateAuthorizationState } from "../task-spec/index.ts";
import { createRiskVector, mergeRiskVectors, minimumTrustLabel, type TrustLabel } from "../trust.ts";
import type { PolicyState, PolicyDecision } from "./contracts.ts";
import { normalizeFindingInput, finding, toolFrequencyKey, normalizeToolName, riskVectorFromFindings, safeStringify, publicPersistentMemoryLabel, normalizePolicyAction, inspectPolicyValue, isRiskVector, flattenText, rememberTrustLabel } from "./support.ts";

export function hydratePersistentMemoryLabels(state: PolicyState, labels: PersistentMemoryLabel[]): void {
  state.sessionRevision += 1;
  const byKey = new Map<string, PersistentMemoryLabel>();
  for (const label of [...state.persistentMemoryLabels, ...labels].filter(isPersistentMemoryLabel)) {
    byKey.set(`${label.key}:${label.content_sha256}`, label);
  }
  state.persistentMemoryLabels = [...byKey.values()].slice(-400);
}

export function updateTaskSpec(state: PolicyState, messages: unknown, config: PluginConfig): void {
  const task = extractLatestUserText(messages);
  if (task === null || task === state.currentTask) return;
  state.sessionRevision += 1;
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

export function updateAfterMessage(state: PolicyState, findings: DetectionFinding[]): void {
  state.sessionRevision += 1;
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
    state.sessionRevision += 1;
    state.history.push({ tool: "unknown_tool", decision: "deny", risk_score: 100 });
    if (state.history.length > 80) state.history = state.history.slice(-80);
    state.contaminated = true;
    state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, createRiskVector({ tool_hijack: 100, privilege: 100 }));
    return;
  }
  const effects = decision.effects;
  if (effects) {
    applyEffects(state, effects);
  } else {
    state.sessionRevision += 1;
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
  if (decision.decision === "allow") {
    updateBehaviorProfile(state, decision.action);
    if (["calendar_write", "email_read", "write_file", "remote_file_create"].includes(decision.action.tool)) {
      state.taskSpec = recordCapabilityUse(state.taskSpec, decision.action);
      state.authorizationState.taskSpec = state.taskSpec;
    }
  }
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
  state.sessionRevision += 1;

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
  // Approval callbacks may arrive after subsequent decisions and results.
  // Patch the live graph instead of resurrecting the evaluation's old graph.
  const graph = state.semanticActionGraph;
  markSemanticActionEnforcement(graph, decision.action_graph_node_id, {
    decision: decision.decision,
    status,
  });
  state.semanticActionGraph = structuredClone(graph);
  state.sessionRevision += 1;
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

function mergeFindingTrust(state: PolicyState, findings: DetectionFinding[]): void {
  state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, riskVectorFromFindings(findings));
  for (const item of findings) {
    const evidence = item.evidence || {};
    const label = evidence.trust_label;
    if (isTrustLabel(label)) rememberTrustLabel(state, label);
  }
}

function isTrustLabel(value: unknown): value is TrustLabel {
  return Boolean(value && typeof value === "object" && typeof (value as TrustLabel).source === "string" && typeof (value as TrustLabel).signature === "string");
}
