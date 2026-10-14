import { PluginConfig } from "../../config.ts";
import type { DetectionFinding } from "../detect.ts";
import { memoryContentHash, type PersistentMemoryLabel } from "../memory-ifc.ts";
import { sourceForToolResult } from "./action-assessment.ts";
import { unique } from "./value-utils.ts";
import { clampText } from "../redact.ts";
import { completeSemanticAction, semanticActionResultContext } from "../semantic-action-graph.ts";
import { extractFieldProvenance, publicProvenance, semanticClaimsForValue, transformProvenance, type DataProvenance, type FieldProvenance, type SemanticClaim } from "../taint/provenance-graph.ts";
import { resolveToolManifest, type ToolSecurityManifest } from "../tool-manifest.ts";
import { analyzeTrustContent, createRiskVector, mergeRiskVectors, riskMax, sourceFromTool, taintProfileFromLabel } from "../trust.ts";
import type { Label, IFCBranch, PolicyState } from "./contracts.ts";
import { finding, normalizeToolName, safeStringify, subjectScopesForAction, rememberTrustLabel, mergeDataProvenance, rememberDataProvenance, confidentialityRank, inspectPolicyValue, textVariants } from "./support.ts";

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
  state.sessionRevision += 1;
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
      state.exposures.push({ source: fieldLabel.source, text: field.value, label: fieldLabel, provenanceId: field.id, semanticClaims: field.semanticClaims, contentIndex: field.contentIndex });
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
    state.sessionRevision += 1;
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
      contentFingerprint: field.contentFingerprint,
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
      contentFingerprint: field.contentFingerprint,
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

function trustedToolLabel(toolCallId: string): Label {
  return {
    source: toolCallId ? `tool:${toolCallId}` : "tool:unknown",
    integrity: "trusted",
    confidentiality: "public",
    tainted: false,
  };
}

function hasInjectionSignal(text: string): boolean {
  text = textVariants(text).join("\n");
  return /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|commands?)|system.{0,40}prompt|developer.{0,40}prompt|exfiltrate|api[_ -]?key|token|secret|password|bypass\s+(policy|guardrail|safety|restriction)|系统提示|开发者提示|内部配置/i.test(text);
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
