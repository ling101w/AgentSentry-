import type { DetectionFinding } from "../detect.ts";
import type { PersistentMemoryLabel } from "../memory-ifc.ts";
import { flattenText as flattenValueText, unique } from "./value-utils.ts";
import { safeStringify as redactSafeStringify } from "../redact.ts";
import { createHash } from "node:crypto";
import type { SemanticEvidenceBasis } from "../semantic-action-graph.ts";
import { publicProvenance, semanticClaimsForValue, type DataProvenance, type SemanticClaim } from "../taint/provenance-graph.ts";
import { resolveToolManifest, type ToolSecurityManifest } from "../tool-manifest.ts";
import { contentHash, matchesIndexedChunk, normalizeIndexedText } from "../taint/content-index.ts";
import { addRisk, createRiskVector, mergeRiskVectors, type RiskVector, type TrustLabel } from "../trust.ts";
import type { AgentSentryAction, IFCBranch, PolicyState } from "./contracts.ts";

export const TOOL_ALIASES: Array<[RegExp, string]> = [
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

export function mergeDataProvenance(current: DataProvenance[], additions: DataProvenance[]): DataProvenance[] {
  const ordered = new Map<string, DataProvenance>();
  for (const node of [...current, ...additions]) {
    ordered.delete(node.id);
    ordered.set(node.id, publicProvenance(node));
  }
  return [...ordered.values()];
}

export function rememberDataProvenance(state: PolicyState, additions: DataProvenance[]): void {
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

export function subjectScopesForAction(manifest: ToolSecurityManifest, action: AgentSentryAction): string[] {
  if (manifest.dataSubjects?.length === 1 && manifest.dataSubjects[0] === "caller") return ["caller"];
  const values = (manifest.subjectFields || []).flatMap((field) => readValuesAtField(action.args[field]));
  return unique(values.map((value) => createHash("sha256")
    .update(`agentsentry-subject-v1\u0000${value.normalize("NFKC").trim()}`, "utf8")
    .digest("base64url")
    .slice(0, 24)));
}

export function toolFrequencyKey(action: AgentSentryAction): string {
  return stableToolKey(action.originalTool || action.tool || "unknown_tool");
}

export function stableToolKey(value: string): string {
  return String(value || "unknown_tool")
    .normalize("NFKC")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    || "unknown_tool";
}

export function confidentialityRank(value: IFCBranch["confidentiality"]): number {
  return { public: 0, internal: 1, "user-private": 2, "tenant-secret": 3 }[value] ?? 0;
}

export function publicPersistentMemoryLabel(label: PersistentMemoryLabel): Record<string, unknown> {
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

export function inspectPolicyValue(value: unknown): string {
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

export function safeStringify(value: unknown): string {
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

export function flattenText(value: unknown): string {
  if (inspectPolicyValue(value)) return safeStringify(value);
  try {
    const flattened = flattenValueText(value);
    return typeof flattened === "string" ? flattened : safeStringify(flattened);
  } catch {
    return safeStringify(value);
  }
}

export function normalizePolicyAction(value: unknown): { action: AgentSentryAction; issue: string } {
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

export function normalizeFindingInput(value: unknown): { findings: DetectionFinding[]; invalidCount: number } {
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

export function isDetectionFinding(value: unknown): value is DetectionFinding {
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

export function normalizeToolName(toolName: string): string {
  const registered = resolveToolManifest(toolName);
  if (registered) return registered.manifest.toolId;
  for (const [pattern, mapped] of TOOL_ALIASES) {
    if (pattern.test(toolName)) return mapped;
  }
  return toolName;
}

export function readValuesAtField(value: unknown): string[] {
  if (typeof value === "string" && value.trim()) return [value.trim()];
  if (Array.isArray(value)) return value.flatMap(readValuesAtField);
  return [];
}

export function finding(
  layer: string,
  findingType: DetectionFinding["finding_type"],
  verdict: "pass" | "require_approval" | "block",
  reason: string,
  score: number,
  evidence: Record<string, unknown>,
): DetectionFinding {
  return { layer, finding_type: findingType, verdict, reason, score, evidence };
}

export function riskVectorFromFindings(findings: DetectionFinding[]): RiskVector {
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

export function rememberTrustLabel(state: PolicyState, label: TrustLabel): void {
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

export function isRiskVector(value: unknown): value is RiskVector {
  if (!value || typeof value !== "object") return false;
  return "prompt_injection" in value && "sensitive_data" in value && "tool_hijack" in value;
}

export function textVariants(text: string): string[] {
  const normalized = canonicalText(text);
  return unique([normalized, ...decodedTextCandidates(normalized)].filter(Boolean)).slice(0, 12);
}

export function canonicalText(text: string): string {
  return text.normalize("NFKC").replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00ad]/g, "");
}

export function decodedTextCandidates(text: string): string[] {
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

export function decodePercentText(text: string): string {
  if (!/%[0-9A-Fa-f]{2}/.test(text)) return "";
  try {
    return printableText(decodeURIComponent(text.replace(/\+/g, "%20")));
  } catch {
    return "";
  }
}

export function decodeBase64Text(token: string): string {
  if (token.length < 16) return "";
  try {
    const normalized = token.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    return printableText(Buffer.from(padded, "base64").toString("utf8"));
  } catch {
    return "";
  }
}

export function decodeHexText(token: string): string {
  if (token.length < 16 || token.length % 2) return "";
  if (!/^[0-9A-Fa-f]+$/.test(token)) return "";
  try {
    return printableText(Buffer.from(token, "hex").toString("utf8"));
  } catch {
    return "";
  }
}

export function printableText(value: string): string {
  if (!value || value.length > 4096) return "";
  let printable = 0;
  for (const char of value) {
    if (/\s/.test(char) || char >= " ") printable += 1;
  }
  return printable / Math.max(value.length, 1) >= 0.85 ? canonicalText(value) : "";
}

export function matchExposure(text: string, exposures: PolicyState["exposures"]): { exposure: PolicyState["exposures"][number]; mode: string } | null {
  const normalizedVariants = exposureTextVariants(text);
  if (!normalizedVariants.length) return null;
  const targetClaims = semanticClaimsForValue({ value: text });
  let inferred: { exposure: PolicyState["exposures"][number]; mode: string } | null = null;
  for (let exposureIndex = exposures.length - 1; exposureIndex >= 0; exposureIndex -= 1) {
    const exposure = exposures[exposureIndex];
    const candidateVariants = exposureTextVariants(exposure.text);
    if (exposure.contentIndex) {
      for (let variantIndex = 0; variantIndex < normalizedVariants.length; variantIndex++) {
        const normalized = normalizeIndexedText(normalizedVariants[variantIndex]);
        if (normalized.length >= 8 && contentHash(normalized) === exposure.contentIndex.normalizedHash) {
          return { exposure, mode: variantIndex > 0 ? "encoded_exact" : "exact" };
        }
        if (matchesIndexedChunk(normalized, exposure.contentIndex)) {
          if (!inferred || inferred.mode === "semantic_derivation") inferred = { exposure, mode: "fingerprint_chunk" };
        }
      }
    }
    for (let textIndex = 0; textIndex < normalizedVariants.length; textIndex += 1) {
      const normalized = normalizedVariants[textIndex];
      for (let candidateIndex = 0; candidateIndex < candidateVariants.length; candidateIndex += 1) {
        const candidate = candidateVariants[candidateIndex];
        const minLength = Math.min(normalized.length, candidate.length);
        const transformed = textIndex > 0 || candidateIndex > 0;
        if (minLength >= 8 && normalized === candidate) {
          if (exposure.contentIndex && exposure.contentIndex.normalizedLength > candidate.length) {
            inferred ??= { exposure, mode: "substring" };
            continue;
          }
          return { exposure, mode: transformed ? "encoded_exact" : "exact" };
        }
        if (minLength >= 24 && (normalized.includes(candidate) || candidate.includes(normalized))) {
          if (!inferred || inferred.mode === "semantic_derivation") inferred = { exposure, mode: transformed ? "encoded_substring" : "substring" };
        }
        if (minLength >= 32 && similarity(normalized.slice(0, 1200), candidate.slice(0, 1200)) >= 0.82) {
          if (!inferred) inferred = { exposure, mode: transformed ? "encoded_fuzzy" : "fuzzy" };
        }
      }
    }
    const semanticMatch = relatedSemanticSubject(text, exposure.text)
      ? matchSemanticClaims(targetClaims, exposure.semanticClaims || []) : "";
    if (semanticMatch && !inferred) inferred = { exposure, mode: semanticMatch };
  }
  return inferred;
}

export function relatedSemanticSubject(target: string, source: string): boolean {
  if (/(该员工|该用户|该客户|此人|这位|this employee|that employee|this user|their salary)/iu.test(target)) return true;
  const generic = new Set(["high", "income", "salary", "credential", "credentials", "private", "privileged", "material", "token", "secret", "password", "reference"]);
  const sourceTokens = new Set(source.toLowerCase().match(/[a-z0-9_@.-]{4,}/g)?.filter((token) => !generic.has(token)) || []);
  return (target.toLowerCase().match(/[a-z0-9_@.-]{4,}/g) || []).some((token) => !generic.has(token) && sourceTokens.has(token));
}

export function provenanceEvidenceForMatch(mode: string): { basis: SemanticEvidenceBasis; confidence: number } {
  if (mode === "exact") return { basis: "observed", confidence: 1 };
  if (mode === "encoded_exact") return { basis: "decoded", confidence: 0.98 };
  if (mode === "substring") return { basis: "conservative", confidence: 0.9 };
  if (mode === "encoded_substring") return { basis: "conservative", confidence: 0.86 };
  if (mode === "fuzzy") return { basis: "conservative", confidence: 0.82 };
  if (mode === "fingerprint_chunk") return { basis: "conservative", confidence: 0.9 };
  if (mode === "encoded_fuzzy") return { basis: "conservative", confidence: 0.78 };
  if (mode === "semantic_derivation") return { basis: "conservative", confidence: 0.72 };
  return { basis: "conservative", confidence: 0.7 };
}

export function matchSemanticClaims(targetClaims: SemanticClaim[], sourceClaims: SemanticClaim[]): "semantic_derivation" | "" {
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

export function normalizeExposureText(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}

export function exposureTextVariants(value: string): string[] {
  return unique(textVariants(value).map(normalizeExposureText).filter(Boolean));
}

export function similarity(left: string, right: string): number {
  const leftTokens = new Set(left.split(/\s+/).filter(Boolean));
  const rightTokens = new Set(right.split(/\s+/).filter(Boolean));
  if (!leftTokens.size || !rightTokens.size) return 0;
  let intersection = 0;
  for (const token of leftTokens) {
    if (rightTokens.has(token)) intersection += 1;
  }
  return intersection / Math.max(leftTokens.size, rightTokens.size);
}
