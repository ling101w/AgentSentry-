import type { PluginConfig } from "../../config.ts";
import type { DetectionFinding } from "../detect.ts";
import { flattenText, isControlArg, isLabeledValue } from "../adapters/openclaw-tools.ts";
import { taintBlockedForSink, taintProfileFromLabel } from "../trust.ts";
import { assessAction, sinkForAction } from "../policy/risk.ts";
import { graphEffectsForFlow } from "./graph.ts";
import type { AgentSentryAction, Label, PolicyEffect, PolicySnapshot, TaintFlow } from "../policy/types.ts";

export function propagateActionTaint(action: AgentSentryAction, state: PolicySnapshot, config: PluginConfig): {
  action: AgentSentryAction;
  findings: DetectionFinding[];
} {
  if (!config.detection.enabled || !config.policy.deterministic || !config.policy.taintFeedback || !state.exposures.length) {
    return { action, findings: [] };
  }
  const args = { ...action.args };
  let changed = false;
  for (const [arg, value] of Object.entries(args)) {
    if (isControlArg(arg) || isLabeledValue(value)) continue;
    const match = matchExposure(flattenText(value), state.exposures);
    if (!match) continue;
    args[arg] = {
      value,
      label: { ...match.exposure.label, influence: "matched" },
      provenance: { source_node: match.exposure.node_id, match: match.mode },
    };
    changed = true;
  }
  return { action: changed ? { ...action, args } : action, findings: [] };
}

export function reachableTaint(action: AgentSentryAction, state: PolicySnapshot, config: PluginConfig): {
  flow: TaintFlow | null;
  effects: PolicyEffect[];
} {
  const sink = sinkForAction(action, assessAction(action, config));
  if (!sink) return { flow: null, effects: [] };
  const candidates: Array<{ arg: string; label: Label; sourceNode: string }> = [];
  for (const [arg, value] of Object.entries(action.args)) {
    if (!isLabeledValue(value)) continue;
    const label = value.label;
    const profile = label.trust_label ? taintProfileFromLabel(label.trust_label) : label.taint_profile;
    const blocked = label.trust_label ? taintBlockedForSink(label.trust_label, sink) : Boolean(label.tainted || label.confidentiality === "secret");
    if (!blocked || !profile) continue;
    candidates.push({ arg, label, sourceNode: value.provenance?.source_node || sourceNodeForLabel(label) });
  }
  const selected = candidates.sort((left, right) => confidence(right.label) - confidence(left.label))[0];
  if (!selected) return { flow: null, effects: [] };
  const profile = selected.label.trust_label ? taintProfileFromLabel(selected.label.trust_label) : selected.label.taint_profile!;
  if (!profile) return { flow: null, effects: [] };
  const labelId = selected.label.trust_label?.id || selected.label.source;
  const flow: TaintFlow = {
    label_id: labelId,
    source: selected.label.source,
    sink,
    blocked: true,
    confidence: profile.confidence,
    reason: profile.reasons.join("; ") || "tainted value reaches a disallowed sink",
    tags: profile.tags,
    path: [],
  };
  const effects = graphEffectsForFlow({
    sourceNode: selected.sourceNode,
    source: selected.label.source,
    labelId,
    actionId: state.nextActionId,
    tool: action.tool,
    arg: selected.arg,
    flow,
  });
  return { flow: { ...flow, path: effects.find((item) => item.type === "taint.flow")?.flow.path || [] }, effects };
}

function matchExposure(text: string, exposures: PolicySnapshot["exposures"]): { exposure: PolicySnapshot["exposures"][number]; mode: string } | null {
  const normalized = normalizeText(text);
  if (!normalized) return null;
  for (let index = exposures.length - 1; index >= 0; index -= 1) {
    const exposure = exposures[index];
    const candidate = normalizeText(exposure.text);
    if (!candidate) continue;
    if (Math.min(normalized.length, candidate.length) >= 24 && (normalized.includes(candidate) || candidate.includes(normalized))) {
      return { exposure, mode: "substring" };
    }
    const anchors = provenanceAnchors(candidate);
    if (anchors.some((anchor) => normalized.includes(anchor))) return { exposure, mode: "shared_provenance_anchor" };
    if (tokenSimilarity(normalized.slice(0, 1600), candidate.slice(0, 1600)) >= 0.55) return { exposure, mode: "token_overlap" };
  }
  return null;
}

function provenanceAnchors(value: string): string[] {
  const matches = value.match(/(?:~?\/[a-z0-9._/-]{5,}|[a-z]:\\[a-z0-9._\\-]{5,}|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|https?:\/\/[^\s"'<>]+|\b(?:api[_-]?key|private[_-]?key|system[_ -]?prompt|openclaw\.json|id_rsa|id_ed25519)\b)/gi) || [];
  return Array.from(new Set(matches.map(normalizeText).filter((item) => item.length >= 6)));
}

function tokenSimilarity(left: string, right: string): number {
  const leftTokens = new Set(left.split(/[^a-z0-9_./~-]+/).filter((item) => item.length >= 4));
  const rightTokens = new Set(right.split(/[^a-z0-9_./~-]+/).filter((item) => item.length >= 4));
  if (leftTokens.size < 3 || rightTokens.size < 3) return 0;
  let intersection = 0;
  for (const token of leftTokens) if (rightTokens.has(token)) intersection += 1;
  return intersection / Math.min(leftTokens.size, rightTokens.size);
}

function sourceNodeForLabel(label: Label): string {
  return label.source.startsWith("tool:") ? `tool_result:${label.source.slice("tool:".length)}` : `tool_result:${label.source}`;
}

function confidence(label: Label): number {
  return label.taint_profile?.confidence || (label.confidentiality === "secret" ? 100 : label.tainted ? 80 : 0);
}

function normalizeText(value: string): string {
  return value.normalize("NFKC").toLowerCase().replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00ad]/g, "").replace(/\s+/g, " ").trim();
}
