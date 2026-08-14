import type { DetectionFinding } from "../detect.ts";
import { finding, taintBlockedForSink, taintProfileFromLabel, type RiskVector, type TaintSink, type TrustLabel } from "../trust.ts";
import type { TaskSpec } from "../task-spec/index.ts";
import type { ActionAssessment, PolicyActionInput } from "./action-assessment.ts";
import { interventionEvidence, type AttackClass } from "./intervention-gate.ts";

export type DataFlowTaintFlow = {
  label_id: string;
  source: string;
  sink: TaintSink;
  blocked: boolean;
  confidence: number;
  reason: string;
  tags: string[];
  confidentiality: "public" | "internal" | "secret";
};

export type DataFlowBranch = {
  id: string;
  source: string;
  status: "isolated" | "merged";
  integrity: "system-trusted" | "user-trusted" | "untrusted-external";
  confidentiality: "public" | "internal" | "user-private" | "tenant-secret";
  purpose: string;
  risk: number;
  confidence: number;
  provenanceIds: string[];
};

export type AbacDecisionInput = {
  action: PolicyActionInput;
  assessment: ActionAssessment;
  sink: TaintSink | null;
  labels: TrustLabel[];
  isolatedBranches: DataFlowBranch[];
  taskSpec: TaskSpec;
  aggregateRisk: RiskVector;
  taintedSources: string[];
};

export type AbacDecision = {
  findings: DetectionFinding[];
  blockedFlow: DataFlowTaintFlow | null;
  isolatedBranchGate: boolean;
};

export function evaluateAbacDataFlow(input: AbacDecisionInput): AbacDecision {
  const findings: DetectionFinding[] = [];
  const blockedFlow = input.sink ? blockedTaintFlow(input.labels, input.sink) : null;
  if (blockedFlow) {
    findings.push(finding("Intent Authorization", "deterministic", "block", "ABAC 数据流策略阻断：低信任或敏感标签不能流向该工具", 100, {
      tool: input.action.tool,
      sink: blockedFlow.sink,
      taint: blockedFlow,
      aggregate_risk: input.aggregateRisk,
      tainted_sources: input.taintedSources.slice(-8),
      ...blockedFlowInterventionEvidence(blockedFlow),
    }));
  }

  return { findings, blockedFlow, isolatedBranchGate: false };
}

function blockedFlowInterventionEvidence(flow: DataFlowTaintFlow): ReturnType<typeof interventionEvidence> {
  const attackClass = attackClassForTags(flow.tags);
  if (attackClass) {
    return interventionEvidence("confirmed_attack", {
      attack_class: attackClass,
      causal_certainty: "observed",
      confidence: Math.max(0.5, Math.min(1, flow.confidence / 100)),
    });
  }
  if (flow.confidentiality === "secret") {
    return interventionEvidence("safety_boundary", { causal_certainty: "observed" });
  }
  return interventionEvidence("risk_only");
}

function attackClassForTags(tags: string[]): AttackClass | null {
  if (tags.some((tag) => tag === "gateway_hijack" || tag === "skill_secret_exfiltration" || tag === "tool_hijack")) {
    return "tool_hijack";
  }
  if (tags.some((tag) => tag === "persistence_instruction" || tag === "memory_poisoning")) {
    return "persistence_abuse";
  }
  if (tags.some((tag) => tag === "prompt_injection"
    || tag === "hidden_html"
    || tag === "url_fragment_instruction"
    || tag === "pdf_hidden_text"
    || tag === "image_metadata_instruction")) {
    return "prompt_injection";
  }
  return null;
}

function blockedTaintFlow(labels: TrustLabel[], sink: TaintSink): DataFlowTaintFlow | null {
  const selected = labels
    .filter((label) => taintBlockedForSink(label, sink))
    .map((label) => ({ label, profile: taintProfileFromLabel(label)! }))
    .sort((left, right) => right.profile.confidence - left.profile.confidence)[0];
  if (!selected) return null;
  return {
    label_id: selected.label.id,
    source: `${selected.label.source}:${selected.label.evidence?.path || selected.label.evidence?.toolName || selected.label.id}`,
    sink,
    blocked: true,
    confidence: selected.profile.confidence,
    reason: selected.profile.reasons.join("; ") || "taint profile blocks this sink",
    tags: selected.profile.tags,
    confidentiality: selected.profile.confidentiality,
  };
}
