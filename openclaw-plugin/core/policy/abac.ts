import type { DetectionFinding } from "../detect.ts";
import { finding, taintBlockedForSink, taintProfileFromLabel, type RiskVector, type TaintSink, type TrustLabel } from "../trust.ts";
import type { TaskSpec } from "../task-spec/index.ts";
import type { ActionAssessment, PolicyActionInput } from "./action-assessment.ts";

export type DataFlowTaintFlow = {
  label_id: string;
  source: string;
  sink: TaintSink;
  blocked: boolean;
  confidence: number;
  reason: string;
  tags: string[];
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
    }));
  }

  return { findings, blockedFlow, isolatedBranchGate: false };
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
  };
}
