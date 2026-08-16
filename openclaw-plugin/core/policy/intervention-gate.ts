import type { InterventionMode } from "../../config.ts";
import type { DetectionFinding } from "../detect.ts";

export type PolicyActionDecision = "allow" | "ask" | "deny";
export type InterventionEvidenceClass =
  | "risk_only"
  | "attack_signal"
  | "confirmed_attack"
  | "safety_boundary";
export type AttackClass =
  | "prompt_injection"
  | "exfiltration"
  | "tool_hijack"
  | "memory_poisoning"
  | "persistence_abuse"
  | "credential_access"
  | "unknown";
export type CausalCertainty = "none" | "inferred" | "observed";

export type InterventionEvidence = {
  evidence_class: InterventionEvidenceClass;
  attack_class?: AttackClass;
  causal_certainty: CausalCertainty;
  confidence: number;
};

export type InterventionGateResult = {
  mode: InterventionMode;
  decision: PolicyActionDecision;
  raw_decision: PolicyActionDecision;
  overridden: boolean;
  evidence_class: InterventionEvidenceClass;
  attack_classes: AttackClass[];
  causal_certainty: CausalCertainty;
  qualified_finding_count: number;
  risk_only_finding_count: number;
  safety_boundary_preserved: boolean;
  approval_cache_override?: boolean;
};

const MIN_ATTACK_SIGNAL_CONFIDENCE = 0.7;
const MIN_CONFIRMED_ATTACK_CONFIDENCE = 0.5;

const EVIDENCE_CLASS_RANK: Record<InterventionEvidenceClass, number> = {
  risk_only: 0,
  attack_signal: 1,
  confirmed_attack: 2,
  safety_boundary: 3,
};

const CAUSAL_CERTAINTY_RANK: Record<CausalCertainty, number> = {
  none: 0,
  inferred: 1,
  observed: 2,
};

export function interventionEvidence(
  evidenceClass: InterventionEvidenceClass,
  options: Partial<Omit<InterventionEvidence, "evidence_class">> = {},
): { intervention_evidence: InterventionEvidence } {
  return {
    intervention_evidence: {
      evidence_class: evidenceClass,
      causal_certainty: options.causal_certainty || "none",
      confidence: clampConfidence(options.confidence ?? defaultConfidence(evidenceClass)),
      ...(options.attack_class ? { attack_class: options.attack_class } : {}),
    },
  };
}

export function applyInterventionGate(input: {
  mode: InterventionMode;
  rawDecision: PolicyActionDecision;
  findings: DetectionFinding[];
  preserveSafetyBoundaries: boolean;
}): InterventionGateResult {
  const classified = input.findings.map((finding) => ({ finding, evidence: evidenceForFinding(finding) }));
  const active = classified.filter(({ finding }) => finding.verdict !== "pass");
  const attackSpecific = active.filter(({ evidence }) => qualifiesAttackEvidence(evidence));
  const safety = active.filter(({ evidence }) => evidence.evidence_class === "safety_boundary");
  const qualifiedSafety = input.preserveSafetyBoundaries ? safety : [];
  const observedConfirmed = attackSpecific.filter(({ finding, evidence }) =>
    evidence.evidence_class === "confirmed_attack"
    && evidence.causal_certainty === "observed"
    && finding.verdict === "block"
  );

  let decision = input.rawDecision;
  let safetyBoundaryPreserved = false;
  if (input.mode === "evidence-gated") {
    const safetyBlock = safety.some(({ finding }) => finding.verdict === "block");
    const safetyReview = safety.some(({ finding }) => finding.verdict === "require_approval");
    if (input.preserveSafetyBoundaries && safetyBlock) {
      decision = "deny";
      safetyBoundaryPreserved = true;
    } else if (input.preserveSafetyBoundaries && safetyReview) {
      decision = "ask";
      safetyBoundaryPreserved = true;
    } else if (observedConfirmed.length) {
      decision = "deny";
    } else if (attackSpecific.length) {
      decision = "ask";
    } else {
      decision = "allow";
    }
  }

  // Report the evidence that actually qualified for this gate.  A malformed
  // or below-threshold attack annotation remains auditable as risk-only, but
  // must not make an allow decision look like a confirmed attack.
  const qualified = [...attackSpecific, ...qualifiedSafety];
  const evidence = strongestEvidence(qualified.map((item) => item.evidence));
  const causalCertainty = attackSpecific.length
    ? strongestCausalCertainty(attackSpecific.map((item) => item.evidence.causal_certainty))
    : qualifiedSafety.length
      ? strongestCausalCertainty(qualifiedSafety.map((item) => item.evidence.causal_certainty))
      : "none";
  const attackClasses = Array.from(new Set(
    attackSpecific
      .map(({ evidence: item }) => item.attack_class)
      .filter((item): item is AttackClass => Boolean(item)),
  )).sort();

  return {
    mode: input.mode,
    decision,
    raw_decision: input.rawDecision,
    overridden: decision !== input.rawDecision,
    evidence_class: evidence.evidence_class,
    attack_classes: attackClasses,
    causal_certainty: causalCertainty,
    qualified_finding_count: qualified.length,
    risk_only_finding_count: active.length - qualified.length,
    safety_boundary_preserved: safetyBoundaryPreserved,
  };
}

function qualifiesAttackEvidence(evidence: InterventionEvidence): boolean {
  if (!evidence.attack_class || evidence.causal_certainty === "none") return false;
  if (evidence.evidence_class === "confirmed_attack") {
    return evidence.confidence >= MIN_CONFIRMED_ATTACK_CONFIDENCE;
  }
  if (evidence.evidence_class === "attack_signal") {
    return evidence.confidence >= MIN_ATTACK_SIGNAL_CONFIDENCE;
  }
  return false;
}

export function evidenceForFinding(finding: DetectionFinding): InterventionEvidence {
  const candidate = finding.evidence?.intervention_evidence;
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    return { evidence_class: "risk_only", causal_certainty: "none", confidence: 0 };
  }
  const value = candidate as Record<string, unknown>;
  const evidenceClass = isEvidenceClass(value.evidence_class) ? value.evidence_class : "risk_only";
  const causalCertainty = isCausalCertainty(value.causal_certainty) ? value.causal_certainty : "none";
  const attackClass = isAttackClass(value.attack_class) ? value.attack_class : undefined;
  return {
    evidence_class: evidenceClass,
    causal_certainty: causalCertainty,
    confidence: clampConfidence(typeof value.confidence === "number" ? value.confidence : 0),
    ...(attackClass ? { attack_class: attackClass } : {}),
  };
}

function strongestEvidence(items: InterventionEvidence[]): InterventionEvidence {
  return items.reduce<InterventionEvidence>((strongest, item) => {
    const classDifference = EVIDENCE_CLASS_RANK[item.evidence_class] - EVIDENCE_CLASS_RANK[strongest.evidence_class];
    if (classDifference > 0) return item;
    if (classDifference < 0) return strongest;
    const causalDifference = CAUSAL_CERTAINTY_RANK[item.causal_certainty] - CAUSAL_CERTAINTY_RANK[strongest.causal_certainty];
    if (causalDifference > 0) return item;
    return item.confidence > strongest.confidence ? item : strongest;
  }, { evidence_class: "risk_only", causal_certainty: "none", confidence: 0 });
}

function strongestCausalCertainty(items: CausalCertainty[]): CausalCertainty {
  return items.reduce<CausalCertainty>((strongest, item) =>
    CAUSAL_CERTAINTY_RANK[item] > CAUSAL_CERTAINTY_RANK[strongest] ? item : strongest
  , "none");
}

function defaultConfidence(evidenceClass: InterventionEvidenceClass): number {
  if (evidenceClass === "confirmed_attack" || evidenceClass === "safety_boundary") return 1;
  if (evidenceClass === "attack_signal") return 0.7;
  return 0;
}

function clampConfidence(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function isEvidenceClass(value: unknown): value is InterventionEvidenceClass {
  return value === "risk_only"
    || value === "attack_signal"
    || value === "confirmed_attack"
    || value === "safety_boundary";
}

function isAttackClass(value: unknown): value is AttackClass {
  return value === "prompt_injection"
    || value === "exfiltration"
    || value === "tool_hijack"
    || value === "memory_poisoning"
    || value === "persistence_abuse"
    || value === "credential_access"
    || value === "unknown";
}

function isCausalCertainty(value: unknown): value is CausalCertainty {
  return value === "none" || value === "inferred" || value === "observed";
}
