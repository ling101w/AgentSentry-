import { describe, expect, it } from "vitest";
import type { DetectionFinding } from "../../core/detect.ts";
import {
  applyInterventionGate,
  interventionEvidence,
} from "../../core/policy/intervention-gate.ts";

describe("evidence-gated intervention policy", () => {
  it("preserves the existing decision in risk-based mode", () => {
    const result = applyInterventionGate({
      mode: "risk-based",
      rawDecision: "deny",
      findings: [finding("block")],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({ decision: "deny", raw_decision: "deny", overridden: false });
  });

  it("allows and audits generic risk or authorization findings", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [finding("block")],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({
      decision: "allow",
      raw_decision: "deny",
      overridden: true,
      evidence_class: "risk_only",
      qualified_finding_count: 0,
      risk_only_finding_count: 1,
    });
  });

  it("does not count pass-only annotations as active attack evidence", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "allow",
      findings: [finding("pass", interventionEvidence("confirmed_attack", {
        attack_class: "prompt_injection",
        causal_certainty: "observed",
      }))],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({
      decision: "allow",
      evidence_class: "risk_only",
      attack_classes: [],
      causal_certainty: "none",
      qualified_finding_count: 0,
      risk_only_finding_count: 0,
    });
  });

  it("asks only after an attack-specific signal reaches a candidate sink", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [finding("require_approval", interventionEvidence("attack_signal", {
        attack_class: "prompt_injection",
        causal_certainty: "inferred",
        confidence: 0.8,
      }))],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({
      decision: "ask",
      evidence_class: "attack_signal",
      attack_classes: ["prompt_injection"],
      causal_certainty: "inferred",
    });
  });

  it("does not qualify an unclassified attack marker as intervention evidence", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [finding("block", interventionEvidence("attack_signal", {
        causal_certainty: "observed",
        confidence: 1,
      }))],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({
      decision: "allow",
      raw_decision: "deny",
      evidence_class: "risk_only",
      attack_classes: [],
      causal_certainty: "none",
      qualified_finding_count: 0,
      risk_only_finding_count: 1,
    });
  });

  it("does not qualify zero-confidence attack metadata", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [finding("block", interventionEvidence("confirmed_attack", {
        attack_class: "tool_hijack",
        causal_certainty: "observed",
        confidence: 0,
      }))],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({
      decision: "allow",
      evidence_class: "risk_only",
      attack_classes: [],
      causal_certainty: "none",
      qualified_finding_count: 0,
      risk_only_finding_count: 1,
    });
  });

  it("denies a confirmed attack with an observed causal sink link", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [finding("block", interventionEvidence("confirmed_attack", {
        attack_class: "exfiltration",
        causal_certainty: "observed",
      }))],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({
      decision: "deny",
      evidence_class: "confirmed_attack",
      attack_classes: ["exfiltration"],
      causal_certainty: "observed",
      overridden: false,
    });
  });

  it("keeps confirmed but non-observed attack evidence at ask", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [finding("block", interventionEvidence("confirmed_attack", {
        attack_class: "tool_hijack",
        causal_certainty: "inferred",
      }))],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({ decision: "ask", raw_decision: "deny", overridden: true });
  });

  it("preserves hard safety boundaries independently from attack attribution", () => {
    const evidence = interventionEvidence("safety_boundary", { causal_certainty: "observed" });
    const protectedResult = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [finding("block", evidence)],
      preserveSafetyBoundaries: true,
    });
    const literalAttackOnlyResult = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [finding("block", evidence)],
      preserveSafetyBoundaries: false,
    });

    expect(protectedResult).toMatchObject({ decision: "deny", safety_boundary_preserved: true });
    expect(literalAttackOnlyResult).toMatchObject({ decision: "allow", safety_boundary_preserved: false });
  });

  it("reports attack causality independently from a stronger safety-boundary finding", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [
        finding("block", interventionEvidence("safety_boundary", { causal_certainty: "observed" })),
        finding("require_approval", interventionEvidence("attack_signal", {
          attack_class: "prompt_injection",
          causal_certainty: "inferred",
          confidence: 0.8,
        })),
      ],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({
      decision: "deny",
      evidence_class: "safety_boundary",
      attack_classes: ["prompt_injection"],
      causal_certainty: "inferred",
    });
  });

  it("preserves an approval safety boundary even without a blocking finding", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [finding("require_approval", interventionEvidence("safety_boundary"))],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({
      decision: "ask",
      evidence_class: "safety_boundary",
      safety_boundary_preserved: true,
    });
  });

  it("orders multiple attack evidence classes by strength and clamps malformed confidence", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "allow",
      findings: [
        finding("require_approval", {
          intervention_evidence: {
            evidence_class: "confirmed_attack",
            attack_class: "tool_hijack",
            causal_certainty: "inferred",
            confidence: 1,
          },
        }),
        finding("require_approval", interventionEvidence("attack_signal", {
          attack_class: "prompt_injection",
          causal_certainty: "inferred",
        })),
      ],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({
      decision: "ask",
      evidence_class: "confirmed_attack",
      attack_classes: ["prompt_injection", "tool_hijack"],
      risk_only_finding_count: 0,
    });
  });

  it("treats malformed evidence payloads as risk-only", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "deny",
      findings: [
        finding("block", { intervention_evidence: [] }),
        finding("block", { intervention_evidence: { evidence_class: "unknown", confidence: Number.POSITIVE_INFINITY } }),
      ],
      preserveSafetyBoundaries: true,
    });

    expect(result).toMatchObject({
      decision: "allow",
      evidence_class: "risk_only",
      qualified_finding_count: 0,
      risk_only_finding_count: 2,
    });
  });
});

function finding(
  verdict: DetectionFinding["verdict"],
  evidence: Record<string, unknown> = {},
): DetectionFinding {
  return {
    layer: "fixture",
    finding_type: "deterministic",
    verdict,
    reason: "fixture",
    score: verdict === "block" ? 100 : 50,
    evidence,
  };
}
