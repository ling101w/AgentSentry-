import { describe, expect, it } from "vitest";
import type { DetectionFinding } from "../../core/detect.ts";
import {
  applyInterventionGate,
  interventionEvidence,
} from "../../core/policy/intervention-gate.ts";

function finding(
  verdict: DetectionFinding["verdict"],
  extraEvidence: Record<string, unknown> = {},
): DetectionFinding {
  return {
    layer: "Tool Boundary",
    finding_type: "deterministic",
    verdict,
    reason: "fixture",
    score: verdict === "block" ? 100 : 40,
    evidence: extraEvidence,
  };
}

describe("intervention gate", () => {
  it("preserves the existing decision in risk-based mode", () => {
    const result = applyInterventionGate({
      mode: "risk-based",
      rawDecision: "deny",
      findings: [finding("block")],
      preserveSafetyBoundaries: true,
    });
    expect(result).toMatchObject({ decision: "deny", raw_decision: "deny", overridden: false });
  });

  it("allows generic risk findings in evidence-gated mode", () => {
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
    });
  });

  it("denies observed confirmed attacks in evidence-gated mode", () => {
    const result = applyInterventionGate({
      mode: "evidence-gated",
      rawDecision: "allow",
      findings: [finding("block", interventionEvidence("confirmed_attack", {
        attack_class: "prompt_injection",
        causal_certainty: "observed",
      }))],
      preserveSafetyBoundaries: true,
    });
    expect(result).toMatchObject({
      decision: "deny",
      overridden: true,
      evidence_class: "confirmed_attack",
    });
  });
});
