import { describe, expect, it } from "vitest";
import { decisionFromRisk, mergeDecision } from "../../core/judge/decision-merge.ts";

describe("monotonic security decision merge", () => {
  it.each([
    ["deny", "allow", "deny"],
    ["deny", "ask", "deny"],
    ["ask", "allow", "ask"],
    ["allow", "ask", "ask"],
    ["allow", "deny", "deny"],
  ] as const)("merges %s with %s as %s", (deterministic, additional, expected) => {
    expect(mergeDecision(deterministic, additional)).toBe(expected);
  });

  it("maps thresholds and findings to a tightening decision", () => {
    expect(decisionFromRisk({ hasBlock: false, hasApproval: true, riskScore: 1, askThreshold: 40, denyThreshold: 70 })).toBe("ask");
    expect(decisionFromRisk({ hasBlock: true, hasApproval: false, riskScore: 0, askThreshold: 40, denyThreshold: 70 })).toBe("deny");
  });
});
