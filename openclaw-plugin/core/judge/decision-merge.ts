export type SecurityDecision = "allow" | "ask" | "deny";

const DECISION_RANK: Record<SecurityDecision, number> = {
  allow: 0,
  ask: 1,
  deny: 2,
};

/** Security decisions are monotonic: later evidence may tighten a decision, never relax it. */
export function mergeDecision(
  deterministic: SecurityDecision,
  additional: SecurityDecision,
): SecurityDecision {
  return DECISION_RANK[additional] > DECISION_RANK[deterministic] ? additional : deterministic;
}

export function decisionFromRisk(input: {
  hasBlock: boolean;
  hasApproval: boolean;
  riskScore: number;
  askThreshold: number;
  denyThreshold: number;
}): SecurityDecision {
  if (input.hasBlock || input.riskScore >= input.denyThreshold) return "deny";
  if (input.hasApproval || input.riskScore >= input.askThreshold) return "ask";
  return "allow";
}
