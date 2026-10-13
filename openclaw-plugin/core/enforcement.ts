import type { EnforcementMode } from "../config.ts";
import type { SecurityDecision } from "./judge/decision-merge.ts";

export type EnforcementAction = "observe" | "allow" | "block" | "approval";

export function toolEnforcementAction(mode: EnforcementMode, decision: SecurityDecision): EnforcementAction {
  if (mode === "observe") return "observe";
  if (decision === "deny") return "block";
  if (decision === "ask") return "approval";
  return "allow";
}

export function decisionKind(decision: SecurityDecision): "allow" | "approval_required" | "hard_deny" {
  return decision === "deny" ? "hard_deny" : decision === "ask" ? "approval_required" : "allow";
}
