import type { PluginConfig } from "../config.ts";
import type { DetectionFinding } from "./detect.ts";
import type { AgentSentryAction } from "./policy.ts";
import type { ActionAssessment } from "./policy/action-assessment.ts";

export type DegradationLevel = 0 | 1 | 2 | 3 | 4;

export type RiskWindowEvent = {
  decision: "allow" | "ask" | "deny";
  risk_score: number;
  verdict: "pass" | "review" | "block";
  tool: string;
  at: string;
};

export type DynamicSecurityState = {
  events: RiskWindowEvent[];
  degradationLevel: DegradationLevel;
  consecutiveSafeActions: number;
  lastEscalatedAt: string | null;
  reasons: string[];
};

export function createDynamicSecurityState(): DynamicSecurityState {
  return {
    events: [],
    degradationLevel: 0,
    consecutiveSafeActions: 0,
    lastEscalatedAt: null,
    reasons: [],
  };
}

export function dynamicSecurityFindingsFor(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  state: DynamicSecurityState,
  config: PluginConfig,
): DetectionFinding[] {
  if (!config.dynamicSecurity.enabled) return [];
  const level = Math.min(state.degradationLevel, config.dynamicSecurity.maxDegradationLevel) as DegradationLevel;

  const facts = actionFacts(action, assessment);
  const entropy = entropyDrift(state, action.tool);
  const findings: DetectionFinding[] = [];
  if (entropy.drift && facts.sideEffect) {
    findings.push(finding(
      "require_approval",
      "会话动作分布发生明显漂移，新的副作用动作需要二次确认",
      45,
      { action_facts: facts, entropy_drift: entropy },
    ));
  }
  if (level >= 1 && facts.externalWrite) {
    findings.push(finding(
      "require_approval",
      "会话风险窗口处于升档状态，外部写入动作需要二次确认",
      42,
      { degradation_level: level, action_facts: facts, recent_reasons: state.reasons.slice(-4) },
    ));
  }
  if (level >= 2 && facts.persistence) {
    findings.push(finding(
      "require_approval",
      "会话风险窗口处于升档状态，持久化写入需要二次确认",
      50,
      { degradation_level: level, action_facts: facts, recent_reasons: state.reasons.slice(-4) },
    ));
  }
  if (level >= 3 && facts.execution) {
    findings.push(finding(
      assessment.dangerousCommand ? "block" : "require_approval",
      assessment.dangerousCommand
        ? "会话风险窗口处于高位，危险命令执行被阻断"
        : "会话风险窗口处于高位，命令执行需要二次确认",
      assessment.dangerousCommand ? 100 : 65,
      { degradation_level: level, action_facts: facts, recent_reasons: state.reasons.slice(-4) },
    ));
  }
  if (level >= 4 && facts.sideEffect) {
    findings.push(finding(
      "require_approval",
      "会话风险窗口处于最高档，非只读动作需要二次确认",
      75,
      { degradation_level: level, action_facts: facts, recent_reasons: state.reasons.slice(-4) },
    ));
  }
  return findings;
}

export function recordDynamicSecurityEvent(
  state: DynamicSecurityState,
  decision: "allow" | "ask" | "deny",
  riskScore: number,
  findings: DetectionFinding[],
  config: PluginConfig,
  tool = "unknown_tool",
): DynamicSecurityState {
  if (!config.dynamicSecurity.enabled) return state;
  const verdict = decision === "deny" || findings.some((item) => item.verdict === "block")
    ? "block"
    : decision === "ask" || findings.some((item) => item.verdict === "require_approval")
      ? "review"
      : "pass";
  const event: RiskWindowEvent = {
    decision,
    risk_score: Math.max(0, Math.trunc(riskScore)),
    verdict,
    tool,
    at: new Date().toISOString(),
  };
  state.events = [...state.events, event].slice(-config.dynamicSecurity.windowSize);

  const highRisk = event.risk_score >= config.dynamicSecurity.riskThreshold || event.verdict === "block";
  if (highRisk) {
    state.consecutiveSafeActions = 0;
    state.degradationLevel = Math.min(config.dynamicSecurity.maxDegradationLevel, state.degradationLevel + 1) as DegradationLevel;
    state.lastEscalatedAt = event.at;
    state.reasons = [
      ...state.reasons,
      strongestReason(findings) || `risk_score=${event.risk_score}`,
    ].slice(-8);
    return state;
  }

  if (event.verdict === "pass" && event.risk_score < config.detection.askThreshold) {
    state.consecutiveSafeActions += 1;
  } else {
    state.consecutiveSafeActions = 0;
  }

  if (state.degradationLevel > 0 && state.consecutiveSafeActions >= config.dynamicSecurity.recoverAfterSafeActions) {
    state.degradationLevel = Math.max(0, state.degradationLevel - 1) as DegradationLevel;
    state.consecutiveSafeActions = 0;
    if (state.degradationLevel === 0) state.reasons = [];
  }
  return state;
}

export function dynamicSecuritySnapshot(state: DynamicSecurityState): Record<string, unknown> {
  const total = state.events.length;
  const high = state.events.filter((event) => event.verdict === "block" || event.risk_score >= 70).length;
  const review = state.events.filter((event) => event.verdict === "review").length;
  const entropy = entropyDrift(state);
  return {
    degradation_level: state.degradationLevel,
    consecutive_safe_actions: state.consecutiveSafeActions,
    window_events: total,
    high_risk_events: high,
    review_events: review,
    entropy_drift: entropy,
    last_escalated_at: state.lastEscalatedAt,
    reasons: state.reasons.slice(-6),
  };
}

function entropyDrift(state: DynamicSecurityState, nextTool = ""): Record<string, unknown> {
  const tools = state.events.map((event) => event.tool).filter(Boolean);
  if (nextTool) tools.push(nextTool);
  const distinct = new Set(tools);
  if (tools.length < 6 || distinct.size < 4) {
    return { drift: false, score: 0, distinct_tools: distinct.size, window_tools: tools.length };
  }
  const counts = new Map<string, number>();
  for (const tool of tools) counts.set(tool, (counts.get(tool) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / tools.length;
    entropy -= probability * Math.log2(probability);
  }
  const maxEntropy = Math.log2(Math.min(tools.length, 8));
  const score = maxEntropy > 0 ? entropy / maxEntropy : 0;
  return {
    drift: score >= 0.72 && distinct.size >= 4,
    score: Number(score.toFixed(3)),
    distinct_tools: distinct.size,
    window_tools: tools.length,
  };
}

function actionFacts(action: AgentSentryAction, assessment: ActionAssessment): Record<string, boolean> {
  return {
    externalWrite: action.tool === "send_email" || (action.tool === "call_api" && assessment.externalSink),
    persistence: assessment.persistence || assessment.systemMutation || action.tool === "memory_write",
    execution: action.tool === "shell_exec" || assessment.dangerousCommand,
    sideEffect: action.tool === "write_file" || action.tool === "send_email" || action.tool === "call_api" || action.tool === "shell_exec" || action.tool === "memory_write",
    sensitive: assessment.sensitive,
  };
}

function strongestReason(findings: DetectionFinding[]): string {
  const sorted = [...findings].sort((left, right) => right.score - left.score);
  return sorted[0]?.reason || "";
}

function finding(verdict: "require_approval" | "block", reason: string, score: number, evidence: Record<string, unknown>): DetectionFinding {
  return {
    layer: "Runtime Governance",
    finding_type: "deterministic",
    verdict,
    reason,
    score,
    evidence,
  };
}
