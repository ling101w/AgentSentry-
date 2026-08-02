import type { PluginConfig } from "../../config.ts";
import type { DetectionFinding } from "../detect.ts";
import { isLabeledValue } from "../adapters/openclaw-tools.ts";
import { behaviorAnomalyFindings } from "../behavior/baseline.ts";
import { riskMax, type TrustLabel } from "../trust.ts";
import { deterministicGate } from "./deterministic.ts";
import { assessAction, baseToolRisk, heuristicScore, riskVectorFromFindings } from "./risk.ts";
import type { AgentSentryAction, PolicyEffect, PolicyEvaluation, PolicySnapshot } from "./types.ts";

export function evaluate(
  snapshot: PolicySnapshot,
  action: AgentSentryAction,
  config: PluginConfig,
  incomingFindings: DetectionFinding[] = [],
): PolicyEvaluation {
  const riskEnabled = config.detection.enabled;
  const findings = riskEnabled ? [...incomingFindings] : [];
  const gate = deterministicGate(action, snapshot, config);
  findings.push(...gate.findings);
  if (riskEnabled) {
    findings.push(...trajectoryFindings(action, snapshot));
    findings.push(...behaviorAnomalyFindings(action, snapshot));
  }

  const violations = unique([
    ...gate.violations,
    ...findings.filter((item) => item.finding_type === "deterministic" && item.verdict === "block").map((item) => item.reason),
  ]);
  const deterministicBlock = violations.length > 0;
  const actionRisk = riskVectorFromFindings(findings);
  const assessment = assessAction(action, config);
  let risk = riskEnabled ? baseToolRisk(action.tool) : 0;
  if (riskEnabled && action.tool === "shell_exec" && !assessment.highRisk) risk = 8;
  if (riskEnabled) {
    risk += heuristicScore(findings);
    risk += Math.min(45, Math.trunc(riskMax(actionRisk) / 2));
    if (gate.taintFlow) risk += Math.min(45, Math.max(20, Math.trunc(gate.taintFlow.confidence / 2)));
  }
  if (deterministicBlock) risk = Math.max(risk + 35, 100);

  const ambiguous = !deterministicBlock && (
    findings.some((item) => item.finding_type !== "deterministic" && item.verdict !== "pass")
    || (riskEnabled && risk >= config.detection.askThreshold)
  );
  const deterministicDisposition: "allow" | "deny" | "ambiguous" = deterministicBlock
    ? "deny"
    : ambiguous
      ? "ambiguous"
      : "allow";

  let outcome: "allow" | "ask" | "deny" = "allow";
  if (deterministicBlock || (riskEnabled && findings.some((item) => item.verdict === "block")) || (riskEnabled && risk >= config.detection.denyThreshold)) {
    outcome = "deny";
  } else if (riskEnabled && (risk >= config.detection.askThreshold || findings.some((item) => item.verdict === "require_approval"))) {
    outcome = "ask";
  }
  const semanticResolution = findings
    .map((item) => item.evidence?.semanticResolution)
    .find((value) => value === "allow" || value === "ask" || value === "deny");
  if (!deterministicBlock && semanticResolution) outcome = semanticResolution;

  const riskScore = Math.min(risk, 150);
  const effects: PolicyEffect[] = [
    ...gate.effects,
    { type: "history.append", value: { tool: action.tool, decision: outcome, risk_score: riskScore } },
    { type: "risk.merge", value: actionRisk },
    { type: "action.advance" },
  ];
  if (outcome === "allow") effects.push({ type: "behavior.observe", action });
  if (findings.some((item) => item.layer === "Context Provenance" || item.layer === "State Integrity")) effects.push({ type: "state.contaminate" });
  for (const label of trustLabelsFromFindings(findings)) effects.push({ type: "trust.remember", label });

  const dedupedFindings = dedupeFindings(findings);
  const decision = {
    decision: outcome,
    risk_score: riskScore,
    reasons: gate.violations.length ? [] : ["action is contained by user-granted capabilities"],
    violations,
    deterministic_block: deterministicBlock,
    deterministic_disposition: deterministicDisposition,
    sentry_score: riskEnabled ? heuristicScore(dedupedFindings) : 0,
    risk_vector: actionRisk,
    trust_labels: reachableLabels(action),
    action,
    task_spec: snapshot.taskSpec,
    findings: dedupedFindings,
    effects,
  };
  return { decision, effects };
}

function trajectoryFindings(action: AgentSentryAction, state: PolicySnapshot): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const count = state.history.filter((item) => item.tool === action.tool).length;
  if (count >= 20) {
    findings.push({
      layer: "Evidence Feedback",
      finding_type: "heuristic",
      verdict: "require_approval",
      reason: "tool frequency is unusually high",
      score: 20,
      evidence: { tool: action.tool, count: count + 1 },
    });
  }
  const readOnlyTask = /summari[sz]e|总结|概括|查看|阅读|看看|分析/.test(state.currentTask.toLowerCase())
    && !/(发送|发邮件|email|mail|写入|保存|执行|运行|记住|memory|remember|shell|command)/i.test(state.currentTask);
  const lastRead = state.history.slice(-4).some((item) => ["read_webpage", "read_file", "call_api"].includes(item.tool));
  if (readOnlyTask && lastRead && ["send_email", "memory_write", "shell_exec", "write_file"].includes(action.tool)) {
    findings.push({
      layer: "Intent Authorization",
      finding_type: "deterministic",
      verdict: "block",
      reason: "dynamic intent tracking detected drift from read-only task to state-changing action",
      score: 100,
      evidence: { task: state.currentTask, tool: action.tool, recent_tools: state.history.slice(-4).map((item) => item.tool) },
    });
  }
  return findings;
}

function reachableLabels(action: AgentSentryAction): TrustLabel[] {
  const labels: TrustLabel[] = [];
  for (const value of Object.values(action.args)) {
    if (!isLabeledValue(value) || !value.label.trust_label) continue;
    if (!labels.some((item) => item.id === value.label.trust_label!.id)) labels.push(value.label.trust_label);
  }
  return labels.slice(-8);
}

function trustLabelsFromFindings(findings: DetectionFinding[]): TrustLabel[] {
  const labels: TrustLabel[] = [];
  for (const item of findings) {
    const label = item.evidence?.trust_label;
    if (!isTrustLabel(label) || labels.some((current) => current.id === label.id)) continue;
    labels.push(label);
  }
  return labels;
}

function isTrustLabel(value: unknown): value is TrustLabel {
  return Boolean(value && typeof value === "object" && typeof (value as TrustLabel).source === "string" && typeof (value as TrustLabel).signature === "string");
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}

function dedupeFindings(findings: DetectionFinding[]): DetectionFinding[] {
  const seen = new Set<string>();
  return findings.filter((item) => {
    const key = `${item.layer}:${item.finding_type}:${item.verdict}:${item.reason}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
