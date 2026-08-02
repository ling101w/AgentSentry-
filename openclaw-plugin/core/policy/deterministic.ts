import type { PluginConfig } from "../../config.ts";
import type { DetectionFinding } from "../detect.ts";
import { readFirstString } from "../adapters/openclaw-tools.ts";
import { checkCapability } from "../authorization/capability.ts";
import { matchAllowedWritePath } from "../security/path.ts";
import { hostFromUrl, targetAllowed } from "../security/url.ts";
import { analyzeTrustContent, sourceFromTool } from "../trust.ts";
import { reachableTaint } from "../taint/propagation.ts";
import { assessAction, isSensitivePathWithAssets, provenanceRiskForAction } from "./risk.ts";
import type { AgentSentryAction, PolicyEffect, PolicySnapshot, TaintFlow } from "./types.ts";
import { isAbsolute, resolve } from "node:path";

export type DeterministicResult = {
  findings: DetectionFinding[];
  violations: string[];
  effects: PolicyEffect[];
  taintFlow: TaintFlow | null;
};

export function deterministicGate(action: AgentSentryAction, state: PolicySnapshot, config: PluginConfig): DeterministicResult {
  if (!config.policy.deterministic) return { findings: [], violations: [], effects: [], taintFlow: null };
  const violations: string[] = [];
  const effects: PolicyEffect[] = [];
  const assessment = assessAction(action, config);
  const capability = checkCapability(action, state.taskSpec);
  if (!capability.allowed) {
    violations.push(capability.reason);
    if (action.tool === "send_email") violations.push("task intent does not allow email");
    if (action.tool === "memory_write") violations.push("task intent does not allow memory write");
    if (action.tool === "write_file") violations.push("task intent does not allow file write");
  }

  const directProvenance = state.provenanceBlocked ? provenanceRiskForAction(action, state) : null;
  if (directProvenance) violations.push("tool call directly references risky workspace item");

  const taint = config.policy.taintFeedback ? reachableTaint(action, state, config) : { flow: null, effects: [] };
  if (taint.flow) {
    violations.push(`ABAC blocked high-risk sink because taint provenance reaches ${taint.flow.sink}`);
    effects.push(...taint.effects);
  }

  const argsAnalysis = analyzeTrustContent(action.args, {
    source: sourceFromTool(action.tool),
    sourceId: action.originalTool,
    toolName: action.originalTool,
    previewChars: config.capture.previewChars,
  });
  if (taint.flow && argsAnalysis.label.confidentiality === "secret") violations.push("tool arguments carry secret-tainted data");
  if (argsAnalysis.findings.some((item) => item.verdict === "block" && item.finding_type === "deterministic")) {
    violations.push("tool arguments match deterministic trust-risk policy");
  }

  if (action.tool === "read_webpage" || action.tool === "call_api") {
    const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
    if (!state.taskSpec.allowed_targets.includes("*") && !targetAllowed(url, state.taskSpec.allowed_targets)) {
      violations.push(`target ${url || "<empty>"} is outside allowed_targets`);
    }
  }
  if (action.tool === "send_email") validateEmail(action, config, violations);
  if (action.tool === "write_file") validateWrite(action, assessment, config, violations);
  if (action.tool === "read_file") {
    const filePath = readFirstString(action.args, ["path", "file", "filename", "target"]);
    if (isSensitivePathWithAssets(filePath, config.policy.sensitiveAssets)) violations.push("read path references sensitive asset");
  }
  if (action.tool === "call_api") validateApi(action, state, config, violations, effects);
  if (action.tool === "shell_exec" && assessment.highRisk) violations.push("shell command requires explicit review");
  if (action.tool === "memory_write") validateMemoryWrite(action, config, violations);

  const uniqueViolations = unique(violations);
  const findings = uniqueViolations.map((reason) => finding(reason, {
    tool: action.tool,
    authorization_path: reason === capability.reason ? capability.graphPath : undefined,
    required_capability: reason === capability.reason ? capability.required : undefined,
  }));
  if (directProvenance) {
    findings.push(finding("tool call directly references a workspace item marked risky by provenance scan", directProvenance, "Context Provenance"));
  }
  if (taint.flow) {
    findings.push(finding("tainted value has a provenance path into a disallowed sink", { tool: action.tool, taint: taint.flow }));
  }
  return { findings: dedupe(findings), violations: uniqueViolations, effects, taintFlow: taint.flow };
}

function validateEmail(action: AgentSentryAction, config: PluginConfig, violations: string[]): void {
  const recipient = readFirstString(action.args, ["recipient", "to", "target", "email"]);
  const body = readFirstString(action.args, ["body", "content", "message", "text"]);
  if (recipient && config.policy.allowlistedRecipients.length && !config.policy.allowlistedRecipients.includes(recipient)) {
    violations.push(`recipient ${recipient} is not allowlisted`);
  }
  if (config.policy.sensitiveAssets.some((asset) => asset && body.toLowerCase().includes(asset.toLowerCase()))) {
    violations.push("body contains secret-tainted data");
  }
}

function validateWrite(action: AgentSentryAction, assessment: ReturnType<typeof assessAction>, config: PluginConfig, violations: string[]): void {
  const requestedPath = readFirstString(action.args, ["path", "file", "filename", "target"]);
  const normalizedPath = requestedPath.replace(/\\/g, "/").toLowerCase();
  const content = readFirstString(action.args, ["content", "body", "text", "patch"]);
  if (!requestedPath) violations.push("missing write path");
  if (assessment.systemMutation) violations.push("write path targets protected system path");
  if (config.policy.sensitiveAssets.some((asset) => asset && normalizedPath.includes(asset.toLowerCase()))) violations.push("write path references sensitive asset");
  if (config.policy.restrictWritesToAllowedRoots) {
    const allowedRoots = config.policy.allowedWriteRoots.map((root) => isAbsolute(root) ? root : resolve(process.cwd(), root));
    const boundary = matchAllowedWritePath(requestedPath, allowedRoots, process.cwd());
    if (!boundary.allowed) violations.push(boundary.reason || "write path is outside allowed roots");
  }
  if (config.policy.sensitiveAssets.some((asset) => asset && content.toLowerCase().includes(asset.toLowerCase()))) violations.push("content contains secret-tainted data");
  if (/(^|\/)(memory\.md|agents\.md|soul\.md|user\.md|openclaw\.json|skill\.md)$/i.test(normalizedPath) || /(^|\/)(?:cron\.d|systemd|startup|skills)(?:\/|$)/i.test(normalizedPath)) {
    violations.push("write path targets memory, configuration, startup, or skill surface");
  }
  const analysis = analyzeTrustContent(content, { source: normalizedPath.includes("skill") ? "skill" : "memory", path: normalizedPath, previewChars: config.capture.previewChars });
  if (analysis.findings.some((item) => item.verdict === "block")) violations.push("write content contains persistence or skill hijack instructions");
}

function validateApi(action: AgentSentryAction, state: PolicySnapshot, config: PluginConfig, violations: string[], effects: PolicyEffect[]): void {
  const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
  const host = hostFromUrl(url);
  const withinTask = state.taskSpec.allowed_targets.includes("*") || targetAllowed(url, state.taskSpec.allowed_targets);
  const hostAllowed = !config.policy.allowlistedApiHosts.length || config.policy.allowlistedApiHosts.includes(host);
  if (host && !hostAllowed) violations.push(`api host ${host} is not allowlisted`);
  if (host && withinTask && hostAllowed) {
    if ((state.apiCallCounts.get(host) || 0) >= 10) violations.push("api rate exceeds configured limit");
    effects.push({ type: "api.increment", host });
  }
  if (/[?&]gatewayURL\s*=\s*wss?:\/\//i.test(url) && !/[?&]gatewayURL\s*=\s*wss?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(url)) {
    violations.push("api call includes non-local Control UI gateway override");
  }
}

function validateMemoryWrite(action: AgentSentryAction, config: PluginConfig, violations: string[]): void {
  const content = readFirstString(action.args, ["content", "body", "text", "value"]);
  const analysis = analyzeTrustContent(content, { source: "memory", sourceId: "memory_write", previewChars: config.capture.previewChars });
  if (analysis.findings.some((item) => item.verdict === "block")) violations.push("memory write contains privileged persistent instruction");
}

function finding(reason: string, evidence: Record<string, unknown>, layer = "Tool Boundary"): DetectionFinding {
  return { layer, finding_type: "deterministic", verdict: "block", reason, score: 100, evidence };
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}

function dedupe(findings: DetectionFinding[]): DetectionFinding[] {
  const seen = new Set<string>();
  return findings.filter((item) => {
    const key = `${item.layer}:${item.reason}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
