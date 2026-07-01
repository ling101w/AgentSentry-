import type { PluginConfig } from "../config.ts";
import type { DetectionFinding } from "./detect.ts";
import { clampText, safeStringify } from "./redact.ts";

export type AgentSentryAction = {
  tool: string;
  originalTool: string;
  args: Record<string, unknown>;
  reason: string;
};

export type TaskSpec = {
  task: string;
  allowed_tools: string[];
  forbidden_tools: string[];
  allowed_targets: string[];
  sensitive_assets: string[];
  output_policy: string;
};

export type Label = {
  source: string;
  integrity: "trusted" | "untrusted";
  confidentiality: "public" | "internal" | "secret";
  tainted: boolean;
};

export type PolicyState = {
  currentTask: string;
  taskSpec: TaskSpec;
  contaminated: boolean;
  foundationBlocked: boolean;
  foundationFindings: DetectionFinding[];
  history: Array<{
    tool: string;
    decision: "allow" | "ask" | "deny";
    risk_score: number;
  }>;
  toolResultLabels: Map<string, Label>;
  exposures: Array<{
    source: string;
    text: string;
    label: Label;
  }>;
  apiCallCounts: Map<string, number>;
};

export type PolicyDecision = {
  decision: "allow" | "ask" | "deny";
  risk_score: number;
  reasons: string[];
  violations: string[];
  deterministic_block: boolean;
  sentry_score: number;
  action: AgentSentryAction;
  task_spec: TaskSpec;
  findings: DetectionFinding[];
};

const TOOL_ALIASES: Array<[RegExp, string]> = [
  [/^(browser\.open|browser_open|open_browser|fetch_url|web\.open|read_webpage)$/i, "read_webpage"],
  [/(read|cat|get).*file|filesystem.*read/i, "read_file"],
  [/(write|create|edit).*file|filesystem.*write|apply_patch/i, "write_file"],
  [/(send).*email|mail/i, "send_email"],
  [/(fetch|request|http|api|curl|wget|browser)/i, "call_api"],
  [/(memory|remember).*write|write.*memory/i, "memory_write"],
  [/(memory|remember).*read|read.*memory/i, "memory_read"],
  [/(shell|command|exec|terminal|powershell|cmd)/i, "shell_exec"],
];

const HIGH_RISK_SINKS = new Set(["send_email", "write_file", "call_api", "shell_exec"]);
const SYSTEM_PATH_MARKERS = ["..", "~", "/etc", "\\windows", "startup", "system32"];
const EXPLICIT_NO_EMAIL = ["do not email", "don't email", "no email", "不要发", "别发", "不要发送", "不要给任何人发"];

export function createPolicyState(): PolicyState {
  const taskSpec = deriveTaskSpec("", []);

  return {
    currentTask: "",
    taskSpec,
    contaminated: false,
    foundationBlocked: false,
    foundationFindings: [],
    history: [],
    toolResultLabels: new Map(),
    exposures: [],
    apiCallCounts: new Map(),
  };
}

export function updateTaskSpec(state: PolicyState, messages: unknown, config: PluginConfig): void {
  const task = extractLatestUserText(messages);
  if (!task || task === state.currentTask) return;
  state.currentTask = task;
  state.taskSpec = deriveTaskSpec(task, config.policy.sensitiveAssets);
}

export function normalizeAction(toolName: string, params: Record<string, unknown>): AgentSentryAction {
  const tool = normalizeToolName(toolName);
  const args = normalizeArgs(tool, params);
  const reason = typeof params.reason === "string" ? params.reason : "";
  return { tool, originalTool: toolName, args, reason };
}

export function applyExposureTaint(action: AgentSentryAction, state: PolicyState, config: PluginConfig): {
  action: AgentSentryAction;
  findings: DetectionFinding[];
} {
  if (!config.detection.enabled || !config.policy.deterministic || !state.exposures.length || !HIGH_RISK_SINKS.has(action.tool)) {
    return { action, findings: [] };
  }

  const args = { ...action.args };
  const findings: DetectionFinding[] = [];
  for (const [key, value] of Object.entries(args)) {
    if (isLabeledValue(value)) continue;
    const text = flattenText(value);
    if (!text.trim()) continue;
    const match = matchExposure(text, state.exposures);
    let exposure = match?.exposure || null;
    let mode = match?.mode || "";
    if (!exposure && isSinkPayloadArg(action.tool, key)) {
      exposure = combinedExposure(state.exposures);
      mode = "run_exposure_default";
    }
    if (!exposure) continue;
    args[key] = { value, label: exposure.label };
    findings.push(finding("Execution Control", "deterministic", "block", "sink argument inherits untrusted run exposure", 100, {
      tool: action.tool,
      arg: key,
      source: exposure.source,
      match: mode,
    }));
  }

  if (!findings.length) return { action, findings };
  return { action: { ...action, args }, findings };
}

export function decideAction(
  action: AgentSentryAction,
  state: PolicyState,
  config: PluginConfig,
  incomingFindings: DetectionFinding[],
): PolicyDecision {
  const findings = [...incomingFindings];
  const reasons: string[] = [];
  const violations: string[] = [];
  const riskScoringEnabled = config.detection.enabled;
  let risk = riskScoringEnabled ? baseToolRisk(action.tool) : 0;

  const taskSpec = state.taskSpec;
  if (config.policy.deterministic && state.foundationBlocked && HIGH_RISK_SINKS.has(action.tool)) {
    findings.push(finding("Foundation", "deterministic", "block", "foundation scan found blocking workspace risk", 100, {
      blockedFindings: state.foundationFindings.filter((item) => item.verdict === "block").map((item) => item.reason),
    }));
    violations.push("foundation scan found blocking workspace risk");
  }

  if (config.policy.deterministic && (taskSpec.forbidden_tools.includes(action.tool) || !taskSpec.allowed_tools.includes(action.tool))) {
    violations.push(`tool ${action.tool} is outside TaskSpec`);
    findings.push(finding("Execution Control", "deterministic", "block", `tool ${action.tool} is outside TaskSpec`, 100, { tool: action.tool }));
  } else if (riskScoringEnabled && (taskSpec.forbidden_tools.includes(action.tool) || !taskSpec.allowed_tools.includes(action.tool))) {
    risk += 50;
  } else {
    reasons.push("tool is allowed by TaskSpec");
  }

  if (riskScoringEnabled) {
    const alignmentFindings = decisionAlignment(action, taskSpec);
    findings.push(...alignmentFindings);
  }

  const policyViolations = config.policy.deterministic ? deterministicViolations(action, taskSpec, state, config) : [];
  for (const violation of policyViolations) {
    violations.push(violation);
    findings.push(finding("Execution Control", "deterministic", "block", violation, 100, { tool: action.tool }));
  }
  for (const reason of findings
    .filter((item) => item.finding_type === "deterministic" && item.verdict === "block")
    .map((item) => item.reason)) {
    violations.push(reason);
  }

  if (riskScoringEnabled) {
    const trajectoryFindings = trajectoryFindingsFor(action, state, config);
    findings.push(...trajectoryFindings);
  }

  const sentryScore = riskScoringEnabled ? heuristicScore(findings) : 0;
  if (riskScoringEnabled) {
    risk += sentryScore;
    risk += taintRisk(action, state, config);
  }
  const deterministicBlock = violations.length > 0 || findings.some((item) => item.finding_type === "deterministic" && item.verdict === "block");
  if (deterministicBlock) risk = Math.max(risk + 35, 100);
  let decision: "allow" | "ask" | "deny" = "allow";
  if (deterministicBlock) {
    decision = "deny";
  } else if (riskScoringEnabled && findings.some((item) => item.verdict === "block")) {
    decision = "deny";
  } else if (riskScoringEnabled && risk >= config.detection.denyThreshold) {
    decision = "deny";
  } else if (riskScoringEnabled && (risk >= config.detection.askThreshold || findings.some((item) => item.verdict === "require_approval"))) {
    decision = "ask";
  }

  return {
    decision,
    risk_score: Math.min(risk, 150),
    reasons,
    violations: unique(violations),
    deterministic_block: deterministicBlock,
    sentry_score: sentryScore,
    action,
    task_spec: taskSpec,
    findings: dedupeFindings(findings),
  };
}

export function updateAfterMessage(state: PolicyState, findings: DetectionFinding[]): void {
  if (findings.some((finding) => finding.layer === "Input Sanitization" || finding.layer === "Cognition Protection")) {
    state.contaminated = true;
  }
}

export function updateAfterDecision(state: PolicyState, decision: PolicyDecision): void {
  state.history.push({
    tool: decision.action.tool,
    decision: decision.decision,
    risk_score: decision.risk_score,
  });
  if (state.history.length > 80) state.history = state.history.slice(-80);
  if (decision.findings.some((finding) => finding.layer === "Input Sanitization" || finding.layer === "Cognition Protection")) {
    state.contaminated = true;
  }
}

export function labelToolResult(toolCallId: string, result: unknown, state: PolicyState, config: PluginConfig): Label {
  if (!config.detection.enabled) {
    const label = trustedToolLabel(toolCallId);
    if (toolCallId) state.toolResultLabels.set(toolCallId, label);
    return label;
  }
  const text = safeStringify(result);
  const label: Label = {
    source: toolCallId ? `tool:${toolCallId}` : "tool:unknown",
    integrity: "untrusted",
    confidentiality: "public",
    tainted: true,
  };
  state.contaminated = true;
  if (config.policy.sensitiveAssets.some((asset) => asset && text.toLowerCase().includes(asset.toLowerCase()))) {
    label.confidentiality = "secret";
  }
  if (toolCallId) state.toolResultLabels.set(toolCallId, label);
  if (text.trim()) {
    state.exposures.push({ source: label.source, text, label: { ...label } });
    if (state.exposures.length > 40) state.exposures = state.exposures.slice(-40);
  }
  return label;
}

export function resultFindings(toolCallId: string, result: unknown, state: PolicyState, config: PluginConfig): DetectionFinding[] {
  if (!config.detection.enabled) {
    labelToolResult(toolCallId, result, state, config);
    return [];
  }
  const label = labelToolResult(toolCallId, result, state, config);
  if (!hasInjectionSignal(safeStringify(result))) return [];
  return [
    finding("Input Sanitization", "heuristic", "pass", "untrusted tool output contains prompt-injection indicators; taint is preserved for sink checks", 25, {
      source: label.source,
      preview: clampText(result, config.capture.previewChars),
    }),
  ];
}

export function mostSevereVerdict(findings: DetectionFinding[]): "pass" | "require_approval" | "block" {
  if (findings.some((item) => item.verdict === "block")) return "block";
  if (findings.some((item) => item.verdict === "require_approval")) return "require_approval";
  return "pass";
}

export function deriveTaskSpec(task: string, sensitiveAssets: string[]): TaskSpec {
  const lowered = task.toLowerCase();
  const allowed = ["read_webpage", "call_api"];
  const forbidden = ["read_file", "write_file", "send_email", "memory_write", "shell_exec"];
  let outputPolicy = "Only answer the user; do not exfiltrate data.";
  const explicitNoEmail = containsAny(lowered, EXPLICIT_NO_EMAIL);

  if (!explicitNoEmail && containsAny(lowered, ["email", "mail", "send to", "发邮件", "发送给"])) {
    allowed.push("send_email");
    removeItem(forbidden, "send_email");
    outputPolicy = "Email only approved recipients when explicitly requested.";
  }
  if (containsAny(lowered, ["write", "save", "report", "保存", "写入", "生成报告", "修改文件", "创建文件"])) {
    allowed.push("write_file");
    removeItem(forbidden, "write_file");
  }
  if (containsAny(lowered, ["file", "secret", "read", "读取文件", "打开文件"])) {
    allowed.push("read_file");
    removeItem(forbidden, "read_file");
  }
  if (containsAny(lowered, ["memory", "remember", "记住", "记忆"])) {
    allowed.push("memory_read", "memory_write");
    removeItem(forbidden, "memory_write");
  }
  if (containsAny(lowered, ["shell", "command", "terminal", "powershell", "运行命令", "执行命令"])) {
    allowed.push("shell_exec");
    removeItem(forbidden, "shell_exec");
  }
  if (containsAny(lowered, ["summarize", "总结"])) {
    allowed.push("read_webpage");
  }

  const explicitTargets = extractTargets(task);

  return {
    task,
    allowed_tools: unique(allowed),
    forbidden_tools: unique(forbidden.filter((tool) => !allowed.includes(tool))),
    allowed_targets: unique(explicitTargets.length ? explicitTargets : ["mock://benign", "mock://attack", "mock://polluted", "mock://rita"]),
    sensitive_assets: sensitiveAssets,
    output_policy: outputPolicy,
  };
}

function deterministicViolations(action: AgentSentryAction, taskSpec: TaskSpec, state: PolicyState, config: PluginConfig): string[] {
  const violations: string[] = [];
  if (action.tool === "read_webpage") {
    const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
    if (!targetAllowed(url, taskSpec.allowed_targets)) {
      violations.push(`target ${url || "<empty>"} is outside allowed_targets`);
    }
  }

  if (action.tool === "send_email") {
    const recipient = readFirstString(action.args, ["recipient", "to", "target", "email"]);
    const body = readFirstString(action.args, ["body", "content", "message", "text"]);
    if (recipient && config.policy.allowlistedRecipients.length && !config.policy.allowlistedRecipients.includes(recipient)) {
      violations.push(`recipient ${recipient} is not allowlisted`);
    }
    if (config.policy.sensitiveAssets.some((asset) => asset && body.toLowerCase().includes(asset.toLowerCase()))) {
      violations.push("body contains secret-tainted data");
    }
    if (!taskSpec.allowed_tools.includes("send_email")) {
      violations.push("task intent does not allow email");
    }
  }

  if (action.tool === "write_file") {
    const path = readFirstString(action.args, ["path", "file", "filename", "target"]).replace(/\\/g, "/").toLowerCase();
    const content = readFirstString(action.args, ["content", "body", "text", "patch"]);
    if (!path) violations.push("missing write path");
    if (SYSTEM_PATH_MARKERS.some((marker) => path.includes(marker))) violations.push("write path looks like a system or traversal path");
    if (config.policy.sensitiveAssets.some((asset) => asset && path.includes(asset.toLowerCase()))) violations.push("write path references sensitive asset");
    if (config.policy.restrictWritesToAllowedRoots && config.policy.allowedWriteRoots.length) {
      const root = path.split("/", 1)[0];
      if (!config.policy.allowedWriteRoots.includes(root)) violations.push(`write root ${root || "<empty>"} is not allowlisted`);
    }
    if (config.policy.sensitiveAssets.some((asset) => asset && content.toLowerCase().includes(asset.toLowerCase()))) {
      violations.push("content contains secret-tainted data");
    }
    if (!taskSpec.allowed_tools.includes("write_file")) {
      violations.push("task intent does not allow file write");
    }
  }

  if (action.tool === "read_file") {
    const path = readFirstString(action.args, ["path", "file", "filename", "target"]).replace(/\\/g, "/").toLowerCase();
    if (config.policy.sensitiveAssets.some((asset) => asset && path.includes(asset.toLowerCase()))) {
      violations.push("read path references sensitive asset");
    }
  }

  if (action.tool === "call_api") {
    const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
    const host = hostFromUrl(url);
    let apiTargetAllowed = true;
    if (!targetAllowed(url, taskSpec.allowed_targets)) {
      violations.push(`target ${url || "<empty>"} is outside allowed_targets`);
      apiTargetAllowed = false;
    }
    if (host) {
      if (config.policy.allowlistedApiHosts.length && !config.policy.allowlistedApiHosts.includes(host)) {
        violations.push(`api host ${host} is not allowlisted`);
      }
      if (apiTargetAllowed && (!config.policy.allowlistedApiHosts.length || config.policy.allowlistedApiHosts.includes(host))) {
        state.apiCallCounts.set(host, (state.apiCallCounts.get(host) || 0) + 1);
      }
      if ((state.apiCallCounts.get(host) || 0) > 10) violations.push("api rate exceeds configured limit");
    }
  }

  if (action.tool === "shell_exec") {
    const command = readFirstString(action.args, ["command", "cmd", "script", "input"]);
    if (command) violations.push("shell command requires explicit review");
  }

  if (config.policy.taintFeedback && state.contaminated && HIGH_RISK_SINKS.has(action.tool)) {
    violations.push("recent contaminated context tightens high-risk sink policy");
  }

  return unique(violations);
}

function decisionAlignment(action: AgentSentryAction, taskSpec: TaskSpec): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const loweredTask = taskSpec.task.toLowerCase();
  if (action.tool === "send_email" && containsAny(loweredTask, EXPLICIT_NO_EMAIL)) {
    findings.push(finding("Decision Alignment", "heuristic", "require_approval", "email action conflicts with explicit user constraint", 35, { tool: action.tool }));
  }
  if (HIGH_RISK_SINKS.has(action.tool) && !taskSpec.allowed_tools.includes(action.tool)) {
    findings.push(finding("Decision Alignment", "heuristic", "require_approval", "high-risk action deviates from task intent", 30, { tool: action.tool }));
  }
  return findings;
}

function trajectoryFindingsFor(action: AgentSentryAction, state: PolicyState, config: PluginConfig): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const count = state.history.filter((item) => item.tool === action.tool).length;
  if (count >= 3) {
    findings.push(finding("Sentry Trajectory", "heuristic", "require_approval", "tool frequency is unusually high", 20, { tool: action.tool, count: count + 1 }));
  }
  if (config.policy.taintFeedback && state.contaminated && HIGH_RISK_SINKS.has(action.tool)) {
    findings.push(finding("Sentry Trajectory", "heuristic", "require_approval", "recent contaminated context tightens high-risk sink policy", 20, { tool: action.tool }));
  }
  return findings;
}

function taintRisk(action: AgentSentryAction, state: PolicyState, config: PluginConfig): number {
  let risk = 0;
  const argsText = safeStringify(action.args).toLowerCase();
  if (config.policy.sensitiveAssets.some((asset) => asset && argsText.includes(asset.toLowerCase()))) risk += 45;
  if (config.policy.taintFeedback && state.contaminated && HIGH_RISK_SINKS.has(action.tool)) risk += 25;
  return Math.min(risk, 80);
}

function normalizeToolName(toolName: string): string {
  for (const [pattern, mapped] of TOOL_ALIASES) {
    if (pattern.test(toolName)) return mapped;
  }
  return toolName;
}

function normalizeArgs(tool: string, params: Record<string, unknown>): Record<string, unknown> {
  const args = { ...params };
  if (tool === "read_webpage" || tool === "call_api") {
    promote(args, "url", ["uri", "href", "target", "endpoint"]);
  }
  if (tool === "read_file" || tool === "write_file") {
    promote(args, "path", ["file", "filename", "target"]);
  }
  if (tool === "send_email") {
    promote(args, "recipient", ["to", "target", "email"]);
    promote(args, "body", ["content", "message", "text"]);
  }
  return args;
}

function promote(args: Record<string, unknown>, target: string, sources: string[]): void {
  if (args[target] !== undefined) return;
  for (const source of sources) {
    if (args[source] !== undefined) {
      args[target] = args[source];
      return;
    }
  }
}

function extractLatestUserText(messages: unknown): string {
  if (!Array.isArray(messages)) return "";
  for (let i = messages.length - 1; i >= 0; i--) {
    const message = messages[i] as Record<string, unknown>;
    if (message?.role !== "user") continue;
    return flattenText(message.content).trim();
  }
  return "";
}

function flattenText(value: unknown): string {
  if (isLabeledValue(value)) return flattenText(value.value);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(flattenText).join(" ");
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (typeof obj.text === "string") return obj.text;
    if (typeof obj.content === "string") return obj.content;
    return Object.values(obj).map(flattenText).join(" ");
  }
  return value === undefined || value === null ? "" : String(value);
}

function isLabeledValue(value: unknown): value is { value: unknown; label: Label } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const obj = value as Record<string, unknown>;
  const label = obj.label as Record<string, unknown> | undefined;
  return obj.value !== undefined && Boolean(label && typeof label === "object" && typeof label.integrity === "string");
}

function finding(
  layer: string,
  findingType: "deterministic" | "heuristic" | "learned",
  verdict: "pass" | "require_approval" | "block",
  reason: string,
  score: number,
  evidence: Record<string, unknown>,
): DetectionFinding {
  return { layer, finding_type: findingType, verdict, reason, score, evidence };
}

function trustedToolLabel(toolCallId: string): Label {
  return {
    source: toolCallId ? `tool:${toolCallId}` : "tool:unknown",
    integrity: "trusted",
    confidentiality: "public",
    tainted: false,
  };
}

function heuristicScore(findings: DetectionFinding[]): number {
  return Math.min(findings.filter((finding) => finding.finding_type !== "deterministic").reduce((total, finding) => total + finding.score, 0), 100);
}

function baseToolRisk(tool: string): number {
  return {
    read_file: 30,
    write_file: 35,
    send_email: 40,
    call_api: 20,
    memory_write: 25,
    memory_read: 10,
    read_webpage: 10,
    shell_exec: 45,
  }[tool] ?? 20;
}

function readFirstString(args: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string") return value;
  }
  return "";
}

function hostFromUrl(url: string): string {
  if (!url) return "";
  try {
    const parsed = new URL(url);
    if (parsed.protocol === "mock:") return "mock.local";
    return parsed.hostname;
  } catch {
    return "";
  }
}

function targetAllowed(target: string, allowedTargets: string[]): boolean {
  if (!allowedTargets.length) return true;
  const normalizedTarget = normalizeTarget(target);
  if (!normalizedTarget) return false;
  return allowedTargets.some((allowed) => targetMatches(normalizedTarget, allowed));
}

function targetMatches(target: string, allowed: string): boolean {
  const normalizedAllowed = normalizeTarget(allowed);
  if (!normalizedAllowed) return false;
  if (target === normalizedAllowed) return true;
  try {
    const targetUrl = new URL(target);
    const allowedUrl = new URL(normalizedAllowed);
    if (targetUrl.protocol !== allowedUrl.protocol) return false;
    if (targetUrl.protocol === "mock:") return target === normalizedAllowed;
    if (targetUrl.hostname !== allowedUrl.hostname) return false;
    const allowedPath = allowedUrl.pathname.replace(/\/$/, "") || "/";
    const targetPath = targetUrl.pathname.replace(/\/$/, "") || "/";
    return allowedPath === "/" || targetPath === allowedPath || targetPath.startsWith(`${allowedPath}/`);
  } catch {
    return target === normalizedAllowed;
  }
}

function normalizeTarget(value: string): string {
  const text = value.trim();
  if (!text) return "";
  try {
    const parsed = new URL(text);
    if (parsed.protocol === "mock:") return text.replace(/\/$/, "");
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    parsed.pathname = parsed.pathname.replace(/\/$/, "") || "/";
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return text.replace(/\/$/, "");
  }
}

function extractTargets(text: string): string[] {
  const matches = text.match(/\b(?:https?:\/\/\S+|mock:\/\/\S+)/g) || [];
  return matches.map(cleanTarget).filter(Boolean);
}

function cleanTarget(value: string): string {
  return value.replace(/[.,;:\])}>'"，。；：）】》”’]+$/g, "");
}

function hasInjectionSignal(text: string): boolean {
  text = textVariants(text).join("\n");
  return /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|commands?)|system.{0,40}prompt|developer.{0,40}prompt|exfiltrate|api[_ -]?key|token|secret|password|bypass\s+(policy|guardrail|safety|restriction)|系统提示|开发者提示|内部配置/i.test(text);
}

function textVariants(text: string): string[] {
  const normalized = canonicalText(text);
  return unique([normalized, ...decodedTextCandidates(normalized)].filter(Boolean)).slice(0, 12);
}

function canonicalText(text: string): string {
  return text.normalize("NFKC").replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00ad]/g, "");
}

function decodedTextCandidates(text: string): string[] {
  const tokens = text.match(/[A-Za-z0-9+/_=-]{16,}|(?:[0-9A-Fa-f]{2}){8,}/g) || [];
  const out: string[] = [];
  for (const token of tokens.slice(0, 24)) {
    if (token.length > 4096) continue;
    const b64 = decodeBase64Text(token);
    if (b64) out.push(b64);
    const hex = decodeHexText(token);
    if (hex) out.push(hex);
  }
  return out;
}

function decodeBase64Text(token: string): string {
  if (token.length < 16) return "";
  try {
    const normalized = token.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    return printableText(Buffer.from(padded, "base64").toString("utf8"));
  } catch {
    return "";
  }
}

function decodeHexText(token: string): string {
  if (token.length < 16 || token.length % 2) return "";
  if (!/^[0-9A-Fa-f]+$/.test(token)) return "";
  try {
    return printableText(Buffer.from(token, "hex").toString("utf8"));
  } catch {
    return "";
  }
}

function printableText(value: string): string {
  if (!value || value.length > 4096) return "";
  let printable = 0;
  for (const char of value) {
    if (/\s/.test(char) || char >= " ") printable += 1;
  }
  return printable / Math.max(value.length, 1) >= 0.85 ? canonicalText(value) : "";
}

function matchExposure(text: string, exposures: PolicyState["exposures"]): { exposure: PolicyState["exposures"][number]; mode: string } | null {
  const normalized = normalizeExposureText(text);
  if (!normalized) return null;
  for (const exposure of exposures) {
    const candidate = normalizeExposureText(exposure.text);
    if (!candidate) continue;
    if (normalized.includes(candidate) || candidate.includes(normalized)) return { exposure, mode: "substring" };
    if (Math.min(normalized.length, candidate.length) >= 32 && similarity(normalized.slice(0, 1200), candidate.slice(0, 1200)) >= 0.82) {
      return { exposure, mode: "fuzzy" };
    }
  }
  return null;
}

function combinedExposure(exposures: PolicyState["exposures"]): PolicyState["exposures"][number] {
  const sources = Array.from(new Set(exposures.map((item) => item.source))).join("+");
  const confidentiality = exposures.some((item) => item.label.confidentiality === "secret")
    ? "secret"
    : exposures.some((item) => item.label.confidentiality === "internal")
      ? "internal"
      : "public";
  return {
    source: sources,
    text: "",
    label: {
      source: sources,
      integrity: "untrusted",
      confidentiality,
      tainted: true,
    },
  };
}

function isSinkPayloadArg(tool: string, name: string): boolean {
  const payloadArgs: Record<string, Set<string>> = {
    send_email: new Set(["body", "content", "message", "text"]),
    write_file: new Set(["content", "body", "data", "text", "patch"]),
    call_api: new Set(["body", "payload", "data", "content"]),
  };
  return Boolean(payloadArgs[tool]?.has(name));
}

function normalizeExposureText(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}

function similarity(left: string, right: string): number {
  const leftTokens = new Set(left.split(/\s+/).filter(Boolean));
  const rightTokens = new Set(right.split(/\s+/).filter(Boolean));
  if (!leftTokens.size || !rightTokens.size) return 0;
  let intersection = 0;
  for (const token of leftTokens) {
    if (rightTokens.has(token)) intersection += 1;
  }
  return intersection / Math.max(leftTokens.size, rightTokens.size);
}

function containsAny(value: string, markers: string[]): boolean {
  return markers.some((marker) => value.includes(marker.toLowerCase()));
}

function removeItem(items: string[], item: string): void {
  const index = items.indexOf(item);
  if (index >= 0) items.splice(index, 1);
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}

function dedupeFindings(findings: DetectionFinding[]): DetectionFinding[] {
  const seen = new Set<string>();
  const out: DetectionFinding[] = [];
  for (const item of findings) {
    const key = `${item.layer}:${item.finding_type}:${item.verdict}:${item.reason}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}
