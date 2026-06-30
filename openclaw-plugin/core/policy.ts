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

export function decideAction(
  action: AgentSentryAction,
  state: PolicyState,
  config: PluginConfig,
  incomingFindings: DetectionFinding[],
): PolicyDecision {
  const findings = [...incomingFindings];
  const reasons: string[] = [];
  const violations: string[] = [];
  let risk = baseToolRisk(action.tool);

  const taskSpec = state.taskSpec;
  if (state.foundationBlocked && HIGH_RISK_SINKS.has(action.tool)) {
    findings.push(finding("Foundation", "deterministic", "block", "foundation scan found blocking workspace risk", 100, {
      blockedFindings: state.foundationFindings.filter((item) => item.verdict === "block").map((item) => item.reason),
    }));
    violations.push("foundation scan found blocking workspace risk");
  }

  if (config.policy.deterministic && (taskSpec.forbidden_tools.includes(action.tool) || !taskSpec.allowed_tools.includes(action.tool))) {
    violations.push(`tool ${action.tool} is outside TaskSpec`);
    findings.push(finding("Execution Control", "deterministic", "block", `tool ${action.tool} is outside TaskSpec`, 100, { tool: action.tool }));
  } else if (taskSpec.forbidden_tools.includes(action.tool) || !taskSpec.allowed_tools.includes(action.tool)) {
    risk += 50;
  } else {
    reasons.push("tool is allowed by TaskSpec");
  }

  const alignmentFindings = decisionAlignment(action, taskSpec);
  findings.push(...alignmentFindings);

  const policyViolations = config.policy.deterministic ? deterministicViolations(action, taskSpec, state, config) : [];
  for (const violation of policyViolations) {
    violations.push(violation);
    findings.push(finding("Execution Control", "deterministic", "block", violation, 100, { tool: action.tool }));
  }

  const trajectoryFindings = trajectoryFindingsFor(action, state, config);
  findings.push(...trajectoryFindings);

  const sentryScore = heuristicScore(findings);
  risk += sentryScore;
  risk += taintRisk(action, state, config);
  if (violations.length) risk += 35;

  const deterministicBlock = violations.length > 0 || findings.some((item) => item.finding_type === "deterministic" && item.verdict === "block");
  let decision: "allow" | "ask" | "deny" = "allow";
  if (deterministicBlock) {
    decision = "deny";
  } else if (findings.some((item) => item.verdict === "block")) {
    decision = "deny";
  } else if (risk >= config.detection.denyThreshold) {
    decision = "deny";
  } else if (risk >= config.detection.askThreshold || findings.some((item) => item.verdict === "require_approval")) {
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
  const text = safeStringify(result);
  const label: Label = {
    source: toolCallId ? `tool:${toolCallId}` : "tool:unknown",
    integrity: "trusted",
    confidentiality: "public",
    tainted: false,
  };
  if (hasInjectionSignal(text)) {
    label.integrity = "untrusted";
    label.tainted = true;
    state.contaminated = true;
  }
  if (config.policy.sensitiveAssets.some((asset) => asset && text.toLowerCase().includes(asset.toLowerCase()))) {
    label.confidentiality = "secret";
    label.tainted = true;
  }
  if (toolCallId) state.toolResultLabels.set(toolCallId, label);
  return label;
}

export function resultFindings(toolCallId: string, result: unknown, state: PolicyState, config: PluginConfig): DetectionFinding[] {
  const label = labelToolResult(toolCallId, result, state, config);
  if (label.integrity !== "untrusted") return [];
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

  return {
    task,
    allowed_tools: unique(allowed),
    forbidden_tools: unique(forbidden.filter((tool) => !allowed.includes(tool))),
    sensitive_assets: sensitiveAssets,
    output_policy: outputPolicy,
  };
}

function deterministicViolations(action: AgentSentryAction, taskSpec: TaskSpec, state: PolicyState, config: PluginConfig): string[] {
  const violations: string[] = [];
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
    if (host) {
      state.apiCallCounts.set(host, (state.apiCallCounts.get(host) || 0) + 1);
      if (config.policy.allowlistedApiHosts.length && !config.policy.allowlistedApiHosts.includes(host)) {
        violations.push(`api host ${host} is not allowlisted`);
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

function hasInjectionSignal(text: string): boolean {
  return /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|commands?)|system.{0,40}prompt|developer.{0,40}prompt|exfiltrate|api[_ -]?key|token|secret|password|bypass\s+(policy|guardrail|safety|restriction)|系统提示|开发者提示|内部配置/i.test(text);
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
