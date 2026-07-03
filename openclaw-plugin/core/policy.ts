import type { PluginConfig } from "../config.ts";
import type { DetectionFinding } from "./detect.ts";
import { clampText, safeStringify } from "./redact.ts";
import {
  addRisk,
  analyzeTrustContent,
  createRiskVector,
  mergeRiskVectors,
  minimumTrustLabel,
  riskMax,
  sourceFromTool,
  taintBlockedForSink,
  taintProfileFromLabel,
  type RiskVector,
  type TaintProfile,
  type TaintSink,
  type TrustSource,
  type TrustLabel,
} from "./trust.ts";

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
  provenance_untrusted?: boolean;
  influence?: "none" | "matched" | "payload_default";
  trust_label?: TrustLabel;
  risk_vector?: RiskVector;
  tags?: string[];
  taint_profile?: TaintProfile;
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
  behaviorProfiles: Map<string, BehaviorProfile>;
  trustLabels: TrustLabel[];
  aggregateRisk: RiskVector;
  taintedSources: string[];
  taintFlows: Array<{
    label_id: string;
    source: string;
    sink: TaintSink;
    blocked: boolean;
    confidence: number;
    reason: string;
    tags: string[];
  }>;
};

type ActionClass = "read" | "write" | "external_sink" | "execution" | "memory" | "network" | "unknown";

type BehaviorProfile = {
  calls: number;
  hosts: string[];
  recipients: string[];
  pathRoots: string[];
  maxParamBytes: number;
  maxParamKeys: number;
};

type ActionAssessment = {
  class: ActionClass;
  highRisk: boolean;
  externalSink: boolean;
  sensitive: boolean;
  persistence: boolean;
  systemMutation: boolean;
  dangerousCommand: boolean;
  reasons: string[];
};

export type PolicyDecision = {
  decision: "allow" | "ask" | "deny";
  risk_score: number;
  reasons: string[];
  violations: string[];
  deterministic_block: boolean;
  sentry_score: number;
  risk_vector: RiskVector;
  trust_labels: TrustLabel[];
  action: AgentSentryAction;
  task_spec: TaskSpec;
  findings: DetectionFinding[];
};

const TOOL_ALIASES: Array<[RegExp, string]> = [
  [/^(browser\.open|browser_open|open_browser|fetch_url|web\.open|read_webpage)$/i, "read_webpage"],
  [/(read|open|parse).*(email|mail)|email.*read|mail.*read/i, "read_webpage"],
  [/(read|parse|summarize).*pdf|pdf.*(read|parse|summarize)/i, "read_webpage"],
  [/(analy[sz]e|read|parse).*(image|picture|photo|ocr)|image.*(ocr|read|analy[sz]e)/i, "read_webpage"],
  [/(read|cat|get).*file|filesystem.*read/i, "read_file"],
  [/(write|create|edit).*file|filesystem.*write|apply_patch/i, "write_file"],
  [/(send).*email|mail/i, "send_email"],
  [/(fetch|request|http|api|curl|wget|browser)/i, "call_api"],
  [/(webhook|hooks?[./_-]?wake|wake_hook)/i, "memory_write"],
  [/(memory|remember).*write|write.*memory/i, "memory_write"],
  [/(memory|remember).*read|read.*memory/i, "memory_read"],
  [/(shell|command|exec|terminal|powershell|cmd)/i, "shell_exec"],
];

const HIGH_RISK_SINKS = new Set(["send_email", "call_api", "shell_exec", "memory_write"]);
const SYSTEM_MUTATION_PATH_MARKERS = ["/etc", "/usr", "/bin", "/sbin", "/var/spool/cron", "/boot", "/root", "\\windows", "system32", "startup"];
const SENSITIVE_PATH_PATTERNS = [
  /(^|\/)\.env(?:\.|$)/i,
  /(^|\/)openclaw\.json$/i,
  /(^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)$/i,
  /(^|\/)(credentials|secrets?|private[_-]?key)(?:\.[a-z0-9]+)?$/i,
  /\/\.ssh\/(?!known_hosts$|authorized_keys$)/i,
  /\/\.aws\/credentials$/i,
  /\/\.kube\/config$/i,
  /\/etc\/shadow$/i,
  /\/etc\/gshadow$/i,
];
const SAFE_SYSTEM_READ_PATHS = [
  "/etc/os-release",
  "/etc/issue",
  "/etc/hostname",
  "/proc/cpuinfo",
  "/proc/meminfo",
  "/proc/loadavg",
  "/proc/uptime",
];
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
    behaviorProfiles: new Map(),
    trustLabels: [],
    aggregateRisk: createRiskVector(),
    taintedSources: [],
    taintFlows: [],
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
      const defaultExposure = combinedExposure(state.exposures);
      if (shouldDefaultPropagateExposure(defaultExposure)) {
        exposure = defaultExposure;
        mode = "run_exposure_default";
      }
    }
    if (!exposure) continue;
    const inheritedLabel: Label = {
      ...exposure.label,
      influence: mode === "run_exposure_default" ? "payload_default" : "matched",
    };
    args[key] = { value, label: inheritedLabel };
    findings.push(finding("Execution Control", "deterministic", "block", "sink argument inherits malicious or secret taint", 100, {
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
  const assessment = assessAction(action, config);
  if (riskScoringEnabled && action.tool === "shell_exec" && !assessment.highRisk) {
    risk = 8;
  }
  if (config.policy.deterministic && state.foundationBlocked && HIGH_RISK_SINKS.has(action.tool)) {
    findings.push(finding("Foundation", "deterministic", "block", "foundation scan found blocking workspace risk", 100, {
      blockedFindings: state.foundationFindings.filter((item) => item.verdict === "block").map((item) => item.reason),
    }));
    violations.push("foundation scan found blocking workspace risk");
  }

  const outsideTaskSpec = taskSpec.forbidden_tools.includes(action.tool) || !taskSpec.allowed_tools.includes(action.tool);
  if (config.policy.deterministic && outsideTaskSpec && shouldHardBlockTaskMismatch(action, assessment, state)) {
    violations.push(`tool ${action.tool} is outside TaskSpec`);
    findings.push(finding("Execution Control", "deterministic", "block", `tool ${action.tool} is outside TaskSpec`, 100, { tool: action.tool, assessment }));
  } else if (riskScoringEnabled && outsideTaskSpec) {
    risk += assessment.highRisk ? 40 : 12;
    findings.push(finding("Execution Control", "heuristic", assessment.highRisk ? "require_approval" : "pass", `tool ${action.tool} is outside TaskSpec`, assessment.highRisk ? 35 : 8, { tool: action.tool, assessment }));
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

    const behaviorFindings = behaviorAnomalyFindingsFor(action, state, config);
    findings.push(...behaviorFindings);

    const trustFindings = trustFindingsFor(action, state);
    findings.push(...trustFindings);
  }

  const actionRisk = riskVectorFromFindings(findings);
  const combinedRisk = mergeRiskVectors(state.aggregateRisk, actionRisk);
  const blockedTaintForRisk = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (riskScoringEnabled && blockedTaintForRisk) {
    risk += Math.min(35, Math.max(15, Math.trunc(blockedTaintForRisk.confidence / 3)));
  }
  if (riskScoringEnabled && (assessment.highRisk || isTrustSensitiveSink(action, assessment))) {
    risk += Math.min(45, Math.trunc(riskMax(combinedRisk) / 2));
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
    risk_vector: combinedRisk,
    trust_labels: state.trustLabels.slice(-8),
    action,
    task_spec: taskSpec,
    findings: dedupeFindings(findings),
  };
}

export function updateAfterMessage(state: PolicyState, findings: DetectionFinding[]): void {
  if (findings.some((finding) => finding.layer === "Input Sanitization" || finding.layer === "Cognition Protection")) {
    state.contaminated = true;
  }
  mergeFindingTrust(state, findings);
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
  if (decision.decision === "allow") updateBehaviorProfile(state, decision.action);
  state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, decision.risk_vector);
  mergeFindingTrust(state, decision.findings);
}

export function labelToolResult(toolCallId: string, result: unknown, state: PolicyState, config: PluginConfig, toolName = ""): Label {
  if (!config.detection.enabled) {
    const label = trustedToolLabel(toolCallId);
    if (toolCallId) state.toolResultLabels.set(toolCallId, label);
    return label;
  }
  const text = safeStringify(result);
  const source = toolName ? sourceForToolResult(toolName, result) : "tool_result";
  const analysis = analyzeTrustContent(result, {
    source,
    sourceId: toolCallId || toolName || "tool_result",
    toolName,
    previewChars: config.capture.previewChars,
  });
  const provenanceUntrusted = !toolName || ["external_web", "email_html", "pdf_text", "image_metadata", "webhook"].includes(source);
  const maliciousTaint = analysis.label.tainted || hasInjectionSignal(text) || riskMax(analysis.risk_vector) >= 50;
  const label: Label = {
    source: toolCallId ? `tool:${toolCallId}` : "tool:unknown",
    integrity: "untrusted",
    confidentiality: "public",
    tainted: false,
    provenance_untrusted: provenanceUntrusted,
    influence: "none",
    trust_label: analysis.label,
    risk_vector: analysis.risk_vector,
    tags: analysis.tags,
    taint_profile: taintProfileFromLabel(analysis.label) || undefined,
  };
  if (maliciousTaint) {
    label.integrity = "untrusted";
    label.tainted = true;
    state.contaminated = true;
  } else if (!provenanceUntrusted) {
    label.integrity = "trusted";
  }
  if (analysis.label.confidentiality === "secret" || config.policy.sensitiveAssets.some((asset) => asset && text.toLowerCase().includes(asset.toLowerCase()))) {
    label.confidentiality = "secret";
  }
  rememberTrustLabel(state, analysis.label);
  state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, analysis.risk_vector);
  if (toolCallId) state.toolResultLabels.set(toolCallId, label);
  if (label.tainted && text.trim()) {
    state.exposures.push({ source: label.source, text, label: { ...label } });
    if (state.exposures.length > 40) state.exposures = state.exposures.slice(-40);
  }
  return label;
}

export function resultFindings(toolCallId: string, result: unknown, state: PolicyState, config: PluginConfig, toolName = ""): DetectionFinding[] {
  if (!config.detection.enabled) {
    labelToolResult(toolCallId, result, state, config, toolName);
    return [];
  }
  const analysis = analyzeTrustContent(result, {
    source: toolName ? sourceForToolResult(toolName, result) : "tool_result",
    sourceId: toolCallId || toolName || "tool_result",
    toolName,
    previewChars: config.capture.previewChars,
  });
  const label = labelToolResult(toolCallId, result, state, config, toolName);
  const findings = [...analysis.findings];
  if (!findings.length && !hasInjectionSignal(safeStringify(result))) return [];
  return [
    ...findings,
    finding("Input Sanitization", "heuristic", "pass", "untrusted tool output contains prompt-injection indicators; taint is preserved for sink checks", 25, {
      source: label.source,
      preview: clampText(result, config.capture.previewChars),
      trust_label: label.trust_label || null,
      risk_vector: label.risk_vector || createRiskVector(),
      tags: label.tags || [],
      taint_profile: label.taint_profile || null,
    }),
  ];
}

export function policyTrustSnapshot(state: PolicyState): Record<string, unknown> {
  const labels = state.trustLabels.slice(-10);
  const lowest = minimumTrustLabel(labels);
  return {
    contaminated: state.contaminated,
    aggregate_risk: state.aggregateRisk,
    tainted_sources: state.taintedSources.slice(-12),
    taint_flows: state.taintFlows.slice(-12),
    lowest_trust: lowest
      ? {
        source: lowest.source,
        integrity: lowest.integrity,
        confidentiality: lowest.confidentiality,
        tainted: lowest.tainted,
      }
      : null,
    labels: labels.map((label) => ({
      id: label.id,
      source: label.source,
      integrity: label.integrity,
      confidentiality: label.confidentiality,
      tainted: label.tainted,
      tags: label.evidence?.tags || [],
      signed_at: label.signed_at,
    })),
  };
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

  if (!explicitNoEmail && containsAny(lowered, ["email", "mail", "send to", "send email", "发邮件", "发送给", "发给", "发送", "邮件", "邮箱"])) {
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
  if (containsAny(lowered, ["网页", "网站", "url", "http", "邮件", "外部内容", "pdf", "图片", "图像", "简历", "文档", "页面"])) {
    allowed.push("read_webpage", "call_api");
  }
  if (containsAny(lowered, [
    "memory",
    "remember",
    "preference",
    "experience",
    "knowledge base",
    "long-term note",
    "记住",
    "记忆",
    "长期经验",
    "经验库",
    "长期偏好",
    "普通偏好",
    "记录经验",
    "记录一条",
    "记录一个",
    "写入长期",
    "写入经验",
    "保存经验",
  ])) {
    allowed.push("memory_read", "memory_write");
    removeItem(forbidden, "memory_write");
  }
  if (containsAny(lowered, ["shell", "command", "terminal", "powershell", "运行命令", "执行命令"])) {
    allowed.push("shell_exec");
    removeItem(forbidden, "shell_exec");
  }
  if (containsAny(lowered, ["系统版本", "目录大小", "磁盘", "内存", "cpu", "uname", "du ", "df ", "os-release"])) {
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
    allowed_targets: unique(explicitTargets.length ? explicitTargets : ["mock://benign", "mock://attack", "mock://polluted", "mock://rita", "http://127.0.0.1:9", "http://127.0.0.1:8765/api/health", "https://example.com/"]),
    sensitive_assets: sensitiveAssets,
    output_policy: outputPolicy,
  };
}

function deterministicViolations(action: AgentSentryAction, taskSpec: TaskSpec, state: PolicyState, config: PluginConfig): string[] {
  const violations: string[] = [];
  const assessment = assessAction(action, config);
  const argsAnalysis = analyzeTrustContent(action.args, {
    source: sourceFromTool(action.tool),
    sourceId: action.originalTool,
    toolName: action.originalTool,
    previewChars: config.capture.previewChars,
  });
  if (action.tool === "read_webpage") {
    const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
    if (!targetAllowed(url, taskSpec.allowed_targets)) {
      violations.push(`target ${url || "<empty>"} is outside allowed_targets`);
    }
  }

  const blockedTaint = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (blockedTaint) {
    violations.push(`ABAC blocked high-risk sink because taint profile disallows flow to ${blockedTaint.sink}`);
  }
  if (isTrustSensitiveSink(action, assessment) && argsAnalysis.label.confidentiality === "secret") {
    violations.push("tool arguments carry secret-tainted data");
  }
  if (argsAnalysis.findings.some((finding) => finding.verdict === "block" && finding.finding_type === "deterministic")) {
    violations.push("tool arguments match deterministic trust-risk policy");
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
    if (path.includes("..")) violations.push("write path contains traversal");
    if (assessment.systemMutation) violations.push("write path targets protected system path");
    if (config.policy.sensitiveAssets.some((asset) => asset && path.includes(asset.toLowerCase()))) violations.push("write path references sensitive asset");
    if (config.policy.restrictWritesToAllowedRoots && config.policy.allowedWriteRoots.length) {
      const root = path.split("/", 1)[0];
      if (!config.policy.allowedWriteRoots.includes(root)) violations.push(`write root ${root || "<empty>"} is not allowlisted`);
    }
    if (config.policy.sensitiveAssets.some((asset) => asset && content.toLowerCase().includes(asset.toLowerCase()))) {
      violations.push("content contains secret-tainted data");
    }
    if (/(^|\/)(memory\.md|agents\.md|soul\.md|user\.md|openclaw\.json|skill\.md)$/i.test(path) || /(^|\/)(?:cron\.d|systemd|startup|skills)(?:\/|$)/i.test(path)) {
      violations.push("write path targets memory, configuration, startup, or skill surface");
    }
    const writeContentAnalysis = analyzeTrustContent(content, { source: path.includes("skill") ? "skill" : "memory", path, previewChars: config.capture.previewChars });
    if (writeContentAnalysis.findings.some((finding) => finding.verdict === "block")) {
      violations.push("write content contains persistence or skill hijack instructions");
    }
    if (!taskSpec.allowed_tools.includes("write_file") && assessment.highRisk) {
      violations.push("task intent does not allow file write");
    }
  }

  if (action.tool === "read_file") {
    const path = readFirstString(action.args, ["path", "file", "filename", "target"]).replace(/\\/g, "/").toLowerCase();
    if (isSensitivePath(path, config)) {
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
    if (/[?&]gatewayURL\s*=\s*wss?:\/\//i.test(url) && !/[?&]gatewayURL\s*=\s*wss?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(url)) {
      violations.push("api call includes non-local Control UI gateway override");
    }
  }

  if (action.tool === "shell_exec") {
    const command = readFirstString(action.args, ["command", "cmd", "script", "input"]);
    if (command && assessment.highRisk) violations.push("shell command requires explicit review");
  }

  if (action.tool === "memory_write") {
    const content = readFirstString(action.args, ["content", "body", "text", "value"]);
    const analysis = analyzeTrustContent(content, { source: "memory", sourceId: "memory_write", previewChars: config.capture.previewChars });
    if (analysis.findings.some((finding) => finding.verdict === "block")) {
      violations.push("memory write contains privileged persistent instruction");
    }
    if (!taskSpec.allowed_tools.includes("memory_write")) {
      violations.push("task intent does not allow memory write");
    }
  }

  return unique(violations);
}

function decisionAlignment(action: AgentSentryAction, taskSpec: TaskSpec): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const loweredTask = taskSpec.task.toLowerCase();
  const assessment = assessActionWithSensitiveAssets(action, taskSpec.sensitive_assets);
  if (action.tool === "send_email" && containsAny(loweredTask, EXPLICIT_NO_EMAIL)) {
    findings.push(finding("Decision Alignment", "heuristic", "require_approval", "email action conflicts with explicit user constraint", 35, { tool: action.tool }));
  }
  if ((assessment.highRisk || isTrustSensitiveSink(action, assessment)) && !taskSpec.allowed_tools.includes(action.tool)) {
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
  const assessment = assessAction(action, config);
  const blockedTaint = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (blockedTaint) {
    findings.push(finding("Sentry Trajectory", "heuristic", "require_approval", "taint profile tightens this high-risk sink", 20, {
      tool: action.tool,
      sink: blockedTaint.sink,
      taint: blockedTaint,
    }));
  }
  const readOnlyTask = /summari[sz]e|总结|概括|查看|阅读|看看|分析/.test(state.currentTask.toLowerCase())
    && !/(发送|发邮件|email|mail|写入|保存|执行|运行|记住|memory|remember|shell|command)/i.test(state.currentTask);
  const lastRead = state.history.slice(-4).some((item) => item.tool === "read_webpage" || item.tool === "read_file" || item.tool === "call_api");
  if (readOnlyTask && lastRead && isTrustSensitiveSink(action, assessment)) {
    findings.push(finding("Decision Alignment", "deterministic", "block", "dynamic intent tracking detected drift from read-only task to high-risk action", 100, {
      task: state.currentTask,
      tool: action.tool,
      recent_tools: state.history.slice(-4).map((item) => item.tool),
    }));
  }
  return findings;
}

function behaviorAnomalyFindingsFor(action: AgentSentryAction, state: PolicyState, config: PluginConfig): DetectionFinding[] {
  const profile = state.behaviorProfiles.get(action.tool);
  if (!profile || profile.calls < 2) return [];
  const current = behaviorSnapshot(action);
  const findings: DetectionFinding[] = [];
  const assessment = assessAction(action, config);
  if (current.host && profile.hosts.length && !profile.hosts.includes(current.host) && (action.tool === "call_api" || assessment.externalSink)) {
    findings.push(finding("Behavior Baseline", "learned", "require_approval", "tool target host deviates from learned session baseline", 35, {
      tool: action.tool,
      host: current.host,
      learned_hosts: profile.hosts.slice(-6),
    }));
  }
  if (current.recipient && profile.recipients.length && !profile.recipients.includes(current.recipient) && action.tool === "send_email") {
    findings.push(finding("Behavior Baseline", "learned", "require_approval", "email recipient deviates from learned session baseline", 35, {
      tool: action.tool,
      recipient: current.recipient,
      learned_recipients: profile.recipients.slice(-6),
    }));
  }
  if (current.pathRoot && profile.pathRoots.length && !profile.pathRoots.includes(current.pathRoot) && (action.tool === "read_file" || action.tool === "write_file")) {
    findings.push(finding("Behavior Baseline", "learned", "require_approval", "file path root deviates from learned session baseline", 25, {
      tool: action.tool,
      root: current.pathRoot,
      learned_roots: profile.pathRoots.slice(-6),
    }));
  }
  if (profile.maxParamBytes > 0 && current.paramBytes > Math.max(profile.maxParamBytes * 4, profile.maxParamBytes + 4096)) {
    findings.push(finding("Behavior Baseline", "learned", "require_approval", "tool parameter size is anomalous for this session", 25, {
      tool: action.tool,
      param_bytes: current.paramBytes,
      learned_max_param_bytes: profile.maxParamBytes,
    }));
  }
  if (profile.maxParamKeys > 0 && current.paramKeys > Math.max(profile.maxParamKeys * 3, profile.maxParamKeys + 8)) {
    findings.push(finding("Behavior Baseline", "learned", "require_approval", "tool parameter shape is anomalous for this session", 20, {
      tool: action.tool,
      param_keys: current.paramKeys,
      learned_max_param_keys: profile.maxParamKeys,
    }));
  }
  return findings;
}

function trustFindingsFor(action: AgentSentryAction, state: PolicyState): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const assessment = assessActionWithSensitiveAssets(action, []);
  const blockedTaint = taintFlowForAction(action, assessment, state);
  if (blockedTaint) {
    findings.push(finding("ABAC Session Policy", "deterministic", "block", "high-risk tool call requires trusted context, but taint profile blocks this sink", 100, {
      tool: action.tool,
      sink: blockedTaint.sink,
      taint: blockedTaint,
      aggregate_risk: state.aggregateRisk,
      tainted_sources: state.taintedSources.slice(-8),
    }));
  }
  const lowest = minimumTrustLabel(state.trustLabels);
  if (!lowest || !isTrustSensitiveSink(action, assessment)) return findings;
  if (lowest.confidentiality === "secret" && (action.tool === "send_email" || action.tool === "call_api" || action.tool === "shell_exec")) {
    findings.push(finding("ABAC Session Policy", "deterministic", "block", "secret-tainted context cannot flow into external sink", 100, {
      tool: action.tool,
      source: lowest.source,
      aggregate_risk: state.aggregateRisk,
    }));
  }
  return findings;
}

function taintRisk(action: AgentSentryAction, state: PolicyState, config: PluginConfig): number {
  let risk = 0;
  const assessment = assessAction(action, config);
  const argsText = safeStringify(action.args).toLowerCase();
  const blockedTaint = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (action.tool !== "memory_write" && config.policy.sensitiveAssets.some((asset) => asset && argsText.includes(asset.toLowerCase()))) risk += 45;
  if (blockedTaint) risk += Math.min(45, Math.max(20, Math.trunc(blockedTaint.confidence / 2)));
  else if (config.policy.taintFeedback && state.contaminated && isTrustSensitiveSink(action, assessment)) risk += 10;
  if (assessment.highRisk || isTrustSensitiveSink(action, assessment)) risk += Math.min(40, Math.trunc(riskMax(state.aggregateRisk) / 3));
  return Math.min(risk, 80);
}

function updateBehaviorProfile(state: PolicyState, action: AgentSentryAction): void {
  const snapshot = behaviorSnapshot(action);
  const existing = state.behaviorProfiles.get(action.tool) || {
    calls: 0,
    hosts: [],
    recipients: [],
    pathRoots: [],
    maxParamBytes: 0,
    maxParamKeys: 0,
  };
  existing.calls += 1;
  if (snapshot.host) pushCapped(existing.hosts, snapshot.host, 12);
  if (snapshot.recipient) pushCapped(existing.recipients, snapshot.recipient, 12);
  if (snapshot.pathRoot) pushCapped(existing.pathRoots, snapshot.pathRoot, 12);
  existing.maxParamBytes = Math.max(existing.maxParamBytes, snapshot.paramBytes);
  existing.maxParamKeys = Math.max(existing.maxParamKeys, snapshot.paramKeys);
  state.behaviorProfiles.set(action.tool, existing);
  if (state.behaviorProfiles.size > 24) {
    const first = state.behaviorProfiles.keys().next().value;
    if (first) state.behaviorProfiles.delete(first);
  }
}

function behaviorSnapshot(action: AgentSentryAction): {
  host: string;
  recipient: string;
  pathRoot: string;
  paramBytes: number;
  paramKeys: number;
} {
  const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
  const path = readFirstString(action.args, ["path", "file", "filename", "target"]);
  return {
    host: hostFromUrl(url),
    recipient: readFirstString(action.args, ["recipient", "to", "email", "target"]).toLowerCase(),
    pathRoot: rootFromPath(path),
    paramBytes: safeStringify(action.args).length,
    paramKeys: countKeys(action.args),
  };
}

function rootFromPath(path: string): string {
  const normalized = path.replace(/\\/g, "/").replace(/^\/+/, "");
  if (!normalized) return "";
  if (/^[a-z]:\//i.test(normalized)) return normalized.slice(0, 2).toLowerCase();
  if (path.startsWith("/")) return `/${normalized.split("/", 1)[0]}`;
  return normalized.split("/", 1)[0] || ".";
}

function countKeys(value: unknown): number {
  if (!value || typeof value !== "object") return 0;
  if (Array.isArray(value)) return value.reduce((total, item) => total + countKeys(item), 0);
  return Object.entries(value as Record<string, unknown>).reduce((total, [, item]) => total + 1 + countKeys(item), 0);
}

function pushCapped(items: string[], value: string, limit: number): void {
  if (!value || items.includes(value)) return;
  items.push(value);
  if (items.length > limit) items.splice(0, items.length - limit);
}

function assessAction(action: AgentSentryAction, config: PluginConfig): ActionAssessment {
  return assessActionWithSensitiveAssets(action, config.policy.sensitiveAssets);
}

function assessActionWithSensitiveAssets(action: AgentSentryAction, sensitiveAssets: string[]): ActionAssessment {
  const path = readFirstString(action.args, ["path", "file", "filename", "target"]).replace(/\\/g, "/");
  const command = readFirstString(action.args, ["command", "cmd", "script", "input"]);
  const argsText = safeStringify(action.args);
  const reasons: string[] = [];
  let actionClass: ActionClass = "unknown";
  let externalSink = false;
  let sensitive = false;
  let persistence = false;
  let systemMutation = false;
  let dangerousCommand = false;

  if (action.tool === "read_file" || action.tool === "read_webpage" || action.tool === "memory_read") actionClass = "read";
  if (action.tool === "write_file") actionClass = "write";
  if (action.tool === "send_email") actionClass = "external_sink";
  if (action.tool === "call_api") actionClass = "network";
  if (action.tool === "shell_exec") actionClass = "execution";
  if (action.tool === "memory_write") actionClass = "memory";

  if (action.tool === "send_email") {
    externalSink = true;
    reasons.push("email is an external sink");
  }
  if (action.tool === "call_api") {
    const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
    const host = hostFromUrl(url);
    externalSink = Boolean(host && !isLocalHost(host));
    if (externalSink) reasons.push(`network call targets external host ${host}`);
  }
  if (isSensitivePathWithAssets(path, sensitiveAssets) || hasSensitiveValue(argsText)) {
    sensitive = true;
    reasons.push("arguments reference sensitive asset");
  }
  if (path && isPersistencePath(path)) {
    persistence = true;
    reasons.push("path targets persistence surface");
  }
  if (action.tool === "memory_write") {
    persistence = true;
    reasons.push("memory write is persistent");
  }
  if (path && isSystemMutationPath(path) && !isSafeSystemReadPath(path)) {
    systemMutation = action.tool !== "read_file";
    if (systemMutation) reasons.push("path targets protected system location");
  }
  if (action.tool === "shell_exec" && command) {
    const shell = assessShellCommand(command);
    sensitive = sensitive || shell.sensitive;
    externalSink = externalSink || shell.externalSink;
    persistence = persistence || shell.persistence;
    systemMutation = systemMutation || shell.systemMutation;
    dangerousCommand = shell.dangerous;
    reasons.push(...shell.reasons);
  }

  const highRisk = externalSink || sensitive || persistence || systemMutation || dangerousCommand;
  return {
    class: actionClass,
    highRisk,
    externalSink,
    sensitive,
    persistence,
    systemMutation,
    dangerousCommand,
    reasons: unique(reasons),
  };
}

function shouldHardBlockTaskMismatch(action: AgentSentryAction, assessment: ActionAssessment, state: PolicyState): boolean {
  if (!assessment.highRisk && (action.tool === "read_file" || action.tool === "write_file" || action.tool === "call_api")) return false;
  if (action.tool === "send_email") return assessment.externalSink || state.contaminated;
  if (action.tool === "shell_exec") return assessment.highRisk;
  if (action.tool === "memory_write") return assessment.persistence;
  return assessment.highRisk;
}

function isTrustSensitiveSink(action: AgentSentryAction, assessment: ActionAssessment): boolean {
  if (action.tool === "send_email") return true;
  if (action.tool === "shell_exec") return assessment.highRisk;
  if (action.tool === "memory_write") return true;
  if (action.tool === "call_api") return assessment.externalSink;
  if (action.tool === "write_file") return assessment.persistence || assessment.systemMutation || assessment.sensitive;
  return false;
}

function sinkForAction(action: AgentSentryAction, assessment: ActionAssessment): TaintSink | null {
  if (action.tool === "send_email") return "send_email";
  if (action.tool === "call_api" && assessment.externalSink) return "call_api";
  if (action.tool === "shell_exec" && assessment.highRisk) return "shell_exec";
  if (action.tool === "memory_write") return "memory_write";
  if (action.tool === "read_file" && assessment.sensitive) return "sensitive_read";
  if (action.tool === "write_file") {
    if (assessment.persistence || assessment.systemMutation) return "config_write";
    if (assessment.sensitive) return "write_file";
  }
  return null;
}

function taintFlowForAction(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  state: PolicyState,
): PolicyState["taintFlows"][number] | null {
  const sink = sinkForAction(action, assessment);
  if (!sink) return null;
  const selected = state.trustLabels
    .filter((label) => taintBlockedForSink(label, sink))
    .map((label) => ({ label, profile: taintProfileFromLabel(label)! }))
    .sort((left, right) => right.profile.confidence - left.profile.confidence)[0];
  if (!selected) return null;
  const flow = {
    label_id: selected.label.id,
    source: `${selected.label.source}:${selected.label.evidence?.path || selected.label.evidence?.toolName || selected.label.id}`,
    sink,
    blocked: true,
    confidence: selected.profile.confidence,
    reason: selected.profile.reasons.join("; ") || "taint profile blocks this sink",
    tags: selected.profile.tags,
  };
  rememberTaintFlow(state, flow);
  return flow;
}

function rememberTaintFlow(state: PolicyState, flow: PolicyState["taintFlows"][number]): void {
  const key = `${flow.label_id}:${flow.sink}:${flow.blocked}`;
  if (!state.taintFlows.some((item) => `${item.label_id}:${item.sink}:${item.blocked}` === key)) {
    state.taintFlows.push(flow);
  }
  if (state.taintFlows.length > 80) state.taintFlows = state.taintFlows.slice(-80);
}

function isSensitivePath(path: string, config: PluginConfig): boolean {
  return isSensitivePathWithAssets(path, config.policy.sensitiveAssets);
}

function isSensitivePathWithAssets(path: string, sensitiveAssets: string[]): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  if (!normalized) return false;
  if (isSafeSystemReadPath(normalized)) return false;
  if (isDocumentationPath(normalized)) return false;
  if (SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(normalized))) return true;
  return sensitiveAssets.some((asset) => {
    const item = asset.trim().replace(/\\/g, "/").toLowerCase();
    if (!item) return false;
    return normalized === item || normalized.endsWith(`/${item}`) || normalized.includes(item);
  });
}

function isPersistencePath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  return /(^|\/)(memory\.md|agents\.md|soul\.md|user\.md|openclaw\.json|skill\.md)$/i.test(normalized)
    || /(^|\/)(cron\.d|systemd|startup|skills|launchagents|launchdaemons)(\/|$)/i.test(normalized)
    || normalized.includes("/.openclaw/");
}

function isSystemMutationPath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  if (isSafeSystemReadPath(normalized)) return false;
  return SYSTEM_MUTATION_PATH_MARKERS.some((marker) => normalized.includes(marker.toLowerCase()));
}

function isSafeSystemReadPath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  return SAFE_SYSTEM_READ_PATHS.includes(normalized);
}

function isDocumentationPath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  if (!/\.(?:md|markdown|txt|rst|adoc)$/i.test(normalized)) return false;
  return /(^|\/)(docs?|examples?|samples?)(\/|$)/i.test(normalized)
    || /(^|\/)(readme|security|changelog|license)(?:\.[a-z0-9]+)?$/i.test(normalized);
}

function hasSensitiveValue(text: string): boolean {
  return /-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----|\bsk-[a-zA-Z0-9_-]{16,}\b|\bgh[pousr]_[a-zA-Z0-9_]{20,}\b|\bbearer\s+[a-zA-Z0-9._-]{16,}\b/i.test(text);
}

function assessShellCommand(command: string): Pick<ActionAssessment, "externalSink" | "sensitive" | "persistence" | "systemMutation" | "dangerousCommand"> & { dangerous: boolean; reasons: string[] } {
  const lower = command.toLowerCase();
  const reasons: string[] = [];
  const safeRead = isLowRiskShellRead(command);
  const externalSink = /\b(curl|wget|scp|rsync|nc|ncat|socat)\b/i.test(command) && !safeRead;
  const sensitive = /(~\/\.ssh\/id_|\/\.ssh\/id_|\.env\b|openclaw\.json|\/etc\/shadow|\/\.aws\/credentials|\/\.kube\/config|secret|token|password|api[_-]?key)/i.test(command);
  const persistence = /\b(crontab|systemctl\s+enable|systemctl\s+edit|tee\s+.*(memory\.md|agents\.md|openclaw\.json)|>>?\s*.*(memory\.md|agents\.md|openclaw\.json|\/etc\/|cron\.d|systemd))\b/i.test(command);
  const systemMutation = !safeRead && /\b(sudo|chmod\s+(777|[0-7]*7[0-7]*)|chown|systemctl|service\s+(start|restart|enable)|mount|umount|iptables|ufw)\b/i.test(command);
  const destructive = /\brm\s+-rf\s+(\/|~|\.\.?)(\s|$)|\bdd\s+.*\bof=\/dev\/|\bmkfs\.|\bshutdown\b|\breboot\b|:\s*\(\s*\)\s*\{/i.test(command);
  const remoteExec = /\b(curl|wget)\b[\s\S]{0,160}\|\s*(bash|sh|zsh|python|node)\b/i.test(command);
  if (externalSink) reasons.push("command uses network transfer");
  if (sensitive) reasons.push("command references sensitive assets");
  if (persistence) reasons.push("command modifies persistence surface");
  if (systemMutation) reasons.push("command mutates system state");
  if (destructive) reasons.push("command is destructive");
  if (remoteExec) reasons.push("command downloads and executes remote code");
  return {
    externalSink,
    sensitive,
    persistence,
    systemMutation,
    dangerousCommand: destructive || remoteExec,
    dangerous: destructive || remoteExec,
    reasons: unique(reasons),
  };
}

function sourceForToolResult(toolName: string, result: unknown): TrustSource {
  const lower = toolName.toLowerCase();
  if (lower === "call_api" || /\b(api|http|fetch|request|curl|wget)\b/.test(lower)) {
    const url = extractResultUrl(result);
    return url && isLocalHost(hostFromUrl(url)) ? "tool_result" : "external_web";
  }
  if (/read_webpage|browser|web|url|pdf|image|ocr|photo/.test(lower)) return sourceFromTool(toolName);
  if (/read_file|filesystem.*read/.test(lower)) return "workspace";
  if (/memory.*read/.test(lower)) return "memory";
  return "tool_result";
}

function extractResultUrl(result: unknown): string {
  if (!result || typeof result !== "object") return "";
  const obj = result as Record<string, unknown>;
  const direct = readFirstString(obj, ["url", "href", "endpoint", "target"]);
  if (direct) return direct;
  const output = obj.output;
  if (output && typeof output === "object") {
    return readFirstString(output as Record<string, unknown>, ["url", "href", "endpoint", "target"]);
  }
  return "";
}

function isLowRiskShellRead(command: string): boolean {
  const trimmed = command.trim();
  const safePatterns = [
    /^(pwd|whoami|id|hostname|uname\s+-a|date)$/i,
    /^(ls|find|du|df)(\s+[-\w./~*]+)*$/i,
    /^(cat|head|tail)\s+\/etc\/(os-release|issue|hostname)$/i,
    /^(cat|head|tail)\s+\/proc\/(cpuinfo|meminfo|loadavg|uptime)$/i,
    /^stat\s+[-\w./~*]+$/i,
    /^wc\s+[-\w\s./~*]+$/i,
  ];
  return safePatterns.some((pattern) => pattern.test(trimmed));
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
  return Math.min(
    findings
      .filter((finding) => finding.finding_type !== "deterministic" && finding.verdict !== "pass")
      .reduce((total, finding) => total + finding.score, 0),
    100,
  );
}

function baseToolRisk(tool: string): number {
  return {
    read_file: 18,
    write_file: 22,
    send_email: 25,
    call_api: 20,
    memory_write: 25,
    memory_read: 10,
    read_webpage: 10,
    shell_exec: 25,
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
    return parsed.hostname;
  } catch {
    return "";
  }
}

function isLocalHost(host: string): boolean {
  const normalized = host.toLowerCase();
  return normalized === "localhost"
    || normalized === "127.0.0.1"
    || normalized === "::1"
    || normalized === "[::1]"
    || normalized.endsWith(".localhost");
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

function mergeFindingTrust(state: PolicyState, findings: DetectionFinding[]): void {
  state.aggregateRisk = mergeRiskVectors(state.aggregateRisk, riskVectorFromFindings(findings));
  for (const item of findings) {
    const evidence = item.evidence || {};
    const label = evidence.trust_label;
    if (isTrustLabel(label)) rememberTrustLabel(state, label);
  }
}

function riskVectorFromFindings(findings: DetectionFinding[]): RiskVector {
  let vector = createRiskVector();
  for (const item of findings) {
    const evidence = item.evidence || {};
    const riskVector = evidence.risk_vector;
    if (isRiskVector(riskVector)) vector = mergeRiskVectors(vector, riskVector);
    if (item.layer === "Cognition Protection") vector = addRisk(vector, createRiskVector({ persistence: item.score }));
    if (item.layer === "Input Sanitization") vector = addRisk(vector, createRiskVector({ prompt_injection: item.score }));
    if (item.layer === "System Preflight" || item.layer === "Runtime Isolation") vector = addRisk(vector, createRiskVector({ privilege: item.score }));
    if (item.layer === "Foundation") vector = addRisk(vector, createRiskVector({ supply_chain: item.score }));
  }
  return vector;
}

function rememberTrustLabel(state: PolicyState, label: TrustLabel): void {
  if (!state.trustLabels.some((item) => item.id === label.id)) {
    state.trustLabels.push(label);
    if (state.trustLabels.length > 80) state.trustLabels = state.trustLabels.slice(-80);
  }
  if (label.tainted) {
    const source = `${label.source}:${label.evidence?.path || label.evidence?.toolName || label.id}`;
    if (!state.taintedSources.includes(source)) state.taintedSources.push(source);
    if (state.taintedSources.length > 80) state.taintedSources = state.taintedSources.slice(-80);
    state.contaminated = true;
  }
}

function isTrustLabel(value: unknown): value is TrustLabel {
  return Boolean(value && typeof value === "object" && typeof (value as TrustLabel).source === "string" && typeof (value as TrustLabel).signature === "string");
}

function isRiskVector(value: unknown): value is RiskVector {
  if (!value || typeof value !== "object") return false;
  return "prompt_injection" in value && "sensitive_data" in value && "tool_hijack" in value;
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
  const trustLabel = exposures.map((item) => item.label.trust_label).find(Boolean);
  const taintProfile = exposures.map((item) => item.label.taint_profile).find(Boolean);
  return {
    source: sources,
    text: "",
    label: {
      source: sources,
      integrity: "untrusted",
      confidentiality,
      tainted: true,
      provenance_untrusted: true,
      influence: "payload_default",
      trust_label: trustLabel,
      taint_profile: taintProfile,
    },
  };
}

function shouldDefaultPropagateExposure(exposure: PolicyState["exposures"][number]): boolean {
  if (exposure.label.confidentiality === "secret") return true;
  const risk = exposure.label.risk_vector || createRiskVector();
  return risk.sensitive_data >= 50
    || risk.exfiltration >= 50
    || risk.persistence >= 50
    || risk.tool_hijack >= 50
    || risk.privilege >= 50
    || risk.prompt_injection >= 80;
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
