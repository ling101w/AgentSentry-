import type { PluginConfig } from "../config.ts";
import { clampText, redactObject, safeStringify } from "./redact.ts";
import { systemPreflight } from "./system-monitor.ts";
import { analyzeTrustContent, riskMax, sourceFromTool } from "./trust.ts";
import {
  applyExposureTaint,
  decideAction,
  mostSevereVerdict,
  normalizeAction,
  type PolicyDecision,
  type PolicyState,
} from "./policy.ts";

export type DetectionFinding = {
  layer: string;
  finding_type: "deterministic" | "heuristic" | "learned";
  verdict: "pass" | "require_approval" | "block";
  reason: string;
  score: number;
  evidence: Record<string, unknown>;
};

export type DetectionResult = {
  decision: "allow" | "ask" | "deny";
  risk_score: number;
  findings: DetectionFinding[];
  summary: string;
  policy: PolicyDecision;
};

const HIGH_RISK_TOOL_PATTERNS = [
  /shell|command|exec|terminal|powershell|cmd/i,
  /write|delete|remove|move|chmod|chown/i,
  /email|mail|message|send/i,
  /http|fetch|request|api|browser/i,
  /memory|remember/i,
];

const DANGEROUS_COMMAND_PATTERNS = [
  /\brm\s+-rf\b/i,
  /\bdel\s+\/[fsq]/i,
  /\bremove-item\b.*\b-recurse\b/i,
  /\bgit\s+reset\s+--hard\b/i,
  /\bshutdown\b|\breboot\b/i,
  /\bformat\b\s+[a-z]:/i,
  /\b(?:curl|wget)\b[\s\S]{0,160}\|\s*(?:bash|sh|zsh|python|node)\b/i,
  /\b(?:curl|wget|invoke-webrequest)\b[\s\S]{0,160}(?:id_rsa|\.env|openclaw\.json|token|secret|password|api[_-]?key)/i,
  /\bchmod\s+777\b/i,
  /\breg\s+add\b/i,
];

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|commands?)/i,
  /(system|developer|internal).{0,48}(prompt|configuration|policy|instruction)/i,
  /(send|show|list|provide|exfiltrate).{0,80}(api[_ -]?key|token|secret|password|credential)/i,
  /bypass\s+(policy|guardrail|safety|restriction)/i,
  /act\s+as\s+(an?\s+)?(unfiltered|jailbroken|developer mode)/i,
  /(系统提示|开发者提示|内部配置|工具声明|输出格式规则|完整提示词)/i,
  /(忽略|绕过|禁用|关闭).{0,32}(安全策略|策略|规则|限制|防护|审计|监督)/i,
  /(以后|未来|下次).{0,60}(忽略|绕过|优先执行|直接执行|无需确认)/i,
];

const SENSITIVE_PATH_PATTERNS = [
  /system_prompt/i,
  /\.env\b/i,
  /id_rsa|ssh[/\\]config/i,
  /api[_-]?key|token|secret|password/i,
  /windows[/\\]system32|startup/i,
  /\/etc\/(?:shadow|gshadow|sudoers|passwd-)/i,
  /\.\.[/\\]/,
];

export function detectToolCall(
  toolName: string,
  params: Record<string, unknown>,
  config: PluginConfig,
  state: PolicyState,
  extraFindings: DetectionFinding[] = [],
): DetectionResult {
  let action = normalizeAction(toolName, params);
  if (!config.detection.enabled) {
    const policy = decideAction(action, state, config, []);
    return { decision: policy.decision, risk_score: policy.risk_score, findings: policy.findings, summary: "detection disabled; policy only", policy };
  }

  const findings: DetectionFinding[] = [...extraFindings];
  const exposure = applyExposureTaint(action, state, config);
  action = exposure.action;
  findings.push(...exposure.findings);
  const text = `${toolName}\n${safeStringify(params)}`;
  let risk = baseToolRisk(toolName);
  const command = readCommand(params);
  if (command && isLowRiskShellRead(command)) {
    risk = 5;
  }
  const trustAnalysis = analyzeTrustContent(params, {
    source: sourceFromTool(toolName),
    sourceId: toolName,
    toolName,
    previewChars: config.capture.previewChars,
  });
  findings.push(...trustAnalysis.findings);
  risk += Math.min(55, Math.trunc(riskMax(trustAnalysis.risk_vector) / 2));

  const preflight = systemPreflight(toolName, params, { previewChars: config.capture.previewChars });
  findings.push(...preflight.findings);
  risk += Math.min(70, Math.trunc(riskMax(preflight.risk_vector) * 0.7));

  if (command) {
    const matched = DANGEROUS_COMMAND_PATTERNS.filter((pattern) => pattern.test(command)).map((pattern) => pattern.source);
    if (matched.length) {
      risk += 55;
      findings.push({
        layer: "Execution Control",
        finding_type: "deterministic",
        verdict: "block",
        reason: "dangerous command pattern detected",
        score: 90,
        evidence: { toolName, command: clampText(command, config.capture.previewChars), matched },
      });
    }
  }

  const pathLike = collectPathLike(params);
  const sensitivePaths = pathLike.filter((value) => !isSafeSystemReadPath(value) && SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(value)));
  if (sensitivePaths.length) {
    risk += 35;
    findings.push({
      layer: "Execution Control",
      finding_type: "deterministic",
      verdict: "block",
      reason: "tool parameters reference sensitive or system paths",
      score: 75,
      evidence: { toolName, paths: sensitivePaths.slice(0, 5) },
    });
  }

  const injectionMatches = matchPatterns(text, PROMPT_INJECTION_PATTERNS);
  if (injectionMatches.length) {
    risk += 25;
    findings.push({
      layer: "Decision Alignment",
      finding_type: "heuristic",
      verdict: "require_approval",
      reason: "tool call contains prompt-injection or exfiltration indicators",
      score: 35,
      evidence: { toolName, matched: injectionMatches.slice(0, 5) },
    });
  }

  const policy = decideAction(action, state, config, findings);
  return {
    decision: policy.decision,
    risk_score: Math.max(Math.min(risk, 150), policy.risk_score),
    findings: policy.findings,
    summary: policy.findings.length ? policy.findings.map((finding) => finding.reason).join("; ") : "no high-risk signal",
    policy,
  };
}

function isSafeSystemReadPath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  return [
    "/etc/os-release",
    "/etc/issue",
    "/etc/hostname",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/loadavg",
    "/proc/uptime",
  ].includes(normalized);
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

export { mostSevereVerdict };

export function detectMessageContent(content: unknown, config: PluginConfig): DetectionFinding[] {
  if (!config.detection.enabled) return [];
  const text = clampText(content, config.capture.previewChars);
  const trustAnalysis = analyzeTrustContent(content, { source: "user_input", sourceId: "message", previewChars: config.capture.previewChars });
  const matched = matchPatterns(text, PROMPT_INJECTION_PATTERNS);
  const findings = [...trustAnalysis.findings];
  if (!matched.length) return findings;
  return [
    ...findings,
    {
      layer: "Input Sanitization",
      finding_type: "heuristic",
      verdict: "pass",
      reason: "message contains prompt-injection indicators",
      score: 25,
      evidence: { matched: matched.slice(0, 5), preview: text },
    },
  ];
}

export function serializeToolParams(params: Record<string, unknown>, config: PluginConfig): unknown {
  if (!config.capture.includeToolParams) return "[disabled]";
  return redactObject(params, config.capture.previewChars);
}

function baseToolRisk(toolName: string): number {
  return HIGH_RISK_TOOL_PATTERNS.some((pattern) => pattern.test(toolName)) ? 20 : 5;
}

function readCommand(params: Record<string, unknown>): string {
  for (const key of ["command", "cmd", "script", "shell", "input"]) {
    const value = params[key];
    if (typeof value === "string") return value;
  }
  return "";
}

function collectPathLike(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") {
    if (/[/:\\]/.test(value) || /\.[a-z0-9]{1,8}$/i.test(value)) out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectPathLike(item, out);
    return out;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (/path|file|dir|target|url/i.test(key) && typeof item === "string") out.push(item);
      collectPathLike(item, out);
    }
  }
  return Array.from(new Set(out));
}

function matchPatterns(text: string, patterns: RegExp[]): string[] {
  const matches: string[] = [];
  for (const variant of textVariants(text)) {
    for (const pattern of patterns) {
      const match = pattern.exec(variant);
      if (match) matches.push(match[0].slice(0, 160));
    }
  }
  return Array.from(new Set(matches));
}

function textVariants(text: string): string[] {
  const normalized = canonicalText(text);
  return Array.from(new Set([normalized, ...decodedTextCandidates(normalized)].filter(Boolean))).slice(0, 12);
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
