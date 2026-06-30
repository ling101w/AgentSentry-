import type { PluginConfig } from "../config.ts";
import { clampText, redactObject, safeStringify } from "./redact.ts";
import {
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
  /\bcurl\b|\bwget\b|\binvoke-webrequest\b/i,
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
];

const SENSITIVE_PATH_PATTERNS = [
  /system_prompt/i,
  /\.env\b/i,
  /id_rsa|ssh[/\\]config/i,
  /api[_-]?key|token|secret|password/i,
  /windows[/\\]system32|\/etc\/|startup/i,
  /\.\.[/\\]/,
];

export function detectToolCall(
  toolName: string,
  params: Record<string, unknown>,
  config: PluginConfig,
  state: PolicyState,
  extraFindings: DetectionFinding[] = [],
): DetectionResult {
  const action = normalizeAction(toolName, params);
  if (!config.detection.enabled) {
    const policy = decideAction(action, state, config, extraFindings);
    return { decision: policy.decision, risk_score: policy.risk_score, findings: policy.findings, summary: "detection disabled; policy only", policy };
  }

  const findings: DetectionFinding[] = [...extraFindings];
  const text = `${toolName}\n${safeStringify(params)}`;
  let risk = baseToolRisk(toolName);

  const command = readCommand(params);
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
  const sensitivePaths = pathLike.filter((value) => SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(value)));
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

export { mostSevereVerdict };

export function detectMessageContent(content: unknown, config: PluginConfig): DetectionFinding[] {
  if (!config.detection.enabled) return [];
  const text = clampText(content, config.capture.previewChars);
  const matched = matchPatterns(text, PROMPT_INJECTION_PATTERNS);
  if (!matched.length) return [];
  return [
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
  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match) matches.push(match[0].slice(0, 160));
  }
  return matches;
}
