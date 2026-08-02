import type { PluginConfig } from "../../config.ts";
import type { DetectionFinding } from "../detect.ts";
import { readFirstString } from "../adapters/openclaw-tools.ts";
import { hostFromUrl, isLocalHost } from "../security/url.ts";
import { addRisk, createRiskVector, mergeRiskVectors, type RiskVector, type TaintSink } from "../trust.ts";
import { safeStringify } from "../redact.ts";
import type { ActionAssessment, AgentSentryAction, PolicySnapshot } from "./types.ts";

const SYSTEM_MUTATION_PATH_MARKERS = ["/etc", "/usr", "/bin", "/sbin", "/var/spool/cron", "/boot", "/root", "\\windows", "system32", "startup"];
const SENSITIVE_PATH_PATTERNS = [
  /(^|\/)\.env(?:\.|$)/i,
  /(^|\/)openclaw\.json$/i,
  /(^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)$/i,
  /(^|\/)(credentials|secrets?|private[_-]?key)(?:\.[a-z0-9]+)?$/i,
  /\/\.ssh\/(?!known_hosts$|authorized_keys$)/i,
  /\/\.aws\/credentials$/i,
  /\/\.kube\/config$/i,
  /\/etc\/(?:shadow|gshadow)$/i,
];
const SAFE_SYSTEM_READ_PATHS = ["/etc/os-release", "/etc/issue", "/etc/hostname", "/proc/cpuinfo", "/proc/meminfo", "/proc/loadavg", "/proc/uptime"];

export function assessAction(action: AgentSentryAction, config: PluginConfig): ActionAssessment {
  return assessActionWithSensitiveAssets(action, config.policy.sensitiveAssets);
}

export function assessActionWithSensitiveAssets(action: AgentSentryAction, sensitiveAssets: string[]): ActionAssessment {
  const filePath = readFirstString(action.args, ["path", "file", "filename", "target"]).replace(/\\/g, "/");
  const command = readFirstString(action.args, ["command", "cmd", "script", "input"]);
  const argsText = safeStringify(action.args);
  const reasons: string[] = [];
  let actionClass: ActionAssessment["class"] = "unknown";
  let externalSink = false;
  let sensitive = false;
  let persistence = false;
  let systemMutation = false;
  let dangerousCommand = false;

  if (["read_file", "read_webpage", "memory_read"].includes(action.tool)) actionClass = "read";
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
    const host = hostFromUrl(readFirstString(action.args, ["url", "href", "endpoint", "target"]));
    externalSink = Boolean(host && !isLocalHost(host));
    if (externalSink) reasons.push(`network call targets external host ${host}`);
  }
  if (isSensitivePathWithAssets(filePath, sensitiveAssets) || hasSensitiveValue(argsText)) {
    sensitive = true;
    reasons.push("arguments reference sensitive asset");
  }
  if (filePath && isPersistencePath(filePath) && !["read_file", "memory_read"].includes(action.tool)) {
    persistence = true;
    reasons.push("path targets persistence surface");
  }
  if (action.tool === "memory_write") {
    persistence = true;
    reasons.push("memory write is persistent");
  }
  if (filePath && isSystemMutationPath(filePath) && !isSafeSystemReadPath(filePath) && action.tool !== "read_file") {
    systemMutation = true;
    reasons.push("path targets protected system location");
  }
  if (action.tool === "shell_exec" && command) {
    const shell = assessShellCommand(command);
    sensitive ||= shell.sensitive;
    externalSink ||= shell.externalSink;
    persistence ||= shell.persistence;
    systemMutation ||= shell.systemMutation;
    dangerousCommand ||= shell.dangerousCommand;
    reasons.push(...shell.reasons);
  }
  return {
    class: actionClass,
    highRisk: externalSink || sensitive || persistence || systemMutation || dangerousCommand,
    externalSink,
    sensitive,
    persistence,
    systemMutation,
    dangerousCommand,
    reasons: unique(reasons),
  };
}

export function sinkForAction(action: AgentSentryAction, assessment: ActionAssessment): TaintSink | null {
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

export function isTrustSensitiveSink(action: AgentSentryAction, assessment: ActionAssessment): boolean {
  return sinkForAction(action, assessment) !== null;
}

export function baseToolRisk(tool: string): number {
  return { read_file: 18, write_file: 22, send_email: 25, call_api: 20, memory_write: 25, memory_read: 10, read_webpage: 10, shell_exec: 25 }[tool] ?? 20;
}

export function heuristicScore(findings: DetectionFinding[]): number {
  return Math.min(findings.filter((item) => item.finding_type !== "deterministic" && item.verdict !== "pass").reduce((sum, item) => sum + item.score, 0), 100);
}

export function riskVectorFromFindings(findings: DetectionFinding[]): RiskVector {
  let vector = createRiskVector();
  for (const item of findings) {
    const evidence = item.evidence || {};
    if (isRiskVector(evidence.risk_vector)) vector = mergeRiskVectors(vector, evidence.risk_vector);
    if (item.layer === "State Integrity") vector = addRisk(vector, createRiskVector({ persistence: item.score }));
    if (item.layer === "Context Provenance") {
      vector = addRisk(vector, createRiskVector({
        prompt_injection: /(prompt|injection|hidden|pdf|image|message|content)/i.test(item.reason) ? item.score : 0,
        supply_chain: /(skill|configuration|workspace|provenance)/i.test(item.reason) ? item.score : 0,
      }));
    }
    if (item.layer === "Tool Boundary") vector = addRisk(vector, createRiskVector({ privilege: item.score }));
  }
  return vector;
}

export function provenanceRiskForAction(action: AgentSentryAction, state: PolicySnapshot): Record<string, unknown> | null {
  const argsText = normalizeText(safeStringify(action.args));
  const matched = state.provenanceFindings.filter((item) => {
    const evidence = item.evidence || {};
    const rawPath = String(evidence.path || evidence.file || "").replace(/\\/g, "/").toLowerCase();
    const base = rawPath.split("/").filter(Boolean).pop() || rawPath;
    return item.verdict === "block" && Boolean(rawPath) && ((rawPath.length >= 6 && argsText.includes(rawPath)) || (base.length >= 6 && argsText.includes(base)));
  });
  if (!matched.length) return null;
  return {
    matched_paths: matched.map((item) => String(item.evidence?.path || item.evidence?.file || "")).slice(0, 5),
    blocked_findings: matched.map((item) => item.reason).slice(0, 5),
  };
}

export function isSensitivePathWithAssets(value: string, sensitiveAssets: string[]): boolean {
  const normalized = value.replace(/\\/g, "/").toLowerCase();
  return SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(normalized))
    || sensitiveAssets.some((asset) => asset && normalized.includes(asset.toLowerCase()));
}

export function isPersistencePath(value: string): boolean {
  const normalized = value.replace(/\\/g, "/").toLowerCase();
  return /(^|\/)(memory\.md|agents\.md|soul\.md|user\.md|openclaw\.json|skill\.md)$/i.test(normalized)
    || /(^|\/)(?:cron\.d|systemd|startup|skills)(?:\/|$)/i.test(normalized);
}

export function isSystemMutationPath(value: string): boolean {
  const normalized = value.replace(/\\/g, "/").toLowerCase();
  return !isSafeSystemReadPath(normalized) && SYSTEM_MUTATION_PATH_MARKERS.some((marker) => normalized.includes(marker.toLowerCase()));
}

export function isSafeSystemReadPath(value: string): boolean {
  return SAFE_SYSTEM_READ_PATHS.includes(value.replace(/\\/g, "/").toLowerCase());
}

export function isDocumentationPath(value: string): boolean {
  const normalized = value.replace(/\\/g, "/").toLowerCase();
  return /\.(?:md|markdown|txt|rst|adoc)$/i.test(normalized)
    && (/(^|\/)(docs?|examples?|samples?)(\/|$)/i.test(normalized) || /(^|\/)(readme|security|changelog|license)(?:\.[a-z0-9]+)?$/i.test(normalized));
}

function hasSensitiveValue(text: string): boolean {
  return /-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----|\bsk-[a-zA-Z0-9_-]{16,}\b|\bgh[pousr]_[a-zA-Z0-9_]{20,}\b|\bbearer\s+[a-zA-Z0-9._-]{16,}\b/i.test(text);
}

function assessShellCommand(command: string): Pick<ActionAssessment, "externalSink" | "sensitive" | "persistence" | "systemMutation" | "dangerousCommand" | "reasons"> {
  const safeRead = /^(pwd|whoami|id|hostname|uname\s+-a|date|du\s+-sh\s+\.|df(?:\s+-h)?|cat\s+\/etc\/(?:os-release|issue|hostname))$/i.test(command.trim());
  const externalSink = /\b(curl|wget|scp|rsync|nc|ncat|socat)\b/i.test(command) && !safeRead;
  const sensitive = /(~\/\.ssh\/id_|\/\.ssh\/id_|\.env\b|openclaw\.json|\/etc\/shadow|secret|token|password|api[_-]?key)/i.test(command);
  const persistence = /\b(crontab|systemctl\s+enable|systemctl\s+edit|>>?\s*.*(?:memory\.md|agents\.md|openclaw\.json|\/etc\/|cron\.d|systemd))\b/i.test(command);
  const systemMutation = !safeRead && /\b(sudo|chmod\s+(?:777|[0-7]*7[0-7]*)|chown|systemctl\s+(?:start|restart|stop|reload|enable|disable|edit)|mount|umount|iptables|ufw)\b/i.test(command);
  const dangerousCommand = /\brm\s+-rf\s+(?:\/|~|\.\.?)(?:\s|$)|\bdd\s+.*\bof=\/dev\/|\bmkfs\.|\bshutdown\b|\breboot\b|\b(curl|wget)\b[\s\S]{0,160}\|\s*(bash|sh|zsh|python|node)\b/i.test(command);
  const reasons = [externalSink && "command uses network transfer", sensitive && "command references sensitive assets", persistence && "command modifies persistence surface", systemMutation && "command mutates system state", dangerousCommand && "command is destructive or executes remote code"].filter(Boolean) as string[];
  return { externalSink, sensitive, persistence, systemMutation, dangerousCommand, reasons };
}

function isRiskVector(value: unknown): value is RiskVector {
  return Boolean(value && typeof value === "object" && "prompt_injection" in value && "sensitive_data" in value && "tool_hijack" in value);
}

function normalizeText(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}
