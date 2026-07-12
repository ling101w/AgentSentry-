import type { PluginConfig } from "../../config.ts";
import { safeStringify } from "../redact.ts";
import { sourceFromTool, type TaintSink, type TrustSource } from "../trust.ts";
import { hostFromUrl, isLocalHost, readFirstString, unique } from "./value-utils.ts";

export type PolicyActionInput = {
  tool: string;
  originalTool: string;
  args: Record<string, unknown>;
  reason: string;
};

export type ActionClass = "read" | "write" | "external_sink" | "execution" | "memory" | "network" | "unknown";

export type ActionAssessment = {
  class: ActionClass;
  highRisk: boolean;
  externalSink: boolean;
  sensitive: boolean;
  persistence: boolean;
  systemMutation: boolean;
  dangerousCommand: boolean;
  reasons: string[];
};

const FILE_PATH_TOOLS = new Set(["read_file", "write_file", "memory_read", "memory_write"]);
const READ_ONLY_TOOLS = new Set(["read_file", "read_webpage", "memory_read"]);
const SYSTEM_MUTATION_PATH_PATTERNS = [
  /^\/(?:etc|usr|bin|sbin|boot|root|proc|sys|dev)(?:\/|$)/i,
  /^\/var\/spool\/cron(?:\/|$)/i,
  /^[a-z]:\/windows(?:\/|$)/i,
  /^\/+windows(?:\/|$)/i,
  /^\/\/[^/]+\/[a-z]\$\/windows(?:\/|$)/i,
];
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

export function assessAction(action: PolicyActionInput, config: PluginConfig): ActionAssessment {
  return assessActionWithSensitiveAssets(action, config.policy.sensitiveAssets);
}

export function assessActionWithSensitiveAssets(action: PolicyActionInput, sensitiveAssets: string[]): ActionAssessment {
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
    externalSink = !host || !isLocalHost(host);
    if (externalSink) reasons.push(host ? `network call targets external host ${host}` : "network call target is missing or invalid");
  }
  if ((FILE_PATH_TOOLS.has(action.tool) && isSensitivePathWithAssets(path, sensitiveAssets)) || hasSensitiveValue(argsText)) {
    sensitive = true;
    reasons.push("arguments reference sensitive asset");
  }
  if (path && FILE_PATH_TOOLS.has(action.tool) && isPersistencePath(path) && !READ_ONLY_TOOLS.has(action.tool)) {
    persistence = true;
    reasons.push("path targets persistence surface");
  }
  if (action.tool === "memory_write") {
    persistence = true;
    reasons.push("memory write is persistent");
  }
  if (path && FILE_PATH_TOOLS.has(action.tool) && !READ_ONLY_TOOLS.has(action.tool) && isSystemMutationPath(path)) {
    systemMutation = true;
    reasons.push("path targets protected system location");
  }
  if (action.tool === "shell_exec" && command) {
    const shell = assessShellCommand(command, sensitiveAssets);
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

export function shouldHardBlockTaskMismatch(
  action: PolicyActionInput,
  assessment: ActionAssessment,
  state: { contaminated: boolean },
): boolean {
  if (!assessment.highRisk && (action.tool === "read_file" || action.tool === "write_file" || action.tool === "call_api")) return false;
  if (action.tool === "send_email") return assessment.externalSink || state.contaminated;
  if (action.tool === "shell_exec") return assessment.highRisk;
  if (action.tool === "memory_write") return assessment.persistence;
  return assessment.highRisk;
}

export function isTrustSensitiveSink(action: PolicyActionInput, assessment: ActionAssessment): boolean {
  if (action.tool === "send_email") return true;
  if (action.tool === "shell_exec") return assessment.highRisk;
  if (action.tool === "memory_write") return true;
  if (action.tool === "call_api") return assessment.externalSink;
  if (action.tool === "write_file") return assessment.persistence || assessment.systemMutation || assessment.sensitive;
  return false;
}

export function sinkForAction(action: PolicyActionInput, assessment: ActionAssessment): TaintSink | null {
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

export function isSensitivePath(path: string, config: PluginConfig): boolean {
  return isSensitivePathWithAssets(path, config.policy.sensitiveAssets);
}

export function isOpenClawMemoryDocumentPath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  if (!normalized) return false;
  return /(^|\/)(memory\.md|soul\.md|user\.md)$/i.test(normalized)
    || /(^|\/)memory\/[^/]+\.md$/i.test(normalized);
}

export function sourceForToolResult(toolName: string, result: unknown): TrustSource {
  const lower = toolName.toLowerCase();
  const tokens = toolNameTokens(toolName);
  if (lower === "call_api" || tokens.some((token) => NETWORK_TOOL_TOKENS.has(token))) {
    const url = extractResultUrl(result);
    return url && isLocalHost(hostFromUrl(url)) ? "tool_result" : "external_web";
  }
  if (/read_file|filesystem.*read/.test(lower)) return "workspace";
  if (/memory.*read/.test(lower)) return "memory";
  return sourceFromTool(toolName);
}

function isSensitivePathWithAssets(path: string, sensitiveAssets: string[]): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  if (!normalized) return false;
  if (isSafeSystemReadPath(normalized)) return false;
  if (SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(normalized))) return true;
  if (isDocumentationPath(normalized)) return false;
  return sensitiveAssets.some((asset) => {
    const item = asset.trim().replace(/\\/g, "/").toLowerCase();
    if (!item) return false;
    if (normalized === item || normalized.endsWith(`/${item}`)) return true;
    const escaped = item.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`(^|[/_.-])${escaped}($|[/_.-])`, "i").test(normalized);
  });
}

function isPersistencePath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  return /(^|\/)(memory\.md|agents\.md|soul\.md|user\.md|openclaw\.json|skill\.md)$/i.test(normalized)
    || /(^|\/)(cron\.d|systemd|startup|skills|launchagents|launchdaemons)(\/|$)/i.test(normalized)
    || /(^|\/)\.ssh\/(authorized_keys|config)$/i.test(normalized)
    || /(^|\/)(\.bashrc|\.zshrc|\.profile|microsoft\.powershell_profile\.ps1)$/i.test(normalized)
    || normalized.includes("/.openclaw/");
}

function isSystemMutationPath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  return SYSTEM_MUTATION_PATH_PATTERNS.some((pattern) => pattern.test(normalized));
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

function assessShellCommand(command: string, sensitiveAssets: string[]): Pick<ActionAssessment, "externalSink" | "sensitive" | "persistence" | "systemMutation" | "dangerousCommand"> & { dangerous: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const safeRead = isLowRiskShellRead(command);
  const networkTransfer = /\b(curl|wget|scp|rsync|nc|ncat|socat|invoke-webrequest|iwr)\b/i.test(command);
  const externalSink = networkTransfer && !safeRead && !usesOnlyLocalNetworkTargets(command);
  const sensitive = hasSensitiveValue(command) || shellPathCandidates(command).some((candidate) => isSensitivePathWithAssets(candidate, sensitiveAssets));
  const persistence = /\b(crontab|systemctl\s+enable|systemctl\s+edit|tee\s+.*(memory\.md|agents\.md|openclaw\.json)|>>?\s*.*(memory\.md|agents\.md|openclaw\.json|\/etc\/|cron\.d|systemd))\b/i.test(command)
    || /\bschtasks(?:\.exe)?\b[\s\S]{0,80}\/create\b/i.test(command)
    || /\breg(?:\.exe)?\s+add\b[\s\S]{0,160}\\(?:run|runonce)\b/i.test(command);
  const systemMutation = !safeRead && /\b(sudo|chmod\s+(777|[0-7]*7[0-7]*)|chown|systemctl\s+(start|restart|stop|reload|enable|disable|edit|daemon-reload|mask|unmask)|service\s+(start|restart|stop|reload|enable|disable)|mount|umount|iptables|ufw|set-executionpolicy|netsh|bcdedit)\b/i.test(command);
  const destructive = /\brm\s+-rf\s+(\/|~|\.\.?)(\s|$)|\bdd\s+.*\bof=\/dev\/|\bmkfs\.|\bshutdown\b|\breboot\b|:\s*\(\s*\)\s*\{/i.test(command)
    || /\b(?:remove-item|del|erase|rmdir)\b[\s\S]{0,100}(?:-recurse|\/s)[\s\S]{0,80}(?:[a-z]:[\\/]|\\\\)/i.test(command)
    || /\bformat(?:\.com)?\s+[a-z]:/i.test(command);
  const remoteExec = /\b(curl|wget|invoke-webrequest|iwr)\b[\s\S]{0,160}\|\s*(bash|sh|zsh|python|node|iex|invoke-expression)\b/i.test(command)
    || /\b(?:iex|invoke-expression)\s*\([\s\S]{0,160}\b(?:iwr|invoke-webrequest)\b/i.test(command);
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

const NETWORK_TOOL_TOKENS = new Set(["api", "http", "https", "fetch", "request", "curl", "wget", "axios", "urllib", "urlopen"]);

function toolNameTokens(toolName: string): string[] {
  return toolName
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function shellPathCandidates(command: string): string[] {
  return (command.match(/"[^"]*"|'[^']*'|[^\s|;&<>]+/g) || [])
    .map((token) => token.replace(/^["']|["']$/g, ""))
    .filter((token) => (token.includes("/") || token.includes("\\") || token.includes(".")) && !/^https?:\/\//i.test(token));
}

function usesOnlyLocalNetworkTargets(command: string): boolean {
  const tokens = command.match(/"[^"]*"|'[^']*'|[^\s|;&]+/g) || [];
  const candidates: string[] = [];
  let skipOptionValue = false;
  for (const rawToken of tokens) {
    const token = rawToken.replace(/^["']|["']$/g, "");
    if (skipOptionValue) {
      skipOptionValue = false;
      continue;
    }
    if (/^(?:-o|--output|-t|--upload-file|-d|--data|--data-binary)$/i.test(token)) {
      skipOptionValue = true;
      continue;
    }
    if (token.startsWith("-") || token.startsWith("@")) continue;
    if (/^(?:https?:\/\/)?(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\]|(?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:[/:][^\s]*)?$/i.test(token)) {
      candidates.push(token);
    }
  }
  return candidates.length > 0 && candidates.every((candidate) => isLocalHost(hostFromUrl(candidate)));
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
