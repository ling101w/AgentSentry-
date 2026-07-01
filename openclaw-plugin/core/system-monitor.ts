import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import type { DetectionFinding } from "./detect.ts";
import { clampText, safeStringify } from "./redact.ts";
import { createRiskVector, finding, type RiskVector } from "./trust.ts";

export type SystemMonitorStatus = {
  pre_exec_policy: "active";
  ebpf: "attached" | "available" | "unavailable";
  reason: string;
};

export type SystemPreflightResult = {
  findings: DetectionFinding[];
  risk_vector: RiskVector;
  status: SystemMonitorStatus;
};

const EXFIL_COMMAND_PATTERNS = [
  /\b(?:cat|less|more|tail|head)\s+(?:~\/\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)|[^\s;&|]*\.env|[^\s;&|]*openclaw\.json|[^\s;&|]*secret[^\s;&|]*|[^\s;&|]*credential[^\s;&|]*)/i,
  /\b(?:curl|wget)\b[\s\S]{0,200}(?:token|secret|password|credential|identity|id_(?:rsa|ed25519|ecdsa|dsa)|openclaw\.json|\.env|\.ssh)/i,
  /\b(?:curl|wget)\b[\s\S]{0,160}\|\s*(?:bash|sh|zsh|python|node)\b/i,
  /\b(?:scp|rsync|nc|ncat|socat)\b[\s\S]{0,180}(?:~\/\.ssh|id_(?:rsa|ed25519|ecdsa|dsa)|\.env|openclaw\.json|secret|token|credential)/i,
  /(?:base64|xxd|openssl\s+enc).{0,140}(?:~\/\.ssh|id_(?:rsa|ed25519|ecdsa|dsa)|\.env|openclaw\.json|secret|token|credential)/i,
  /--data(?:-binary)?\s+@(?:~\/\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)|[^\s;&|]*\.env|[^\s;&|]*openclaw\.json)/i,
];

const PRIVILEGE_COMMAND_PATTERNS = [
  /\bsudo\b/i,
  /\bchmod\s+(?:777|[0-7]*7[0-7]*)\b/i,
  /\bchown\b/i,
  /\b(?:systemctl|service)\s+(?:enable|start|restart|edit|daemon-reload)\b/i,
  /\bcrontab\b|\bcron\b/i,
  /\brm\s+-rf\s+(?:\/|~|\.{1,2})\b/i,
  /\b(?:bash|sh|zsh|python|node|perl|ruby)\s+-c\b/i,
];

const SENSITIVE_PATH_PATTERNS = [
  /(?:^|\/)\.env(?:\.|$)?/i,
  /(?:^|\/)openclaw\.json$/i,
  /(?:^|\/)(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)$/i,
  /(?:^|\/)(?:secret|secrets|credentials)(?:\.json|\.txt|\.yaml|\.yml)?$/i,
  /\/etc\/(?:shadow|gshadow|sudoers|passwd-)|\/root\/|~\/\.ssh/i,
];

const PERSISTENCE_PATH_PATTERNS = [
  /(?:^|\/)(?:memory\.md|agents\.md|soul\.md|user\.md)$/i,
  /(?:^|\/)\.openclaw(?:\/|$)/i,
  /(?:^|\/)(?:crontab|cron\.d|systemd|startup|launchagents|launchdaemons)(?:\/|$)/i,
];

const NON_LOCAL_GATEWAY_PATTERN = /[?&]gatewayURL\s*=\s*wss?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))/i;

export function systemPreflight(
  toolName: string,
  params: Record<string, unknown>,
  options: { previewChars?: number } = {},
): SystemPreflightResult {
  const previewChars = options.previewChars ?? 1200;
  const normalized = toolName.toLowerCase();
  const text = `${toolName}\n${safeStringify(params)}`;
  const command = readFirstString(params, ["command", "cmd", "script", "shell", "input"]);
  const paths = collectPathLike(params);
  const urls = collectUrls(params);
  const findings: DetectionFinding[] = [];
  const risk = createRiskVector();

  if (/shell|command|exec|terminal|powershell|cmd/.test(normalized) || command) {
    const safeRead = command ? isLowRiskShellRead(command) : false;
    const exfilMatches = safeRead ? [] : matchPatterns(command || text, EXFIL_COMMAND_PATTERNS);
    const privilegeMatches = safeRead ? [] : matchPatterns(command || text, PRIVILEGE_COMMAND_PATTERNS);
    if (exfilMatches.length) {
      risk.exfiltration = 95;
      risk.sensitive_data = Math.max(risk.sensitive_data, 85);
      findings.push(finding("System Preflight", "deterministic", "block", "command can read or transmit sensitive local assets", 100, {
        command: clampText(command || text, previewChars),
        matched: exfilMatches,
        monitor: systemMonitorStatus(),
      }));
    }
    if (privilegeMatches.length) {
      risk.privilege = 90;
      findings.push(finding("System Preflight", "deterministic", "block", "command requests privileged or persistent system changes", 95, {
        command: clampText(command || text, previewChars),
        matched: privilegeMatches,
        monitor: systemMonitorStatus(),
      }));
    }
  }

  const sensitivePaths = paths.filter((path) => !isSafeSystemReadPath(path) && SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(path)));
  if (sensitivePaths.length) {
    risk.sensitive_data = Math.max(risk.sensitive_data, 85);
    findings.push(finding("System Preflight", "deterministic", "block", "tool parameters target sensitive local paths", 90, {
      paths: sensitivePaths.slice(0, 8),
      monitor: systemMonitorStatus(),
    }));
  }

  const persistencePaths = paths.filter((path) => PERSISTENCE_PATH_PATTERNS.some((pattern) => pattern.test(path)));
  if (persistencePaths.length) {
    risk.persistence = 90;
    findings.push(finding("System Preflight", "deterministic", "block", "tool parameters target memory, startup, or OpenClaw configuration paths", 95, {
      paths: persistencePaths.slice(0, 8),
      monitor: systemMonitorStatus(),
    }));
  }

  const gatewayUrls = urls.filter((url) => NON_LOCAL_GATEWAY_PATTERN.test(url) || /gatewayURL/i.test(url));
  if (gatewayUrls.length) {
    risk.tool_hijack = 100;
    findings.push(finding("System Preflight", "deterministic", "block", "Control UI gateway URL override detected before network call", 100, {
      urls: gatewayUrls.slice(0, 6),
      monitor: systemMonitorStatus(),
    }));
  }

  return {
    findings: dedupeFindings(findings),
    risk_vector: risk,
    status: systemMonitorStatus(),
  };
}

export function systemMonitorStatus(): SystemMonitorStatus {
  const bpffs = existsSync("/sys/fs/bpf");
  const bpftoolPath = commandPath("bpftool", ["/usr/sbin/bpftool", "/sbin/bpftool", "/usr/bin/bpftool"]);
  const bpftool = bpftoolPath ? spawnSync(bpftoolPath, ["version"], { stdio: "ignore" }) : { status: 127 };
  const bpfWritable = canAccess("/sys/fs/bpf");
  const tracingReadable = canAccess("/sys/kernel/tracing") || canAccess("/sys/kernel/debug/tracing");
  const unprivileged = readKernelFlag("/proc/sys/kernel/unprivileged_bpf_disabled");
  if (bpffs && bpftool.status === 0 && typeof process.getuid === "function" && process.getuid() === 0 && bpfWritable && tracingReadable) {
    return { pre_exec_policy: "active", ebpf: "available", reason: "bpffs, tracefs and bpftool are available; root can attach probes" };
  }
  if (bpffs && bpftool.status === 0 && !bpfWritable) {
    return {
      pre_exec_policy: "active",
      ebpf: "unavailable",
      reason: `bpffs and bpftool exist, but /sys/fs/bpf is not accessible to this user service${unprivileged ? `; unprivileged_bpf_disabled=${unprivileged}` : ""}`,
    };
  }
  if (bpffs && bpftool.status === 0 && !tracingReadable) {
    return { pre_exec_policy: "active", ebpf: "unavailable", reason: "bpftool exists, but tracefs/debugfs is not accessible to this user service" };
  }
  return { pre_exec_policy: "active", ebpf: "unavailable", reason: "kernel eBPF attachment tools are not available in this runtime" };
}

function readFirstString(args: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string") return value;
  }
  return "";
}

function collectPathLike(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") {
    if (/[/:\\~]/.test(value) || /\.[a-z0-9]{1,8}$/i.test(value)) out.push(value.replace(/\\/g, "/"));
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectPathLike(item, out);
    return out;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (/path|file|dir|target|url|href|endpoint|command|script|content|body/i.test(key)) collectPathLike(item, out);
    }
  }
  return Array.from(new Set(out));
}

function collectUrls(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") {
    for (const match of value.matchAll(/wss?:\/\/[^\s"'<>]+|https?:\/\/[^\s"'<>]+/gi)) {
      out.push(match[0]);
    }
    if (/gatewayURL/i.test(value)) out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectUrls(item, out);
    return out;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value as Record<string, unknown>)) collectUrls(item, out);
  }
  return Array.from(new Set(out));
}

function matchPatterns(text: string, patterns: RegExp[]): string[] {
  const matches: string[] = [];
  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match) matches.push(match[0].slice(0, 180).replace(/\bsk-[a-zA-Z0-9_-]{8,}\b/g, "[redacted]"));
  }
  return Array.from(new Set(matches));
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

function canAccess(path: string): boolean {
  try {
    const testPath = commandPath("test", ["/usr/bin/test", "/bin/test"]) || "test";
    return existsSync(path) && spawnSync(testPath, ["-r", path], { stdio: "ignore" }).status === 0;
  } catch {
    return false;
  }
}

function readKernelFlag(path: string): string {
  try {
    const catPath = commandPath("cat", ["/usr/bin/cat", "/bin/cat"]) || "cat";
    const result = spawnSync(catPath, [path], { encoding: "utf8" });
    return result.status === 0 ? result.stdout.trim() : "";
  } catch {
    return "";
  }
}

function commandPath(name: string, candidates: string[]): string {
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  try {
    const result = spawnSync("command", ["-v", name], { shell: true, encoding: "utf8" });
    return result.status === 0 ? result.stdout.trim().split(/\r?\n/)[0] || "" : "";
  } catch {
    return "";
  }
}

function dedupeFindings(findings: DetectionFinding[]): DetectionFinding[] {
  const seen = new Set<string>();
  const out: DetectionFinding[] = [];
  for (const item of findings) {
    const key = `${item.layer}:${item.verdict}:${item.reason}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}
