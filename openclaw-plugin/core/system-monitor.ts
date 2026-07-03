import { closeSync, existsSync, openSync, readSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import type { RuntimeIsolationUnavailableAction } from "../config.ts";
import type { DetectionFinding } from "./detect.ts";
import { clampText, safeStringify } from "./redact.ts";
import { createRiskVector, finding, type RiskVector } from "./trust.ts";

export type EbpfObserverStatus = {
  service: string;
  active: boolean;
  detected_by: "systemd" | "process" | "none";
  script_path: string;
  log_path: string;
  log_exists: boolean;
  log_mtime?: string;
  recent_events?: number;
};

export type SystemMonitorStatus = {
  pre_exec_policy: "active";
  ebpf: "attached" | "available" | "unavailable";
  reason: string;
  observer: EbpfObserverStatus;
  isolation: {
    mode: "kernel-assisted" | "pre-exec";
    controls: string[];
    limitations: string[];
    recommended_runtime: string[];
  };
};

export type SystemPreflightResult = {
  findings: DetectionFinding[];
  risk_vector: RiskVector;
  status: SystemMonitorStatus;
};

export type EbpfLogCheckpoint = {
  log_path: string;
  size: number;
  created_at: string;
  monitor: SystemMonitorStatus;
};

export type EbpfRuntimeAudit = {
  enabled: boolean;
  monitor: SystemMonitorStatus;
  checkpoint: EbpfLogCheckpoint | null;
  scanned_bytes: number;
  event_count: number;
  interesting_events: Array<Record<string, unknown>>;
  findings: DetectionFinding[];
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
  /\b(?:iptables|ufw)\s+(?:-F|disable|allow|delete|reset)\b/i,
  /\b(?:mount|umount|nsenter|unshare|setcap|setenforce)\b/i,
  /\bdocker\b[\s\S]{0,120}--privileged\b/i,
];

const SENSITIVE_PATH_PATTERNS = [
  /(?:^|\/)\.env(?:\.|$)?/i,
  /(?:^|\/)openclaw\.json$/i,
  /(?:^|\/)(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)$/i,
  /(?:^|\/)(?:secret|secrets|credentials)(?:\.json|\.txt|\.yaml|\.yml)?$/i,
  /\/etc\/(?:shadow|gshadow|sudoers|passwd-)|\/root\/|~\/\.ssh/i,
  /\/proc\/(?:self\/)?environ\b|\/proc\/\d+\/(?:environ|mem|cmdline)\b/i,
  /\/var\/run\/docker\.sock\b|\/run\/containerd\/containerd\.sock\b/i,
  /\/dev\/(?:mem|kmem|kmsg)\b/i,
];

const PERSISTENCE_PATH_PATTERNS = [
  /(?:^|\/)(?:memory\.md|agents\.md|soul\.md|user\.md)$/i,
  /(?:^|\/)\.openclaw(?:\/|$)/i,
  /(?:^|\/)(?:crontab|cron\.d|systemd|startup|launchagents|launchdaemons)(?:\/|$)/i,
];

const NON_LOCAL_GATEWAY_PATTERN = /[?&]gatewayURL\s*=\s*wss?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))/i;

const HOST_ESCAPE_COMMAND_PATTERNS = [
  /\/var\/run\/docker\.sock|\/run\/containerd\/containerd\.sock/i,
  /\bdocker\b[\s\S]{0,120}(?:--privileged|-v\s*\/:|\/var\/run\/docker\.sock)/i,
  /\b(?:nsenter|unshare)\b/i,
  /\bmount\b[\s\S]{0,120}(?:\/dev|proc|sysfs|cgroup)/i,
  /\/proc\/(?:self\/)?environ\b|\/proc\/\d+\/(?:environ|mem|cmdline)\b/i,
  /\/dev\/(?:mem|kmem|kmsg)\b/i,
];

const EBPF_OBSERVER_SERVICE = "agentsentry-ebpf-observer.service";
const EBPF_OBSERVER_SCRIPT = "/home/ubuntu/AgentSentry-/tools/agentsentry-ebpf-observer.bt";
const EBPF_OBSERVER_LOG = "/var/log/agentsentry-ebpf.jsonl";

export function systemPreflight(
  toolName: string,
  params: Record<string, unknown>,
  options: {
    previewChars?: number;
    requireKernelObserverForHighRisk?: boolean;
    unavailableAction?: RuntimeIsolationUnavailableAction;
  } = {},
): SystemPreflightResult {
  const previewChars = options.previewChars ?? 1200;
  const normalized = toolName.toLowerCase();
  const text = `${toolName}\n${safeStringify(params)}`;
  const command = readFirstString(params, ["command", "cmd", "script", "shell", "input"]);
  const paths = collectPathLike(params);
  const urls = collectUrls(params);
  const findings: DetectionFinding[] = [];
  const risk = createRiskVector();
  const monitor = systemMonitorStatus();

  if (/shell|command|exec|terminal|powershell|cmd/.test(normalized) || command) {
    const safeRead = command ? isLowRiskShellRead(command) : false;
    const exfilMatches = safeRead ? [] : matchPatterns(command || text, EXFIL_COMMAND_PATTERNS);
    const privilegeMatches = safeRead ? [] : matchPatterns(command || text, PRIVILEGE_COMMAND_PATTERNS);
    const escapeMatches = safeRead ? [] : matchPatterns(command || text, HOST_ESCAPE_COMMAND_PATTERNS);
    const egressUrls = safeRead ? [] : collectUrls(command || text).filter((url) => isExternalUrl(url));
    if (exfilMatches.length) {
      risk.exfiltration = 95;
      risk.sensitive_data = Math.max(risk.sensitive_data, 85);
      findings.push(finding("System Preflight", "deterministic", "block", "command can read or transmit sensitive local assets", 100, {
        command: clampText(command || text, previewChars),
        matched: exfilMatches,
        monitor,
        isolation_plan: isolationPlan("block"),
      }));
    }
    if (privilegeMatches.length) {
      risk.privilege = 90;
      findings.push(finding("System Preflight", "deterministic", "block", "command requests privileged or persistent system changes", 95, {
        command: clampText(command || text, previewChars),
        matched: privilegeMatches,
        monitor,
        isolation_plan: isolationPlan("block"),
      }));
    }
    if (escapeMatches.length) {
      risk.privilege = 100;
      findings.push(finding("Runtime Isolation", "deterministic", "block", "command attempts host escape or container boundary bypass", 100, {
        command: clampText(command || text, previewChars),
        matched: escapeMatches,
        monitor,
        isolation_plan: isolationPlan("block"),
      }));
    }
    if (egressUrls.length) {
      risk.exfiltration = Math.max(risk.exfiltration, 45);
      findings.push(finding("Runtime Isolation", "heuristic", "require_approval", "command performs network egress and requires sandbox egress review", 45, {
        command: clampText(command || text, previewChars),
        urls: egressUrls.slice(0, 8),
        monitor,
        isolation_plan: isolationPlan("review"),
      }));
    }
  }

  const sensitivePaths = paths.filter((path) => !isSafeSystemReadPath(path) && SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(path)));
  if (sensitivePaths.length) {
    risk.sensitive_data = Math.max(risk.sensitive_data, 85);
    findings.push(finding("System Preflight", "deterministic", "block", "tool parameters target sensitive local paths", 90, {
      paths: sensitivePaths.slice(0, 8),
      monitor,
      isolation_plan: isolationPlan("block"),
    }));
  }

  const persistencePaths = paths.filter((path) => PERSISTENCE_PATH_PATTERNS.some((pattern) => pattern.test(path)));
  if (persistencePaths.length) {
    risk.persistence = 90;
    findings.push(finding("System Preflight", "deterministic", "block", "tool parameters target memory, startup, or OpenClaw configuration paths", 95, {
      paths: persistencePaths.slice(0, 8),
      monitor,
      isolation_plan: isolationPlan("block"),
    }));
  }

  const gatewayUrls = urls.filter((url) => NON_LOCAL_GATEWAY_PATTERN.test(url) || /gatewayURL/i.test(url));
  if (gatewayUrls.length) {
    risk.tool_hijack = 100;
    findings.push(finding("System Preflight", "deterministic", "block", "Control UI gateway URL override detected before network call", 100, {
      urls: gatewayUrls.slice(0, 6),
      monitor,
      isolation_plan: isolationPlan("block"),
    }));
  }

  findings.push(...kernelRuntimeGateFindings({
    toolName,
    normalized,
    command,
    paths,
    urls,
    sensitivePaths,
    persistencePaths,
    monitor,
    requireKernelObserver: Boolean(options.requireKernelObserverForHighRisk),
    unavailableAction: options.unavailableAction || "require_approval",
    previewChars,
  }));

  return {
    findings: dedupeFindings(findings),
    risk_vector: risk,
    status: monitor,
  };
}

function kernelRuntimeGateFindings(input: {
  toolName: string;
  normalized: string;
  command: string;
  paths: string[];
  urls: string[];
  sensitivePaths: string[];
  persistencePaths: string[];
  monitor: SystemMonitorStatus;
  requireKernelObserver: boolean;
  unavailableAction: RuntimeIsolationUnavailableAction;
  previewChars: number;
}): DetectionFinding[] {
  if (!input.requireKernelObserver) return [];
  const externalUrls = input.urls.filter((url) => isExternalUrl(url));
  const highRiskShell = Boolean(input.command && /shell|command|exec|terminal|powershell|cmd/.test(input.normalized) && !isLowRiskShellRead(input.command));
  const riskyFileMutation = /write|delete|remove|move|chmod|chown/.test(input.normalized)
    && input.paths.some((path) => path.startsWith("/") || path.includes("..") || SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(path)) || PERSISTENCE_PATH_PATTERNS.some((pattern) => pattern.test(path)));
  const guardedSurfaces = [
    highRiskShell ? "shell_exec" : "",
    externalUrls.length ? "network_egress" : "",
    input.sensitivePaths.length ? "sensitive_file_access" : "",
    input.persistencePaths.length ? "persistence_surface" : "",
    riskyFileMutation ? "file_mutation" : "",
  ].filter(Boolean);
  if (!guardedSurfaces.length) return [];

  const evidence = {
    toolName: input.toolName,
    guarded_surfaces: guardedSurfaces,
    command: input.command ? clampText(input.command, input.previewChars) : "",
    paths: input.paths.slice(0, 8),
    urls: externalUrls.slice(0, 8),
    monitor: input.monitor,
    runtime_gate: {
      required: true,
      reason: "high-risk runtime surface requires kernel-assisted audit before execution",
      unavailable_action: input.unavailableAction,
    },
  };

  if (input.monitor.ebpf === "attached") {
    return [finding("Runtime Isolation", "deterministic", "pass", "kernel eBPF observer attached for high-risk runtime surface", 0, evidence)];
  }

  const hardSurface = highRiskShell || input.sensitivePaths.length > 0 || input.persistencePaths.length > 0 || riskyFileMutation;
  const verdict: DetectionFinding["verdict"] = input.unavailableAction === "block" || hardSurface ? "block" : "require_approval";
  return [finding(
    "Runtime Isolation",
    "deterministic",
    verdict,
    "kernel eBPF observer is required before high-risk runtime surface can execute",
    verdict === "block" ? 95 : 45,
    evidence,
  )];
}

export function systemMonitorStatus(): SystemMonitorStatus {
  const observer = ebpfObserverStatus();
  if (observer.active) {
    return withIsolation({
      pre_exec_policy: "active",
      ebpf: "attached",
      reason: `AgentSentry eBPF observer is active via ${observer.detected_by}; kernel exec/open/connect events are written to ${observer.log_path}`,
      observer,
    });
  }

  const bpffs = existsSync("/sys/fs/bpf");
  const bpftoolPath = commandPath("bpftool", ["/usr/sbin/bpftool", "/sbin/bpftool", "/usr/bin/bpftool"]);
  const bpftool = bpftoolPath ? spawnSync(bpftoolPath, ["version"], { stdio: "ignore" }) : { status: 127 };
  const bpfWritable = canAccess("/sys/fs/bpf");
  const tracingReadable = canAccess("/sys/kernel/tracing") || canAccess("/sys/kernel/debug/tracing");
  const unprivileged = readKernelFlag("/proc/sys/kernel/unprivileged_bpf_disabled");
  if (bpffs && bpftool.status === 0 && typeof process.getuid === "function" && process.getuid() === 0 && bpfWritable && tracingReadable) {
    return withIsolation({ pre_exec_policy: "active", ebpf: "available", reason: "bpffs, tracefs and bpftool are available; root can attach probes", observer });
  }
  if (bpffs && bpftool.status === 0 && !bpfWritable) {
    return withIsolation({
      pre_exec_policy: "active",
      ebpf: "unavailable",
      reason: `bpffs and bpftool exist, but /sys/fs/bpf is not accessible to this user service and ${EBPF_OBSERVER_SERVICE} is not active${unprivileged ? `; unprivileged_bpf_disabled=${unprivileged}` : ""}`,
      observer,
    });
  }
  if (bpffs && bpftool.status === 0 && !tracingReadable) {
    return withIsolation({ pre_exec_policy: "active", ebpf: "unavailable", reason: `bpftool exists, but tracefs/debugfs is not accessible to this user service and ${EBPF_OBSERVER_SERVICE} is not active`, observer });
  }
  return withIsolation({ pre_exec_policy: "active", ebpf: "unavailable", reason: "kernel eBPF attachment tools are not available in this runtime", observer });
}

export function ebpfLogCheckpoint(): EbpfLogCheckpoint | null {
  const monitor = systemMonitorStatus();
  if (monitor.ebpf !== "attached" || !monitor.observer.log_exists) return null;
  try {
    const stats = statSync(EBPF_OBSERVER_LOG);
    return {
      log_path: EBPF_OBSERVER_LOG,
      size: stats.size,
      created_at: new Date().toISOString(),
      monitor,
    };
  } catch {
    return null;
  }
}

export function auditRuntimeEventsSince(
  checkpoint: EbpfLogCheckpoint | null,
  toolName: string,
  params: Record<string, unknown>,
  options: { previewChars?: number; maxBytes?: number; maxEvents?: number } = {},
): EbpfRuntimeAudit {
  const monitor = systemMonitorStatus();
  const previewChars = options.previewChars ?? 1200;
  const maxBytes = Math.max(4096, options.maxBytes ?? 512 * 1024);
  const maxEvents = Math.max(10, options.maxEvents ?? 400);
  if (!checkpoint || monitor.ebpf !== "attached") {
    return {
      enabled: false,
      monitor,
      checkpoint,
      scanned_bytes: 0,
      event_count: 0,
      interesting_events: [],
      findings: [],
    };
  }

  const { events, scannedBytes } = readEbpfEventsSince(checkpoint, maxBytes, maxEvents);
  const audit = auditEbpfEvents(events, toolName, params, monitor, previewChars);
  return {
    enabled: true,
    monitor,
    checkpoint,
    scanned_bytes: scannedBytes,
    event_count: events.length,
    interesting_events: audit.interestingEvents,
    findings: audit.findings,
  };
}

function readEbpfEventsSince(
  checkpoint: EbpfLogCheckpoint,
  maxBytes: number,
  maxEvents: number,
): { events: Array<Record<string, unknown>>; scannedBytes: number } {
  if (checkpoint.log_path !== EBPF_OBSERVER_LOG || !existsSync(EBPF_OBSERVER_LOG)) return { events: [], scannedBytes: 0 };
  try {
    const stats = statSync(EBPF_OBSERVER_LOG);
    if (stats.size <= checkpoint.size) return { events: [], scannedBytes: 0 };
    const available = stats.size - checkpoint.size;
    const length = Math.min(available, maxBytes);
    const offset = stats.size - length;
    const buffer = Buffer.alloc(length);
    const fd = openSync(EBPF_OBSERVER_LOG, "r");
    try {
      readSync(fd, buffer, 0, length, offset);
    } finally {
      closeSync(fd);
    }
    const lines = buffer.toString("utf8").split(/\r?\n/).filter((line) => line.trim().startsWith("{"));
    const parsed: Array<Record<string, unknown>> = [];
    for (const line of lines.slice(-maxEvents)) {
      try {
        const item = JSON.parse(line);
        if (item && typeof item === "object" && !Array.isArray(item)) parsed.push(item as Record<string, unknown>);
      } catch {
        // Ignore malformed observer lines; bpftrace can be interrupted mid-write.
      }
    }
    return { events: parsed, scannedBytes: length };
  } catch {
    return { events: [], scannedBytes: 0 };
  }
}

function auditEbpfEvents(
  events: Array<Record<string, unknown>>,
  toolName: string,
  params: Record<string, unknown>,
  monitor: SystemMonitorStatus,
  previewChars: number,
): { findings: DetectionFinding[]; interestingEvents: Array<Record<string, unknown>> } {
  const normalized = toolName.toLowerCase();
  const command = readFirstString(params, ["command", "cmd", "script", "shell", "input"]);
  const expectedPaths = collectPathLike(params);
  const shellTool = /shell|command|exec|terminal|powershell|cmd/.test(normalized);
  const lowRiskShell = shellTool && command ? isLowRiskShellRead(command) : false;
  const interestingEvents: Array<Record<string, unknown>> = [];
  const findings: DetectionFinding[] = [];

  const sensitiveOpenEvents = events
    .filter((event) => String(event.event || "") === "openat")
    .filter((event) => isRelevantComm(String(event.comm || "")))
    .map((event) => ({ event, filename: String(event.filename || "") }))
    .filter(({ filename }) => filename && !isBenignRuntimePath(filename) && isSensitiveRuntimePath(filename))
    .filter(({ filename }) => !expectedPaths.some((expected) => sameRuntimePathIntent(expected, filename)))
    .slice(0, 12);

  if (sensitiveOpenEvents.length) {
    interestingEvents.push(...sensitiveOpenEvents.map((item) => item.event));
    findings.push(finding("Runtime Isolation", "deterministic", "require_approval", "eBPF observed unexpected sensitive file access after tool was allowed", 80, {
      toolName,
      expected_paths: expectedPaths.slice(0, 8),
      observed_paths: sensitiveOpenEvents.map((item) => item.filename).slice(0, 8),
      monitor,
      runtime_audit: {
        source: "ebpf",
        event: "openat",
        policy: "high-confidence sensitive path only",
      },
    }));
  }

  const execEvents = events
    .filter((event) => String(event.event || "") === "execve")
    .filter((event) => isRelevantComm(String(event.comm || "")))
    .map((event) => ({ event, text: execEventText(event) }))
    .filter(({ text }) => isDangerousRuntimeExec(text))
    .slice(0, 12);

  const unexpectedExecEvents = execEvents.filter(({ text }) => !shellTool || (lowRiskShell && command && !text.includes(command)));
  if (unexpectedExecEvents.length) {
    interestingEvents.push(...unexpectedExecEvents.map((item) => item.event));
    findings.push(finding("Runtime Isolation", "deterministic", "require_approval", "eBPF observed unexpected process execution after non-shell or low-risk tool was allowed", 85, {
      toolName,
      command: command ? clampText(command, previewChars) : "",
      observed_exec: unexpectedExecEvents.map((item) => clampText(item.text, 240)).slice(0, 8),
      monitor,
      runtime_audit: {
        source: "ebpf",
        event: "execve",
        policy: "dangerous exec only; normal node/library activity ignored",
      },
    }));
  }

  return {
    findings: dedupeFindings(findings),
    interestingEvents: interestingEvents.slice(0, 20),
  };
}

function ebpfObserverStatus(): EbpfObserverStatus {
  const systemdActive = systemctlIsActive(EBPF_OBSERVER_SERVICE);
  const processActive = processIsActive("bpftrace .*agentsentry-ebpf-observer\\.bt");
  const log = observerLogInfo(EBPF_OBSERVER_LOG);
  return {
    service: EBPF_OBSERVER_SERVICE,
    active: systemdActive || processActive,
    detected_by: systemdActive ? "systemd" : processActive ? "process" : "none",
    script_path: EBPF_OBSERVER_SCRIPT,
    log_path: EBPF_OBSERVER_LOG,
    ...log,
  };
}

function systemctlIsActive(service: string): boolean {
  const systemctl = commandPath("systemctl", ["/usr/bin/systemctl", "/bin/systemctl"]);
  if (!systemctl) return false;
  try {
    return spawnSync(systemctl, ["is-active", "--quiet", service], { stdio: "ignore" }).status === 0;
  } catch {
    return false;
  }
}

function processIsActive(pattern: string): boolean {
  const pgrep = commandPath("pgrep", ["/usr/bin/pgrep", "/bin/pgrep"]);
  if (!pgrep) return false;
  try {
    return spawnSync(pgrep, ["-f", pattern], { stdio: "ignore" }).status === 0;
  } catch {
    return false;
  }
}

function observerLogInfo(path: string): Pick<EbpfObserverStatus, "log_exists" | "log_mtime" | "recent_events"> {
  if (!existsSync(path)) return { log_exists: false };
  try {
    const stats = statSync(path);
    const maxRead = 64 * 1024;
    const length = Math.min(stats.size, maxRead);
    const offset = Math.max(0, stats.size - length);
    const buffer = Buffer.alloc(length);
    const fd = openSync(path, "r");
    try {
      readSync(fd, buffer, 0, length, offset);
    } finally {
      closeSync(fd);
    }
    const tail = buffer.toString("utf8");
    const recentEvents = tail.split(/\r?\n/).filter((line) => line.trim().startsWith("{")).length;
    return {
      log_exists: true,
      log_mtime: stats.mtime.toISOString(),
      recent_events: recentEvents,
    };
  } catch {
    return { log_exists: true };
  }
}

function withIsolation(status: Omit<SystemMonitorStatus, "isolation">): SystemMonitorStatus {
  return {
    ...status,
    isolation: isolationStatus(status.ebpf),
  };
}

function isolationStatus(ebpf: SystemMonitorStatus["ebpf"]): SystemMonitorStatus["isolation"] {
  return {
    mode: ebpf === "available" || ebpf === "attached" ? "kernel-assisted" : "pre-exec",
    controls: [
      "tool-call preflight",
      "sensitive path denylist",
      "persistence surface denylist",
      "privileged command denylist",
      "gateway override denylist",
      "network egress review",
    ],
    limitations: ebpf === "available" || ebpf === "attached"
      ? ["kernel probes require privileged service deployment"]
      : ["kernel eBPF enforcement is unavailable to this user service", "post-exec syscall observation is not attached"],
    recommended_runtime: [
      "run OpenClaw tools as a low-privilege user",
      "mount workspace read-write and system paths read-only",
      "apply outbound network allowlist",
      "enable seccomp/AppArmor or eBPF observer when host policy permits",
    ],
  };
}

function isolationPlan(action: "block" | "review"): Record<string, unknown> {
  return {
    action,
    required_controls: action === "block"
      ? ["deny before execution", "do not pass command to shell/tool runtime"]
      : ["operator approval", "network egress allowlist", "capture full command and destination"],
    fallback: "application pre-exec policy remains authoritative when kernel observer is unavailable",
  };
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

function isExternalUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    return (parsed.protocol === "http:" || parsed.protocol === "https:" || parsed.protocol === "ws:" || parsed.protocol === "wss:")
      && host !== "localhost"
      && host !== "127.0.0.1"
      && host !== "::1"
      && host !== "[::1]"
      && !host.endsWith(".localhost");
  } catch {
    return false;
  }
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

function isRelevantComm(comm: string): boolean {
  return /^(node|bash|sh|zsh|python|python3|curl|wget|nc|ncat|socat)$/i.test(comm.trim());
}

function isBenignRuntimePath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/");
  return !normalized
    || normalized === "/dev/null"
    || normalized.startsWith("/usr/lib/")
    || normalized.startsWith("/lib/")
    || normalized.startsWith("/usr/share/locale/")
    || normalized.startsWith("/usr/share/nodejs/")
    || normalized.startsWith("/home/ubuntu/.openclaw/tools/node-")
    || normalized.includes("/node_modules/")
    || normalized.includes("/.codex/shell_snapshots/")
    || normalized === "/etc/ld.so.cache"
    || /\/LC_[A-Z_]+$/.test(normalized);
}

function isSensitiveRuntimePath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/");
  return SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(normalized))
    || /(?:^|\/)\.ssh(?:\/|$)/i.test(normalized)
    || /(?:^|\/)(?:openclaw\.json|runtime-config\.json|exec-approvals\.json)$/i.test(normalized)
    || /(?:^|\/)(?:\.env|\.npmrc|\.pypirc|credentials|credential|secrets?)(?:\.|$|\/)/i.test(normalized);
}

function sameRuntimePathIntent(expected: string, observed: string): boolean {
  if (!expected) return false;
  const normalizedExpected = expected.replace(/^file:\/\//, "").replace(/\\/g, "/");
  const normalizedObserved = observed.replace(/\\/g, "/");
  if (normalizedExpected === normalizedObserved) return true;
  if (!normalizedExpected.startsWith("/") && normalizedObserved.endsWith(`/${normalizedExpected.replace(/^\/+/, "")}`)) return true;
  return false;
}

function execEventText(event: Record<string, unknown>): string {
  return [event.argv0, event.argv1, event.argv2]
    .map((value) => typeof value === "string" ? value : "")
    .filter(Boolean)
    .join(" ");
}

function isDangerousRuntimeExec(text: string): boolean {
  return /\b(?:curl|wget)\b[\s\S]{0,160}\|\s*(?:bash|sh|zsh|python|node)\b/i.test(text)
    || /\b(?:curl|wget|nc|ncat|socat|scp|rsync)\b[\s\S]{0,180}(?:\.env|id_rsa|id_ed25519|openclaw\.json|token|secret|credential)/i.test(text)
    || /\b(?:bash|sh|zsh|python|python3|node)\s+-c\b/i.test(text)
    || /\b(?:sudo|chmod|chown|systemctl|service|crontab|iptables|ufw|docker)\b/i.test(text)
    || /\brm\s+-rf\b/i.test(text);
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
