import type { PluginConfig } from "../config.ts";

type CommandContext = {
  args?: string;
};

type CommandRuntime = {
  dashboardUrl: string;
  recordsPath: string;
  runtimeConfigPath: string;
  approvalCachePath: string;
  sessionCount: number;
  approvalCacheCount: number;
  resetRecords: () => void;
  clearFoundationCache: () => void;
  clearApprovalCache: () => void;
  setConfig: (config: PluginConfig) => void;
  persistConfig: (config: PluginConfig) => void;
  resetRuntimeConfig: () => void;
};

const WRITABLE_PREFIXES = [
  "capture.",
  "detection.",
  "semantic.",
  "foundationScan.",
  "policy.",
  "enforcement.",
  "notifications.",
  "responseCover.",
];

export function handleAgentSentryCommand(
  ctx: CommandContext,
  config: PluginConfig,
  startupConfig: PluginConfig,
  runtime: CommandRuntime,
): { text: string } {
  const tokens = tokenize(ctx.args || "");
  if (!tokens.length || tokens[0] === "status") {
    return { text: formatStatus(config, runtime) };
  }

  if (tokens[0] === "reset") {
    runtime.resetRecords();
    return { text: "AgentSentry records cleared." };
  }

  if (tokens[0] === "approvals") {
    const action = tokens[1] || "status";
    if (action === "status") {
      return { text: `AgentSentry approval cache: ${runtime.approvalCacheCount} exact operation(s).` };
    }
    if (action === "reset") {
      runtime.clearApprovalCache();
      return { text: "AgentSentry approval cache cleared." };
    }
    return { text: "Usage: /agentsentry approvals [status|reset]" };
  }

  if (tokens[0] !== "config") {
    return { text: usage() };
  }

  const action = tokens[1];
  if (action === "get") {
    const key = tokens[2];
    if (!key) return { text: `AgentSentry Configuration:\n${formatConfigTree(config)}` };
    const value = getAtPath(config, key);
    return value === undefined ? { text: `Config key not found: ${key}` } : { text: `${key} = ${JSON.stringify(value)}` };
  }

  if (action === "set") {
    const key = tokens[2];
    const rawValue = tokens.slice(3).join(" ");
    if (!key || rawValue === "") return { text: "Usage: /agentsentry config set <key> <value>" };
    if (!isWritablePath(config, key)) return { text: `Invalid or read-only config path: ${key}` };

    const existing = getAtPath(config, key);
    const parsed = parseValue(rawValue, existing);
    if (!isTypeCompatible(existing, parsed)) {
      return { text: `Type mismatch for ${key}: expected ${typeName(existing)}, got ${typeName(parsed)}.` };
    }
    if (!setAtPath(config, key, parsed)) return { text: `Failed to set config path: ${key}` };
    runtime.setConfig(config);
    runtime.persistConfig(config);
    if (key.startsWith("foundationScan.") || key.startsWith("policy.") || key.startsWith("semantic.")) runtime.clearFoundationCache();
    return { text: `${key} set to ${JSON.stringify(parsed)}\nPersisted: ${runtime.runtimeConfigPath}` };
  }

  if (action === "reset") {
    copyWritableConfig(startupConfig, config);
    runtime.setConfig(config);
    runtime.resetRuntimeConfig();
    runtime.clearFoundationCache();
    return { text: "AgentSentry runtime configuration reset to startup values." };
  }

  return { text: usage() };
}

export function formatStatus(config: PluginConfig, runtime: CommandRuntime): string {
  return [
    "AgentSentry is active.",
    `Dashboard: ${runtime.dashboardUrl}`,
    `Records: ${runtime.recordsPath}`,
    `Runtime config: ${runtime.runtimeConfigPath}`,
    `Approval cache file: ${runtime.approvalCachePath}`,
    `Sessions: ${runtime.sessionCount}`,
    `Approval cache: ${runtime.approvalCacheCount} exact operation(s)`,
    `Enforcement: ${config.enforcement.mode}`,
    `Foundation scan: ${config.foundationScan.enabled ? "enabled" : "disabled"}`,
    `Detection: ${config.detection.enabled ? "enabled" : "disabled"}`,
    `Semantic judge: ${config.semantic.enabled ? `${config.semantic.model} (${config.semantic.apiKeyEnv})` : "disabled"}`,
    `Notifications: ${config.notifications.enableProactiveNotifications ? config.notifications.minSeverity : "disabled"}`,
    `Response cover: ${config.responseCover.enabled ? "enabled" : "disabled"}`,
    "Commands:",
    "  /agentsentry status",
    "  /agentsentry config get [key]",
    "  /agentsentry config set <key> <value>",
    "  /agentsentry config reset",
    "  /agentsentry approvals [status|reset]",
    "  /agentsentry reset",
  ].join("\n");
}

function usage(): string {
  return [
    "Usage:",
    "  /agentsentry status",
    "  /agentsentry config get [key]",
    "  /agentsentry config set <key> <value>",
    "  /agentsentry config reset",
    "  /agentsentry approvals [status|reset]",
    "  /agentsentry reset",
  ].join("\n");
}

function tokenize(value: string): string[] {
  return value.trim().split(/\s+/).filter(Boolean);
}

function listLeafPaths(obj: unknown, prefix = ""): string[] {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return [];
  const paths: string[] = [];
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === "object" && !Array.isArray(value)) {
      paths.push(...listLeafPaths(value, path));
    } else {
      paths.push(path);
    }
  }
  return paths;
}

function formatConfigTree(config: PluginConfig): string {
  return listLeafPaths(config)
    .filter((path) => isWritablePath(config, path))
    .map((path) => `  ${path}: ${JSON.stringify(getAtPath(config, path))}`)
    .join("\n");
}

function getAtPath(obj: unknown, path: string): unknown {
  const parts = path.split(".");
  let current = obj;
  for (const part of parts) {
    if (!current || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function setAtPath(obj: unknown, path: string, value: unknown): boolean {
  const parts = path.split(".");
  let current = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!current || typeof current !== "object") return false;
    current = (current as Record<string, unknown>)[parts[i]];
  }
  if (!current || typeof current !== "object") return false;
  (current as Record<string, unknown>)[parts[parts.length - 1]] = value;
  return true;
}

function isWritablePath(config: PluginConfig, path: string): boolean {
  if (!WRITABLE_PREFIXES.some((prefix) => path.startsWith(prefix))) return false;
  const value = getAtPath(config, path);
  return value === null || ["boolean", "number", "string"].includes(typeof value) || Array.isArray(value);
}

function parseValue(raw: string, existing: unknown): unknown {
  if (Array.isArray(existing)) {
    const trimmed = raw.trim();
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) return parsed;
      } catch {
        // fall through to comma parsing
      }
    }
    return trimmed.split(",").map((item) => item.trim()).filter(Boolean);
  }
  if (typeof existing === "boolean") return raw === "true";
  if (typeof existing === "number") return Number(raw);
  return raw;
}

function isTypeCompatible(existing: unknown, parsed: unknown): boolean {
  if (Array.isArray(existing)) return Array.isArray(parsed) && parsed.every((item) => typeof item === "string");
  if (typeof existing === "boolean") return typeof parsed === "boolean";
  if (typeof existing === "number") return typeof parsed === "number" && Number.isFinite(parsed);
  if (typeof existing === "string") return typeof parsed === "string";
  return false;
}

function typeName(value: unknown): string {
  return Array.isArray(value) ? "array" : typeof value;
}

function copyWritableConfig(from: PluginConfig, to: PluginConfig): void {
  for (const path of listLeafPaths(to).filter((item) => isWritablePath(to, item))) {
    const value = getAtPath(from, path);
    setAtPath(to, path, Array.isArray(value) ? [...value] : value);
  }
}
