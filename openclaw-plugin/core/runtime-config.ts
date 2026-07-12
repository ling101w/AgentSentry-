import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { applySecurityProfile, isSecurityProfileName, PluginConfig } from "../config.ts";

const MAX_RUNTIME_CONFIG_BYTES = 1024 * 1024;
const INVALID_VALUE = Symbol("invalid-runtime-config-value");
let knownConfigLeafPaths: readonly string[] | undefined;

const ENUM_VALUES: Readonly<Record<string, readonly string[]>> = {
  profile: ["observe", "balanced", "competition", "high-security"],
  "semantic.mode": ["off", "risk-tiered", "full"],
  "runtimeIsolation.unavailableAction": ["require_approval", "block"],
  "enforcement.mode": ["observe", "approval", "block"],
  "notifications.minSeverity": ["warning", "danger"],
};

export function runtimeConfigPath(config: PluginConfig): string {
  const configuredStateDir = config.storage.stateDir.trim();
  const stateDir = configuredStateDir || process.env.OPENCLAW_STATE_DIR?.trim() || join(homedir(), ".openclaw");
  return join(stateDir, "agentsentry", "runtime-config.json");
}

export function loadRuntimeConfig(baseConfig: PluginConfig): PluginConfig {
  const path = runtimeConfigPath(baseConfig);
  if (!existsSync(path)) return baseConfig;
  try {
    if (statSync(path).size > MAX_RUNTIME_CONFIG_BYTES) return baseConfig;
    const raw = JSON.parse(readFileSync(path, "utf8"));
    applyConfigOverlay(baseConfig, raw);
  } catch {
    // Ignore malformed runtime config and keep OpenClaw/plugin defaults.
  }
  return baseConfig;
}

export function saveRuntimeConfig(config: PluginConfig): void {
  const path = runtimeConfigPath(config);
  const tempPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const snapshot = new PluginConfig();
  applyConfigOverlay(snapshot, config);
  const contents = JSON.stringify(snapshot, null, 2) + "\n";

  mkdirSync(dirname(path), { recursive: true });
  try {
    writeFileSync(tempPath, contents, { encoding: "utf8", flag: "wx", mode: 0o600 });
    renameSync(tempPath, path);
  } catch (error) {
    try {
      rmSync(tempPath, { force: true });
    } catch {
      // Preserve the original persistence error if temporary-file cleanup also fails.
    }
    throw error;
  }
}

export function deleteRuntimeConfig(config: PluginConfig): void {
  rmSync(runtimeConfigPath(config), { force: true });
}

function applyConfigOverlay(target: PluginConfig, overlay: unknown): void {
  if (!overlay || typeof overlay !== "object" || Array.isArray(overlay)) return;

  const profile = getAtPath(overlay, "profile");
  const normalizedProfile = typeof profile === "string" ? profile.trim() : "";
  if (isSecurityProfileName(normalizedProfile)) {
    applySecurityProfile(target, normalizedProfile);
  }

  for (const path of getKnownConfigLeafPaths()) {
    const current = getAtPath(target, path);
    const next = getAtPath(overlay, path);
    if (next === undefined) continue;
    const normalized = normalizeValue(path, current, next);
    if (normalized === INVALID_VALUE) continue;
    setAtPath(target, path, normalized);
  }

  if (target.detection.askThreshold >= target.detection.denyThreshold) {
    target.detection.askThreshold = Math.max(1, target.detection.denyThreshold - 10);
  }
}

function getKnownConfigLeafPaths(): readonly string[] {
  knownConfigLeafPaths ??= listLeafPaths(new PluginConfig());
  return knownConfigLeafPaths;
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

function getAtPath(obj: unknown, path: string): unknown {
  const parts = path.split(".");
  let current = obj;
  for (const part of parts) {
    if (!current || typeof current !== "object") return undefined;
    if (!Object.hasOwn(current, part)) return undefined;
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

function normalizeValue(path: string, existing: unknown, next: unknown): unknown | typeof INVALID_VALUE {
  if (Array.isArray(existing)) {
    if (!Array.isArray(next) || next.some((item) => typeof item !== "string" || !item.trim())) return INVALID_VALUE;
    return Array.from(new Set(next.map((item) => (item as string).trim())));
  }
  if (typeof existing === "boolean") return typeof next === "boolean" ? next : INVALID_VALUE;
  if (typeof existing === "number") {
    if (typeof next !== "number" || !Number.isFinite(next)) return INVALID_VALUE;
    const normalized = Math.trunc(next);
    return normalized > 0 ? normalized : INVALID_VALUE;
  }
  if (typeof existing === "string") {
    if (typeof next !== "string") return INVALID_VALUE;
    const normalized = next.trim();
    const allowedValues = ENUM_VALUES[path];
    if (allowedValues && !allowedValues.includes(normalized)) return INVALID_VALUE;
    return normalized;
  }
  return INVALID_VALUE;
}
