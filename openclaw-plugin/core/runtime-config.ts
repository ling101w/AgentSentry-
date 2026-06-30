import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { PluginConfig } from "../config.ts";

export function runtimeConfigPath(config: PluginConfig): string {
  const stateDir = config.storage.stateDir || process.env.OPENCLAW_STATE_DIR?.trim() || join(homedir(), ".openclaw");
  return join(stateDir, "agentsentry", "runtime-config.json");
}

export function loadRuntimeConfig(baseConfig: PluginConfig): PluginConfig {
  const path = runtimeConfigPath(baseConfig);
  if (!existsSync(path)) return baseConfig;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8"));
    applyConfigOverlay(baseConfig, raw);
  } catch {
    // Ignore malformed runtime config and keep OpenClaw/plugin defaults.
  }
  return baseConfig;
}

export function saveRuntimeConfig(config: PluginConfig): void {
  const path = runtimeConfigPath(config);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(config, null, 2) + "\n", "utf8");
}

export function deleteRuntimeConfig(config: PluginConfig): void {
  rmSync(runtimeConfigPath(config), { force: true });
}

function applyConfigOverlay(target: PluginConfig, overlay: unknown): void {
  if (!overlay || typeof overlay !== "object" || Array.isArray(overlay)) return;
  for (const path of listLeafPaths(target)) {
    const current = getAtPath(target, path);
    const next = getAtPath(overlay, path);
    if (next === undefined) continue;
    if (!isTypeCompatible(current, next)) continue;
    setAtPath(target, path, Array.isArray(next) ? [...next] : next);
  }
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

function isTypeCompatible(existing: unknown, next: unknown): boolean {
  if (Array.isArray(existing)) return Array.isArray(next) && next.every((item) => typeof item === "string");
  if (typeof existing === "boolean") return typeof next === "boolean";
  if (typeof existing === "number") return typeof next === "number" && Number.isFinite(next);
  if (typeof existing === "string") return typeof next === "string";
  return false;
}
