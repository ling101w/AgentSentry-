import { existsSync, readFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import type { PluginConfig } from "../../config.ts";
import { pathWithinRoot, matchAllowedWritePath } from "../../core/path-security.ts";
function repoRoot(): string {
  const configured = process.env.AGENTSENTRY_REPO_ROOT;
  if (configured) return resolve(configured);
  const cwd = resolve(process.cwd());
  const candidates = [
    resolve(fileURLToPath(new URL("../../..", import.meta.url))),
    resolve(fileURLToPath(new URL("../../../..", import.meta.url))),
    cwd,
  ];
  for (const candidate of candidates) {
    if (existsSync(join(candidate, "pyproject.toml")) && existsSync(join(candidate, "openclaw-plugin"))) return candidate;
  }
  if (existsSync(join(cwd, "openclaw-workspace")) || existsSync(join(cwd, "src")) || existsSync(join(cwd, "README.md"))) return cwd;
  const knownWorkspace = "/home/ubuntu/AgentSentry-";
  if (existsSync(join(knownWorkspace, "README.md"))) return knownWorkspace;
  return resolve(process.cwd());
}

export function toolStateDir(): string {
  return resolve(process.env.AGENTSENTRY_TOOL_STATE_DIR || join(process.env.HOME || repoRoot(), ".openclaw", "agentsentry", "business-tools"));
}

export function openClawWorkspaceRoot(): string {
  const configuredConfig = process.env.AGENTSENTRY_OPENCLAW_CONFIG || join(process.env.HOME || "", ".openclaw", "openclaw.json");
  try {
    if (configuredConfig && existsSync(configuredConfig)) {
      const parsed = JSON.parse(readFileSync(configuredConfig, "utf8")) as Record<string, unknown>;
      const agents = parsed.agents && typeof parsed.agents === "object" ? parsed.agents as Record<string, unknown> : {};
      const defaults = agents.defaults && typeof agents.defaults === "object" ? agents.defaults as Record<string, unknown> : {};
      const workspace = typeof defaults.workspace === "string" ? defaults.workspace.trim() : "";
      if (workspace) {
        if (workspace.startsWith("~/")) return resolve(join(process.env.HOME || "", workspace.slice(2)));
        return resolve(workspace);
      }
    }
  } catch {
    // Keep lab tooling available even when OpenClaw config is temporarily being rewritten.
  }
  return join(repoRoot(), "openclaw-workspace");
}

function readRoot(): string {
  return openClawWorkspaceRoot();
}

function writeRoot(): string {
  return resolve(process.env.AGENTSENTRY_WRITE_ROOT || openClawWorkspaceRoot());
}

export function resolveReadPath(requestedPath: string): string {
  const root = readRoot();
  const filePath = isAbsolute(requestedPath) ? resolve(requestedPath) : resolve(root, requestedPath);
  const boundary = pathWithinRoot(filePath, root, "read");
  if (!boundary.allowed) throw new Error(`read path is outside workspace: ${requestedPath}`);
  if (!existsSync(boundary.target)) {
    throw new Error(`file not found: ${requestedPath}`);
  }
  return boundary.target;
}

export function resolveWritePath(requestedPath: string, config: PluginConfig): string {
  const root = writeRoot();
  mkdirSync(root, { recursive: true });
  const filePath = isAbsolute(requestedPath) ? resolve(requestedPath) : resolve(root, requestedPath);
  const workspaceBoundary = pathWithinRoot(filePath, root);
  if (!workspaceBoundary.allowed) throw new Error(`write path is outside allowed workspace: ${requestedPath}`);
  if (config.policy.restrictWritesToAllowedRoots) {
    const allowedRoots = config.policy.allowedWriteRoots.map((item) => isAbsolute(item) ? item : resolve(root, item));
    const allowlistBoundary = matchAllowedWritePath(workspaceBoundary.target, allowedRoots, root);
    if (!allowlistBoundary.allowed) throw new Error(allowlistBoundary.reason || `write path is outside configured allowed roots: ${requestedPath}`);
    return allowlistBoundary.target;
  }
  return workspaceBoundary.target;
}

export function ensureParent(filePath: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
}

export function firstParam(params: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = params[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

export function stringifyValue(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

export function clipObject(value: Record<string, unknown>, previewChars: number): Record<string, unknown> {
  const clipped: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === "string") clipped[key] = clip(item, previewChars);
    else clipped[key] = item;
  }
  return clipped;
}

export function clip(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, Math.max(0, maxChars - 20))}...[truncated]`;
}
