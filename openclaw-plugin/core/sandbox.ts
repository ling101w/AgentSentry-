import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { PluginConfig } from "../config.ts";

export type SandboxTransaction = {
  workspaceDir: string;
  tempDir: string;
  originalCommand: string;
  wrappedCommand: string;
  useBestEffortNetworkIsolation: boolean;
  requireNetworkIsolation: boolean;
  excludes: string[];
};

const DEFAULT_EXCLUDES = [".git", "node_modules", ".openclaw/agentsentry"];

export function shouldSandboxShellCommand(command: string): boolean {
  return Boolean(command.trim()) && !isLowRiskShellReadCommand(command);
}

export function createShellSandboxTransaction(
  config: PluginConfig,
  workspaceDir: string,
  command: string,
): SandboxTransaction | null {
  if (!workspaceDir || !existsSync(workspaceDir)) return null;
  if (!shouldSandboxShellCommand(command)) return null;

  const networkIsolationAvailable = canUseUnshare();
  if (config.runtimeIsolation.requireNetworkNamespaceForShell && !networkIsolationAvailable) return null;
  const tempDir = mkdtempSync(join(tmpdir(), "agentsentry-sandbox-"));
  const wrappedCommand = buildSandboxWrapperCommand({
    tempDir,
    workspaceDir: resolve(workspaceDir),
    command,
    excludes: DEFAULT_EXCLUDES,
    useBestEffortNetworkIsolation: networkIsolationAvailable,
    requireNetworkIsolation: config.runtimeIsolation.requireNetworkNamespaceForShell,
  });
  return {
    workspaceDir: resolve(workspaceDir),
    tempDir,
    originalCommand: command,
    wrappedCommand,
    useBestEffortNetworkIsolation: networkIsolationAvailable,
    requireNetworkIsolation: config.runtimeIsolation.requireNetworkNamespaceForShell,
    excludes: DEFAULT_EXCLUDES,
  };
}

export function materializeSandboxWorkspace(transaction: SandboxTransaction): void {
  rmSync(transaction.tempDir, { recursive: true, force: true });
  mkdirSync(transaction.tempDir, { recursive: true });
  copyDirectory(transaction.workspaceDir, transaction.tempDir, transaction.excludes);
}

export function commitSandboxWorkspace(transaction: SandboxTransaction): { committed: boolean; reason?: string } {
  try {
    if (!existsSync(transaction.tempDir)) return { committed: false, reason: "sandbox workspace missing" };
    syncDirectory(transaction.tempDir, transaction.workspaceDir, transaction.excludes);
    return { committed: true };
  } catch (error) {
    return { committed: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

export function discardSandboxWorkspace(transaction: SandboxTransaction): void {
  rmSync(transaction.tempDir, { recursive: true, force: true });
}

export function shellNetworkIsolationAvailable(): boolean {
  return canUseUnshare();
}

function buildSandboxWrapperCommand(input: {
  tempDir: string;
  workspaceDir: string;
  command: string;
  excludes: string[];
  useBestEffortNetworkIsolation: boolean;
  requireNetworkIsolation: boolean;
}): string {
  const plan = Buffer.from(JSON.stringify({
    tempDir: input.tempDir,
    workspaceDir: input.workspaceDir,
    command: input.command,
    excludes: input.excludes,
    useBestEffortNetworkIsolation: input.useBestEffortNetworkIsolation,
    requireNetworkIsolation: input.requireNetworkIsolation,
  }), "utf8").toString("base64url");
  const script = `
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
const plan = JSON.parse(Buffer.from(process.env.AGENTSENTRY_SANDBOX_PLAN || "", "base64url").toString("utf8"));
const excludes = new Set(plan.excludes || []);
function copyDirectory(source, target) {
  mkdirSync(target, { recursive: true });
  for (const entry of readdirSync(source, { withFileTypes: true })) {
    if (excludes.has(entry.name)) continue;
    const src = join(source, entry.name);
    const dest = join(target, entry.name);
    if (entry.isDirectory()) copyDirectory(src, dest);
    else if (entry.isSymbolicLink()) continue;
    else cpSync(src, dest, { force: true });
  }
}
function removeMissing(source, target) {
  if (!existsSync(target)) return;
  for (const entry of readdirSync(target, { withFileTypes: true })) {
    if (excludes.has(entry.name)) continue;
    const src = join(source, entry.name);
    const dest = join(target, entry.name);
    if (!existsSync(src)) {
      rmSync(dest, { recursive: true, force: true });
      continue;
    }
    if (entry.isDirectory()) removeMissing(src, dest);
  }
}
function syncTree(source, target) {
  copyDirectory(source, target);
  removeMissing(source, target);
}
rmSync(plan.tempDir, { recursive: true, force: true });
mkdirSync(plan.tempDir, { recursive: true });
copyDirectory(plan.workspaceDir, plan.tempDir);
const command = plan.command;
if (plan.requireNetworkIsolation && !plan.useBestEffortNetworkIsolation) {
  console.error("AgentSentry strict network namespace isolation is unavailable");
  process.exit(126);
}
const shellCommand = plan.useBestEffortNetworkIsolation && process.platform !== "win32"
  ? ["unshare", ["-n", "--", "/bin/bash", "-lc", command]]
  : ["/bin/bash", ["-lc", command]];
const result = spawnSync(shellCommand[0], shellCommand[1], {
  cwd: plan.tempDir,
  env: { ...process.env, PWD: plan.tempDir, AGENTSENTRY_SANDBOX_TEMP_DIR: plan.tempDir, AGENTSENTRY_SANDBOX_WORKSPACE_DIR: plan.workspaceDir },
  encoding: "utf8",
  stdio: "inherit",
});
process.exit(typeof result.status === "number" ? result.status : 1);
`;
  return `AGENTSENTRY_SANDBOX_PLAN=${shellEscape(plan)} node --input-type=module -e ${shellEscape(script)}`;
}

function syncDirectory(source: string, target: string, excludes: string[]): void {
  copyDirectory(source, target, excludes);
  removeMissing(source, target, excludes);
}

function copyDirectory(source: string, target: string, excludes: string[]): void {
  mkdirSync(target, { recursive: true });
  const excluded = new Set(excludes);
  for (const entry of readdirSync(source, { withFileTypes: true })) {
    if (excluded.has(entry.name)) continue;
    const src = join(source, entry.name);
    const dest = join(target, entry.name);
    if (entry.isDirectory()) {
      copyDirectory(src, dest, excludes);
    } else if (entry.isSymbolicLink()) {
      continue;
    } else {
      cpSync(src, dest, { force: true });
    }
  }
}

function removeMissing(source: string, target: string, excludes: string[]): void {
  if (!existsSync(target)) return;
  const excluded = new Set(excludes);
  for (const entry of readdirSync(target, { withFileTypes: true })) {
    if (excluded.has(entry.name)) continue;
    const src = join(source, entry.name);
    const dest = join(target, entry.name);
    if (!existsSync(src)) {
      rmSync(dest, { recursive: true, force: true });
      continue;
    }
    if (entry.isDirectory()) removeMissing(src, dest, excludes);
  }
}

function shellEscape(text: string): string {
  return `'${text.replace(/'/g, `'\\''`)}'`;
}

function canUseUnshare(): boolean {
  const probe = spawnSync("unshare", ["-n", "--", "true"], { stdio: "ignore" });
  return probe.status === 0;
}

function isLowRiskShellReadCommand(command: string): boolean {
  const normalized = command.trim().toLowerCase();
  if (!normalized) return false;
  if (/[;&|`$><]/.test(normalized)) return false;
  return /^(pwd|whoami|id|hostname|uname(?:\s+-a)?|uptime|ls(?:\s+-la)?(?:\s+[\w./-]+)?|cat\s+\/etc\/(?:os-release|hostname|hosts)|df(?:\s+-h)?|free(?:\s+-h)?|env)$/i.test(normalized);
}
