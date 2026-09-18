const WORKSPACE_CONTEXT_BASENAMES = new Set([
  "agents.md",
  "soul.md",
  "user.md",
  "identity.md",
  "heartbeat.md",
  "tools.md",
  "memory.md",
  "bootstrap.md",
  "openclaw-workspace-state.json",
]);

const SKIP_CONTEXT_DIRS = /(^|\/)(skills|node_modules|dist|plugin-skills)\//;

export function isMutatingFileTool(toolName: string): boolean {
  return /write|delete|remove|move|chmod|chown|exec|shell|command|terminal|powershell|cmd/.test(String(toolName || "").toLowerCase());
}

export function isInsideOpenClawWorkspace(path: string): boolean {
  return /(?:^|\/)\.openclaw\/workspace(?:\/|$)/i.test(normalizePath(path));
}

export function isTrustedWorkspaceContextPath(path: string): boolean {
  const normalized = normalizePath(path);
  if (!normalized || SKIP_CONTEXT_DIRS.test(normalized)) return false;
  const base = normalized.split("/").pop() || "";
  if (WORKSPACE_CONTEXT_BASENAMES.has(base)) return true;
  return /(^|\/)memory\/[^/]+\.md$/i.test(normalized);
}

export function isTrustedWorkspaceContextRead(toolName: string, path: string, command = ""): boolean {
  if (command || isMutatingFileTool(toolName)) return false;
  return isTrustedWorkspaceContextPath(path);
}

export function isOpenClawConfigPersistencePath(path: string): boolean {
  const normalized = normalizePath(path);
  if (!normalized || isInsideOpenClawWorkspace(normalized)) return false;
  return /(?:^|\/)\.openclaw\/(?!workspace(?:\/|$))/i.test(normalized)
    || /(?:^|\/)openclaw\.json$/i.test(normalized);
}

function normalizePath(path: string): string {
  return String(path || "").replace(/\\/g, "/").toLowerCase();
}
