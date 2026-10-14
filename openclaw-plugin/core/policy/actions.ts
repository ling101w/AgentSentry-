import { isOpenClawMemoryDocumentPath } from "./action-assessment.ts";
import { readFirstString } from "./value-utils.ts";
import type { AgentSentryAction } from "./contracts.ts";
import { normalizeToolName } from "./support.ts";

export function normalizeAction(toolName: string, params: Record<string, unknown>): AgentSentryAction {
  const originalTool = typeof toolName === "string" && toolName.trim() ? toolName : "unknown_tool";
  let input: Record<string, unknown> = {};
  try {
    if (params && typeof params === "object" && !Array.isArray(params)) input = params;
  } catch {
    input = {};
  }
  let tool = normalizeToolName(originalTool);
  let args: Record<string, unknown>;
  try {
    args = normalizeArgs(tool, input);
  } catch {
    args = {};
  }
  tool = specializeStateTool(tool, args);
  const reason = typeof input.reason === "string" ? input.reason : "";
  return { tool, originalTool, args, reason };
}

function specializeStateTool(tool: string, args: Record<string, unknown>): string {
  const path = readFirstString(args, ["path", "file", "filename", "target"]);
  if (!isOpenClawMemoryDocumentPath(path)) return tool;
  if (tool === "read_file") return "memory_read";
  if (tool === "write_file") return "memory_write";
  return tool;
}

function normalizeArgs(tool: string, params: Record<string, unknown>): Record<string, unknown> {
  const args = { ...params };
  if (tool === "read_webpage" || tool === "call_api") {
    promote(args, "url", ["uri", "href", "target", "endpoint"]);
  }
  if (tool === "read_file" || tool === "write_file") {
    promote(args, "path", ["file", "filename", "target"]);
    // AgentDojo's workspace file tools address fixtures by file_id. Keep the
    // original id for audit/execution, but give policy a relative synthetic
    // path so it never resolves the id as a host absolute path or reports a
    // false workspace escape.
    if (!readFirstString(args, ["path"]) && typeof args.file_id === "string" && args.file_id.trim()) {
      args.path = `.agentsentry/agentdojo-files/${args.file_id.trim()}`;
    }
  }
  if (tool === "write_file") {
    const patch = readFirstString(args, ["input", "patch", "diff"]);
    if (patch) {
      if (!readFirstString(args, ["path"])) {
        const path = extractApplyPatchPath(patch);
        if (path) args.path = path;
      }
      if (!readFirstString(args, ["content", "body", "text"])) {
        const content = extractApplyPatchContent(patch);
        if (content) args.content = content;
      }
    }
  }
  if (tool === "send_email") {
    promote(args, "recipient", ["recipients", "to", "target", "email"]);
    promote(args, "body", ["content", "message", "text"]);
  }
  return args;
}

function extractApplyPatchPath(patch: string): string {
  const match = String(patch || "").match(/\*\*\*\s+(?:Add File|Update File|Delete File):\s+(\S+)/i);
  return match?.[1]?.trim() || "";
}

function extractApplyPatchContent(patch: string): string {
  return String(patch || "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1))
    .join("\n");
}

function promote(args: Record<string, unknown>, target: string, sources: string[]): void {
  if (args[target] !== undefined) return;
  for (const source of sources) {
    if (args[source] !== undefined) {
      args[target] = args[source];
      return;
    }
  }
}
