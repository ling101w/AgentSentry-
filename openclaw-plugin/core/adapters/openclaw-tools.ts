import type { AgentSentryAction, Label } from "../policy/types.ts";

const TOOL_ALIASES: Array<[RegExp, string]> = [
  [/^(browser\.open|browser_open|open_browser|fetch_url|web\.open|read_webpage)$/i, "read_webpage"],
  [/^(read|open)$/i, "read_file"],
  [/^(write|create|edit|replace|patch)$/i, "write_file"],
  [/(read|open|parse).*(email|mail)|email.*read|mail.*read/i, "read_webpage"],
  [/(read|parse|summarize).*pdf|pdf.*(read|parse|summarize)/i, "read_webpage"],
  [/(analy[sz]e|read|parse).*(image|picture|photo|ocr)|image.*(ocr|read|analy[sz]e)/i, "read_webpage"],
  [/(read|cat|get).*file|filesystem.*read/i, "read_file"],
  [/(write|create|edit).*file|filesystem.*write|apply_patch/i, "write_file"],
  [/(send).*email|mail/i, "send_email"],
  [/(fetch|request|http|api|curl|wget|browser)/i, "call_api"],
  [/(webhook|hooks?[./_-]?wake|wake_hook)/i, "memory_write"],
  [/(memory|remember).*write|write.*memory/i, "memory_write"],
  [/(memory|remember).*read|read.*memory/i, "memory_read"],
  [/(shell|command|exec|terminal|powershell|cmd)/i, "shell_exec"],
];

export function normalizeAction(toolName: string, params: Record<string, unknown>): AgentSentryAction {
  let tool = normalizeToolName(toolName);
  const args = normalizeArgs(tool, params);
  tool = specializeStateTool(tool, args);
  return { tool, originalTool: toolName, args, reason: typeof params.reason === "string" ? params.reason : "" };
}

export function readFirstString(args: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string") return value;
    if (isLabeledValue(value)) {
      const unwrapped = flattenText(value.value).trim();
      if (unwrapped) return unwrapped;
    }
  }
  return "";
}

export function flattenText(value: unknown): string {
  if (isLabeledValue(value)) return flattenText(value.value);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(flattenText).join(" ");
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (typeof obj.text === "string") return obj.text;
    if (typeof obj.content === "string") return obj.content;
    return Object.values(obj).map(flattenText).join(" ");
  }
  return value === undefined || value === null ? "" : String(value);
}

export function isLabeledValue(value: unknown): value is { value: unknown; label: Label; provenance?: { source_node: string; match: string } } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const obj = value as Record<string, unknown>;
  const label = obj.label as Record<string, unknown> | undefined;
  return obj.value !== undefined && Boolean(label && typeof label === "object" && typeof label.integrity === "string");
}

export function isControlArg(name: string): boolean {
  return /^(timeout|timeoutms|max_?tokens?|limit|page|pagesize|offset|cursor|count|retries|retry|temperature|top_p|stream)$/i.test(name);
}

export function isOpenClawMemoryDocumentPath(value: string): boolean {
  const normalized = value.replace(/\\/g, "/").toLowerCase();
  return /(^|\/)(memory\.md|soul\.md|user\.md)$/i.test(normalized) || /(^|\/)memory\/[^/]+\.md$/i.test(normalized);
}

function specializeStateTool(tool: string, args: Record<string, unknown>): string {
  const path = readFirstString(args, ["path", "file", "filename", "target"]);
  if (!isOpenClawMemoryDocumentPath(path)) return tool;
  if (tool === "read_file") return "memory_read";
  if (tool === "write_file") return "memory_write";
  return tool;
}

function normalizeToolName(toolName: string): string {
  for (const [pattern, mapped] of TOOL_ALIASES) if (pattern.test(toolName)) return mapped;
  return toolName;
}

function normalizeArgs(tool: string, params: Record<string, unknown>): Record<string, unknown> {
  const args = { ...params };
  if (tool === "read_webpage" || tool === "call_api") promote(args, "url", ["uri", "href", "target", "endpoint"]);
  if (tool === "read_file" || tool === "write_file") promote(args, "path", ["file", "filename", "target"]);
  if (tool === "send_email") {
    promote(args, "recipient", ["to", "target", "email"]);
    promote(args, "body", ["content", "message", "text"]);
  }
  return args;
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
