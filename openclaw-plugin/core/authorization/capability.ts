import { isAbsolute, relative, resolve } from "node:path";
import { readFirstString } from "../adapters/openclaw-tools.ts";
import { targetMatches } from "../security/url.ts";
import { authorizationPath } from "./graph.ts";
import type { AgentSentryAction, Capability, TaskSpec } from "../policy/types.ts";

export type CapabilityCheck = {
  allowed: boolean;
  required: Capability["kind"] | null;
  reason: string;
  graphPath: string[];
};

export function requiredCapability(action: AgentSentryAction): Capability | null {
  if (action.tool === "read_file") {
    return { kind: "fs.read", roots: [readFirstString(action.args, ["path", "file", "filename", "target"])] };
  }
  if (action.tool === "write_file") {
    return { kind: "fs.write", roots: [readFirstString(action.args, ["path", "file", "filename", "target"])] };
  }
  if (action.tool === "read_webpage" || action.tool === "call_api" || action.tool === "web_search") {
    return { kind: "network.fetch", origins: [readFirstString(action.args, ["url", "href", "endpoint", "target"])] };
  }
  if (action.tool === "send_email") {
    return { kind: "email.send", recipients: [readFirstString(action.args, ["recipient", "to", "target", "email"]).toLowerCase()] };
  }
  if (action.tool === "memory_read") return { kind: "memory.read", namespace: memoryNamespace(action) };
  if (action.tool === "memory_write") return { kind: "memory.write", namespace: memoryNamespace(action) };
  if (action.tool === "shell_exec") return { kind: "execution.shell" };
  return null;
}

export function checkCapability(action: AgentSentryAction, taskSpec: TaskSpec): CapabilityCheck {
  const required = requiredCapability(action);
  if (!required) return { allowed: true, required: null, reason: "", graphPath: [] };
  const candidates = taskSpec.capabilities.filter((item) => item.kind === required.kind);
  const scope = requiredScope(required);
  const graphPath = authorizationPath(taskSpec.authorization_graph, required.kind, scope);
  if (!candidates.length) {
    return { allowed: false, required: required.kind, reason: `capability ${required.kind} was not granted by the user`, graphPath };
  }
  const allowed = candidates.some((candidate) => capabilityContains(candidate, required));
  return {
    allowed,
    required: required.kind,
    reason: allowed ? "" : `action exceeds granted ${required.kind} capability scope`,
    graphPath,
  };
}

function requiredScope(capability: Capability): string {
  if (capability.kind === "fs.read" || capability.kind === "fs.write") return capability.roots[0] || "";
  if (capability.kind === "network.fetch") return capability.origins[0] || "";
  if (capability.kind === "email.send") return capability.recipients?.[0] || "";
  if (capability.kind === "memory.read" || capability.kind === "memory.write") return capability.namespace;
  return "";
}

export function capabilityContains(granted: Capability, required: Capability): boolean {
  if (granted.kind !== required.kind) return false;
  if (granted.kind === "execution.shell") return true;
  if (granted.kind === "email.send" && required.kind === "email.send") {
    const recipients = granted.recipients;
    const target = required.recipients?.[0] || "";
    return !recipients?.length || recipients.includes(target);
  }
  if (granted.kind === "network.fetch" && required.kind === "network.fetch") {
    const target = required.origins[0] || "";
    return granted.origins.some((origin) => origin === "*" || targetMatches(target, origin));
  }
  if ((granted.kind === "fs.read" || granted.kind === "fs.write") && (required.kind === "fs.read" || required.kind === "fs.write")) {
    const target = required.roots[0] || "";
    return Boolean(target) && granted.roots.some((root) => pathWithinScope(target, root));
  }
  if ((granted.kind === "memory.read" || granted.kind === "memory.write") && (required.kind === "memory.read" || required.kind === "memory.write")) {
    return granted.namespace === "*" || granted.namespace === required.namespace;
  }
  return false;
}

export function toolsForCapabilities(capabilities: Capability[]): string[] {
  const tools: string[] = [];
  for (const capability of capabilities) {
    if (capability.kind === "fs.read") tools.push("read_file");
    if (capability.kind === "fs.write") tools.push("write_file");
    if (capability.kind === "network.fetch") tools.push("read_webpage", "call_api", "web_search");
    if (capability.kind === "email.send") tools.push("send_email");
    if (capability.kind === "memory.read") tools.push("memory_read");
    if (capability.kind === "memory.write") tools.push("memory_write");
    if (capability.kind === "execution.shell") tools.push("shell_exec");
  }
  return Array.from(new Set(tools));
}

function pathWithinScope(target: string, scope: string): boolean {
  if (!scope || scope === "." || scope === "*") return true;
  const normalizedTarget = target.replace(/\\/g, "/").replace(/\/$/, "");
  const normalizedScope = scope.replace(/\\/g, "/").replace(/\/$/, "");
  if (normalizedTarget.toLowerCase() === normalizedScope.toLowerCase()) return true;
  if (!isAbsolute(target) && !isAbsolute(scope)) {
    return normalizedTarget.toLowerCase().startsWith(`${normalizedScope.toLowerCase()}/`);
  }
  try {
    const rel = relative(resolve(scope), resolve(target));
    return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
  } catch {
    return false;
  }
}

function memoryNamespace(action: AgentSentryAction): string {
  return readFirstString(action.args, ["namespace", "key", "path", "file", "filename"]) || "*";
}
