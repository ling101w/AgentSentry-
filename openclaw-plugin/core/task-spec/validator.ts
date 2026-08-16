import type {
  CapabilityActionRequest,
  CapabilityAuthorization,
  TaskCapability,
  TaskSpec,
} from "./types.ts";
import { posix } from "node:path";
import { hostFromUrl, targetMatches } from "../security/url.ts";
import { isLowRiskShellReadCommand } from "../policy/safe-ops.ts";
import { flattenText, isLabeledValue } from "../policy/value-utils.ts";

const SIDE_EFFECT_TOOLS = new Set([
  "write_file",
  "send_email",
  "call_api",
  "shell_exec",
  "memory_write",
  "calendar_write",
  "cloud_file_write",
  "cloud_file_share",
]);

export function authorizeCapability(
  spec: TaskSpec,
  request: CapabilityActionRequest,
  context: { taskMode?: TaskSpec["task_mode"] } = {},
): CapabilityAuthorization {
  const tool = request.tool;
  if (spec.denied_tools.includes(tool)) {
    return denied("explicit_user_denial");
  }

  const descriptor = descriptorFor(request);
  if (!descriptor) return review("unknown_tool_capability");
  const relevant = spec.capabilities.filter((capability) => descriptorMatches(capability, descriptor));
  if (!relevant.length) {
    const parseFailure = context.taskMode === "data_only" || context.taskMode === "chatter";
    return review(parseFailure ? "authorization_parse_failed" : "missing_explicit_authorization");
  }

  const authoritative = relevant.filter((capability) => isAuthoritative(capability));
  if (!authoritative.length) {
    return SIDE_EFFECT_TOOLS.has(tool)
      ? denied("non_authoritative_context_cannot_grant_side_effects")
      : review("non_authoritative_context");
  }

  const mismatches: CapabilityAuthorization[] = [];
  for (const capability of authoritative) {
    const validation = validateConstraints(capability, request, descriptor.method);
    if (validation.authorized) return validation;
    mismatches.push(validation);
  }

  if (mismatches.length) return mismatches[0];

  const first = authoritative[0];
  const actualTarget = targetFor(request);
  return {
    action: "deny",
    authorized: false,
    reason: constraintMismatchReason(first, request, descriptor.method),
    capability: first,
    expectedTarget: first.targets.join(", "),
    actualTarget,
  };
}

export function isSideEffectToolCall(request: CapabilityActionRequest): boolean {
  if (!SIDE_EFFECT_TOOLS.has(request.tool)) return false;
  if (request.tool !== "call_api") return true;
  return !["GET", "HEAD", "OPTIONS"].includes(requestMethod(request));
}

function descriptorFor(request: CapabilityActionRequest): { action: TaskCapability["action"]; resource: TaskCapability["resourceType"]; method?: string } | null {
  if (request.tool === "business_read") return { action: "read", resource: "api" };
  if (request.tool === "read_file") return { action: "read", resource: "file" };
  if (request.tool === "write_file") return { action: "write", resource: "file" };
  if (request.tool === "send_email") return { action: "send", resource: "email" };
  if (request.tool === "read_webpage") return { action: "read", resource: "api", method: "GET" };
  if (request.tool === "call_api") {
    const method = requestMethod(request);
    return { action: ["GET", "HEAD", "OPTIONS"].includes(method) ? "read" : "request", resource: "api", method };
  }
  if (request.tool === "shell_exec") return { action: "execute", resource: "shell" };
  if (request.tool === "memory_write") return { action: "persist", resource: "memory" };
  if (request.tool === "memory_read") return { action: "read", resource: "memory" };
  if (request.tool === "calendar_write") return { action: "write", resource: "calendar" };
  if (request.tool === "cloud_file_write") return { action: "write", resource: "cloud_file" };
  if (request.tool === "cloud_file_share") return { action: "send", resource: "cloud_file" };
  return null;
}

function descriptorMatches(
  capability: TaskCapability,
  descriptor: { action: TaskCapability["action"]; resource: TaskCapability["resourceType"] },
): boolean {
  if (capability.resourceType !== descriptor.resource) return false;
  if (capability.action === descriptor.action) return true;
  if (descriptor.resource !== "api") return false;
  if (descriptor.action === "read" && capability.action === "request" && capability.effect === "read_only") return true;
  return descriptor.action === "request" && capability.action === "read";
}

function validateConstraints(capability: TaskCapability, request: CapabilityActionRequest, method?: string): CapabilityAuthorization {
  const target = targetFor(request);
  if (capability.constraints.allowedMethods?.length && method && !capability.constraints.allowedMethods.includes(method)) {
    return mismatch("method_outside_authorization", capability, target);
  }

  if (request.tool === "send_email") {
    const recipients = readMany(request.args, ["recipient", "recipients", "to", "target", "email"])
      .map((recipient) => recipient.toLowerCase());
    const allowed = capability.constraints.allowedRecipients || capability.targets;
    const unauthorized = recipients.find((recipient) => !allowed.some((item) => item.toLowerCase() === recipient));
    if (!recipients.length || unauthorized) {
      return mismatch("recipient_outside_authorization", capability, unauthorized || "");
    }
    const attachment = readFirst(request.args, ["attachment", "attachments", "path", "file"]);
    if (attachment && capability.constraints.allowedPaths?.length && !capability.constraints.allowedPaths.some((item) => pathMatches(attachment, item))) {
      return mismatch("attachment_outside_authorization", capability, attachment);
    }
  }

  if (request.tool === "calendar_write") {
    const operation = calendarOperation(request);
    if (capability.constraints.allowedOperations?.length
      && !capability.constraints.allowedOperations.map((item) => item.toLowerCase()).includes(operation)) {
      return mismatch("calendar_operation_outside_authorization", capability, operation);
    }
    const participants = readMany(request.args, ["participants", "recipients", "attendees"])
      .map((item) => item.toLowerCase());
    const allowedRecipients = capability.constraints.allowedRecipients;
    const unauthorized = allowedRecipients?.length
      ? participants.find((item) => !allowedRecipients.some((allowed) => allowed.toLowerCase() === item))
      : undefined;
    if (unauthorized) return mismatch("participant_outside_authorization", capability, unauthorized);
  }

  if (request.tool === "cloud_file_write") {
    const operation = cloudFileOperation(request);
    if (capability.constraints.allowedOperations?.length
      && !capability.constraints.allowedOperations.map((item) => item.toLowerCase()).includes(operation)) {
      return mismatch("cloud_file_operation_outside_authorization", capability, operation);
    }
    const name = readFirst(request.args, ["filename", "path", "file"]);
    if (name && capability.constraints.allowedPaths?.length
      && !capability.constraints.allowedPaths.some((allowed) => pathMatches(name, allowed))) {
      return mismatch("cloud_file_outside_authorization", capability, name);
    }
  }

  if (request.tool === "cloud_file_share") {
    const recipients = readMany(request.args, ["recipient", "recipients", "to", "email"])
      .map((item) => item.toLowerCase());
    const allowed = capability.constraints.allowedRecipients || capability.targets;
    const unauthorized = recipients.find((recipient) => !allowed.some((item) => item.toLowerCase() === recipient));
    if (!recipients.length || unauthorized) return mismatch("recipient_outside_authorization", capability, unauthorized || "");
  }

  if (request.tool === "read_file" || request.tool === "write_file") {
    const path = readFirst(request.args, ["path", "file", "filename", "target"]);
    const allowed = capability.constraints.allowedPaths || capability.targets;
    if (!path || !allowed.some((item) => pathMatches(path, item))) {
      return mismatch("path_outside_authorization", capability, path);
    }
  }

  if (request.tool === "read_webpage" || request.tool === "call_api") {
    const url = readFirst(request.args, ["url", "href", "endpoint", "target"]);
    if (!url || !capability.targets.some((item) => networkTargetMatches(url, item))) {
      return mismatch("target_outside_authorization", capability, url);
    }
    const host = hostFromUrl(url);
    if (capability.constraints.allowedHosts?.length && (!host || !capability.constraints.allowedHosts.includes(host))) {
      return mismatch("host_outside_authorization", capability, host);
    }
  }

  if (request.tool === "shell_exec") {
    const command = readFirst(request.args, ["command", "cmd", "script", "input"]);
    if (!shellTargetMatches(command, capability.targets)) {
      return mismatch("command_outside_authorization", capability, command);
    }
  }

  return { action: "allow", authorized: true, reason: "explicit_capability_match", capability };
}

function constraintMismatchReason(capability: TaskCapability, request: CapabilityActionRequest, method?: string): string {
  if (capability.constraints.allowedMethods?.length && method && !capability.constraints.allowedMethods.includes(method)) return "method_outside_authorization";
  if (request.tool === "send_email" || request.tool === "cloud_file_share") return "recipient_outside_authorization";
  if (request.tool === "calendar_write") return "calendar_operation_outside_authorization";
  if (request.tool === "cloud_file_write") return "cloud_file_operation_outside_authorization";
  if (request.tool === "read_file" || request.tool === "write_file") return "path_outside_authorization";
  if (request.tool === "read_webpage" || request.tool === "call_api") return "target_outside_authorization";
  if (request.tool === "shell_exec") return "command_outside_authorization";
  return "capability_constraints_not_satisfied";
}

function isAuthoritative(capability: TaskCapability): boolean {
  return (capability.evidence.source === "user"
    || (capability.evidence.source === "delegated_tool_result" && capability.evidence.delegationVerified === true))
    && capability.evidence.explicitAuthorization
    && !capability.evidence.insideQuotation
    && !capability.evidence.negated
    && capability.evidence.targetIsConcrete;
}

function requestMethod(request: CapabilityActionRequest): string {
  const explicit = readFirst(request.args, ["method", "httpMethod", "verb"]).toUpperCase();
  if (explicit) return explicit;
  return hasPayload(request.args) ? "POST" : "GET";
}

function hasPayload(args: Record<string, unknown>): boolean {
  return ["body", "payload", "data", "content"].some((key) => args[key] !== undefined && args[key] !== null && String(args[key]) !== "");
}

function targetFor(request: CapabilityActionRequest): string {
  if (request.tool === "send_email") return readFirst(request.args, ["recipient", "to", "target", "email"]);
  if (request.tool === "read_file" || request.tool === "write_file") return readFirst(request.args, ["path", "file", "filename", "target"]);
  if (request.tool === "read_webpage" || request.tool === "call_api") return readFirst(request.args, ["url", "href", "endpoint", "target"]);
  if (request.tool === "shell_exec") return readFirst(request.args, ["command", "cmd", "script", "input"]);
  if (request.tool === "calendar_write") return calendarOperation(request);
  if (request.tool === "cloud_file_write") return cloudFileOperation(request);
  if (request.tool === "cloud_file_share") return readFirst(request.args, ["recipient", "to", "email"]);
  return request.tool;
}

function calendarOperation(request: CapabilityActionRequest): string {
  const tool = (request.originalTool || "").toLowerCase();
  if (tool.includes("reschedule")) return "reschedule";
  if (tool.includes("participant")) return "participants";
  if (tool.includes("cancel")) return "cancel";
  return "create";
}

function cloudFileOperation(request: CapabilityActionRequest): string {
  const tool = (request.originalTool || "").toLowerCase();
  if (tool.includes("git_delete") || tool.includes("delete_node")) return "delete";
  if (tool.includes("transfer")) return "transfer";
  if (tool.includes("invite")) return "invite";
  if (tool.includes("unstar")) return "unstar";
  if (tool.includes("star")) return "star";
  if (tool.includes("issue")) return "issue";
  if (tool.includes("push")) return "push";
  if (tool.includes("pull")) return "pull";
  if (tool.includes("ssh")) return tool.includes("delete") ? "ssh_delete" : "ssh_add";
  if (tool.includes("download") || tool.includes("clone")) return "pull";
  if (tool.includes("move") || tool.includes("copy") || tool.includes("create")) return "create";
  if (tool.includes("append")) return "append";
  if (tool.includes("delete")) return "delete";
  if (tool.includes("share")) return "share";
  return "create";
}

function pathMatches(actual: string, allowed: string): boolean {
  const normalizedActual = normalizePath(actual);
  const normalizedAllowed = normalizePath(allowed);
  if (!normalizedActual || !normalizedAllowed) return false;
  if (normalizedAllowed === "~/.ssh/authorized_keys") return normalizedActual.endsWith("/.ssh/authorized_keys");
  if (normalizedAllowed.startsWith("~/.openclaw/")) return normalizedActual.endsWith(normalizedAllowed.slice(1));
  if (normalizedAllowed.endsWith("/*")) return normalizedActual.startsWith(normalizedAllowed.slice(0, -1));
  const actualIsAbsolute = normalizedActual.startsWith("/") || /^[a-z]:\//.test(normalizedActual);
  const allowedIsSafeRelative = !normalizedAllowed.startsWith("/")
    && !/^[a-z]:\//.test(normalizedAllowed)
    && normalizedAllowed !== ".."
    && !normalizedAllowed.startsWith("../");
  // Runtime adapters resolve workspace-relative paths before authorization.
  // Match that resolved path back to the exact user-authorized relative suffix;
  // allowed-root enforcement separately proves it belongs to the workspace.
  if (actualIsAbsolute && allowedIsSafeRelative) return normalizedActual.endsWith(`/${normalizedAllowed}`);
  return normalizedActual === normalizedAllowed;
}

function networkTargetMatches(actual: string, allowed: string): boolean {
  return targetMatches(normalizeNetworkTarget(actual), normalizeNetworkTarget(allowed));
}

function shellTargetMatches(command: string, targets: string[]): boolean {
  const normalized = command.trim().replace(/\s+/g, " ").toLowerCase();
  if (!normalized) return false;
  if (targets.includes("system:read-only")) return isLowRiskShellReadCommand(normalized);
  if (targets.includes("task:test")) return /^(?:npm|pnpm|yarn)\s+test\b|^python\s+-m\s+pytest\b|^pytest\b/.test(normalized);
  if (targets.includes("task:build")) return /^(?:npm|pnpm|yarn)\s+(?:run\s+)?build\b/.test(normalized);
  return targets.some((target) => target.trim().replace(/\s+/g, " ").toLowerCase() === normalized);
}

function normalizePath(value: string): string {
  const slashes = value.trim().replace(/\\/g, "/");
  if (!slashes) return "";
  const directoryWildcard = slashes.endsWith("/*");
  const withoutWildcard = directoryWildcard ? slashes.slice(0, -2) : slashes;
  const normalized = posix.normalize(withoutWildcard).replace(/^\.\//, "").replace(/\/$/, "").toLowerCase();
  return directoryWildcard ? `${normalized}/*` : normalized;
}

function normalizeNetworkTarget(value: string): string {
  const text = value.trim().replace(/[.,;:\])}>'"，。；：）】》”’]+$/g, "");
  if (!text) return "";
  try {
    const parsed = new URL(text);
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return text.replace(/\/$/, "");
  }
}

function readFirst(args: Record<string, unknown>, keys: string[]): string {
  return readMany(args, keys)[0] || "";
}

function readMany(args: Record<string, unknown>, keys: string[]): string[] {
  for (const key of keys) {
    const original = args[key];
    const value = isLabeledValue(original) ? original.value : original;
    if (typeof value === "string" && value.trim()) return [value.trim()];
    if (Array.isArray(value)) {
      const items = value.map((item) => flattenText(item).trim()).filter(Boolean);
      if (items.length) return items;
    }
  }
  return [];
}

function denied(reason: string): CapabilityAuthorization {
  return { action: "deny", authorized: false, reason };
}

function review(reason: string): CapabilityAuthorization {
  return { action: "ask", authorized: false, reason };
}

function mismatch(reason: string, capability: TaskCapability, actualTarget: string): CapabilityAuthorization {
  return {
    action: "deny",
    authorized: false,
    reason,
    capability,
    expectedTarget: capability.targets.join(", "),
    actualTarget,
  };
}
