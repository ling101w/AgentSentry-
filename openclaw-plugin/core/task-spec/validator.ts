import type {
  CapabilityActionRequest,
  CapabilityAuthorization,
  TaskCapability,
  TaskSpec,
} from "./types.ts";
import { posix } from "node:path";
import { hostFromUrl, targetMatches } from "../security/url.ts";
import { isLowRiskShellReadCommand } from "../policy/safe-ops.ts";

const SIDE_EFFECT_TOOLS = new Set(["write_file", "send_email", "call_api", "shell_exec", "memory_write"]);

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
    // (P0-3) A keyword-inferred sensitive target is surfaced as a pending
    // approval request instead of a silent grant.
    const pending = matchPendingRequest(spec, descriptor, request);
    if (pending) {
      return {
        action: "ask",
        authorized: false,
        reason: `pending_capability_request:${pending.reason}`,
        capability: {
          action: pending.action,
          resourceType: pending.resourceType,
          targets: pending.targets,
          effect: pending.effect,
          constraints: {},
          evidence: {
            sourceMessageHash: "",
            source: "system",
            explicitSpan: pending.evidenceSpan,
            explicitAuthorization: false,
            insideQuotation: false,
            negated: false,
            targetIsConcrete: true,
            confidence: pending.confidence,
          },
          expiresAfterTurn: 0,
        },
        expectedTarget: pending.targets.join(", "),
        actualTarget: targetFor(request),
      };
    }
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
    // (P1) Enforce per-capability usage budgets before constraint checks so
    // an exhausted or expired grant degrades to approval instead of looping.
    const budget = checkUsageBudget(capability, request);
    if (budget) {
      mismatches.push(budget);
      continue;
    }
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

/** (P0-3) Match a tool call against pending keyword-inferred proposals. */
function matchPendingRequest(
  spec: TaskSpec,
  descriptor: { action: TaskCapability["action"]; resource: TaskCapability["resourceType"] },
  request: CapabilityActionRequest,
): TaskSpec["pending_capability_requests"] extends (infer T)[] | undefined ? T | undefined : never {
  const pending = spec.pending_capability_requests || [];
  for (const proposal of pending) {
    if (proposal.action !== descriptor.action) continue;
    if (proposal.resourceType !== descriptor.resource) continue;
    const target = targetFor(request);
    if (!target) continue;
    if (proposal.targets.some((allowed) => matchesProposalTarget(target, allowed, request.tool))) return proposal;
  }
  return undefined;
}

function matchesProposalTarget(actual: string, allowed: string, tool: string): boolean {
  if (tool === "read_file" || tool === "write_file") return pathMatches(actual, allowed);
  return actual.toLowerCase() === allowed.toLowerCase();
}

/**
 * (P1) Per-capability usage accounting: maxCalls and maxBytes are enforced
 * against capability.usage, and expiresAfterTurn is compared to the turn
 * counter maintained by the session state.
 */
function checkUsageBudget(capability: TaskCapability, request: CapabilityActionRequest): CapabilityAuthorization | null {
  const usage = capability.usage;
  if (!usage) return null;
  const maxCalls = capability.constraints.maxCalls ?? Number.POSITIVE_INFINITY;
  if (usage.calls >= maxCalls) {
    return {
      action: "ask",
      authorized: false,
      reason: "capability_call_budget_exhausted",
      capability,
      actualTarget: targetFor(request),
    };
  }
  if (request.tool === "write_file") {
    const maxBytes = capability.constraints.maxBytes ?? Number.POSITIVE_INFINITY;
    const content = readFirst(request.args, ["content", "text", "body", "data"]);
    if (usage.bytesWritten + content.length > maxBytes) {
      return {
        action: "ask",
        authorized: false,
        reason: "capability_byte_budget_exhausted",
        capability,
        actualTarget: targetFor(request),
      };
    }
  }
  return null;
}

/** (P1) Record a successful use against the capability's usage budget. */
export function recordCapabilityUse(spec: TaskSpec, request: CapabilityActionRequest): TaskSpec {
  const descriptor = descriptorFor(request);
  if (!descriptor) return spec;
  let updated = false;
  const capabilities = spec.capabilities.map((capability) => {
    if (!descriptorMatches(capability, descriptor)) return capability;
    if (!validateConstraints(capability, request, descriptor.method).authorized) return capability;
    const usage = capability.usage || { calls: 0, bytesWritten: 0, expiresAfterTurn: capability.expiresAfterTurn };
    const content = request.tool === "write_file"
      ? readFirst(request.args, ["content", "text", "body", "data"]).length
      : 0;
    updated = true;
    return {
      ...capability,
      usage: {
        calls: usage.calls + 1,
        bytesWritten: usage.bytesWritten + content,
        expiresAfterTurn: usage.expiresAfterTurn,
      },
    };
  });
  return updated ? { ...spec, capabilities } : spec;
}

export function isSideEffectToolCall(request: CapabilityActionRequest): boolean {
  if (!SIDE_EFFECT_TOOLS.has(request.tool)) return false;
  if (request.tool !== "call_api") return true;
  return !["GET", "HEAD", "OPTIONS"].includes(requestMethod(request));
}

function descriptorFor(request: CapabilityActionRequest): { action: TaskCapability["action"]; resource: TaskCapability["resourceType"]; method?: string } | null {
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

  // (P0-1) Clause-scoped binding check runs last as defense in depth: a
  // request that passed the per-tool target checks must still fall inside the
  // parameter tuple extracted from the clause that granted the capability,
  // which is what blocks "send A to Alice; send B to Bob" cross-combinations.
  if (!boundArgumentsMatch(capability, request)) {
    return mismatch("arguments_outside_clause_binding", capability, target);
  }

  return { action: "allow", authorized: true, reason: "explicit_capability_match", capability };
}

function constraintMismatchReason(capability: TaskCapability, request: CapabilityActionRequest, method?: string): string {
  if (capability.constraints.allowedMethods?.length && method && !capability.constraints.allowedMethods.includes(method)) return "method_outside_authorization";
  if (request.tool === "send_email") return "recipient_outside_authorization";
  if (request.tool === "read_file" || request.tool === "write_file") return "path_outside_authorization";
  if (request.tool === "read_webpage" || request.tool === "call_api") return "target_outside_authorization";
  if (request.tool === "shell_exec") return "command_outside_authorization";
  return "capability_constraints_not_satisfied";
}

/**
 * (P0-4) Authoritativeness requires user-sourced evidence with an explicit
 * authorization flag. Evidence fields are only ever written by the
 * deterministic extractor for user-originated clauses — refinement clones may
 * carry narrowed targets but never regain the user flag.
 */
function isAuthoritative(capability: TaskCapability): boolean {
  return capability.evidence.source === "user"
    && capability.evidence.explicitAuthorization
    && !capability.evidence.insideQuotation
    && !capability.evidence.negated
    && capability.evidence.targetIsConcrete;
}

/**
 * (P0-1) Enforce clause-bound parameters. When a capability carries a bound
 * tuple (recipients/paths/urls/commands extracted from the same clause that
 * granted it), the actual call arguments must fall inside that binding.
 * Without this, "send A to Alice; send B to Bob" could satisfy authorization
 * with any (file, recipient) combination.
 */
function boundArgumentsMatch(capability: TaskCapability, request: CapabilityActionRequest): boolean {
  const bound = capability.bound;
  if (!bound) return true;
  if (request.tool === "send_email" && bound.recipients?.length) {
    const recipients = readMany(request.args, ["recipient", "recipients", "to", "target", "email"])
      .map((recipient) => recipient.toLowerCase());
    if (!recipients.length || recipients.some((recipient) => !bound.recipients!.some((item) => item.toLowerCase() === recipient))) {
      return false;
    }
  }
  if ((request.tool === "read_file" || request.tool === "write_file") && bound.paths?.length) {
    const path = readFirst(request.args, ["path", "file", "filename", "target"]);
    if (!path || !bound.paths.some((item) => pathMatches(path, item))) return false;
  }
  if ((request.tool === "read_webpage" || request.tool === "call_api") && bound.urls?.length) {
    const url = readFirst(request.args, ["url", "href", "endpoint", "target"]);
    if (!url || !bound.urls.some((item) => networkTargetMatches(url, item))) return false;
  }
  if (request.tool === "shell_exec" && bound.commands?.length) {
    const command = readFirst(request.args, ["command", "cmd", "script", "input"]);
    if (!command || !shellTargetMatches(command, bound.commands)) return false;
  }
  return true;
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
  return request.tool;
}

function pathMatches(actual: string, allowed: string): boolean {
  const normalizedActual = normalizePath(actual);
  const normalizedAllowed = normalizePath(allowed);
  if (!normalizedActual || !normalizedAllowed) return false;
  // (P0-3) Home-relative grants must anchor to the home directory. The old
  // endsWith check let any /tmp/evil/.openclaw/skills/x match ~/.openclaw/skills/*.
  if (normalizedAllowed.startsWith("~/")) {
    const suffix = normalizedAllowed.slice(2);
    const wildcard = suffix.endsWith("/*");
    const base = wildcard ? suffix.slice(0, -2) : suffix;
    const marker = `/${base.split("/")[0]}/`;
    const homeVariants = ["/home/", "/users/", "/root/"];
    // (P0-3) The home-relative marker must be found *inside* a home-directory
    // prefix. A bare lastIndexOf would let /tmp/evil/.openclaw/skills/x match
    // ~/.openclaw/skills/* all over again.
    const matched = homeVariants.some((prefix) => {
      if (!normalizedActual.startsWith(prefix)) return false;
      const index = normalizedActual.indexOf(marker, prefix.length - 1);
      if (index < 0) return false;
      const relative = normalizedActual.slice(index + 1);
      return wildcard
        ? relative.startsWith(`${base}/`)
        : relative === base;
    });
    if (matched) return true;
    // Also accept the explicit ~/.ssh/authorized_keys convenience form.
    if (normalizedAllowed === "~/.ssh/authorized_keys") {
      return /\/\.ssh\/authorized_keys$/.test(normalizedActual)
        && !/(^|\/)\.\.(\/|$)/.test(normalizedActual);
    }
    return false;
  }
  if (normalizedAllowed.endsWith("/*")) return normalizedActual.startsWith(normalizedAllowed.slice(0, -1));
  if (normalizedActual === normalizedAllowed) return true;
  return workspaceRelativePath(normalizedActual) === workspaceRelativePath(normalizedAllowed);
}

function workspaceRelativePath(path: string): string {
  const marker = "/.openclaw/workspace/";
  const index = path.indexOf(marker);
  if (index >= 0) return path.slice(index + marker.length);
  return path.replace(/^\/+/, "");
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
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (Array.isArray(value) && value.length) return String(value[0]).trim();
  }
  return "";
}

function readMany(args: Record<string, unknown>, keys: string[]): string[] {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) return [value.trim()];
    if (Array.isArray(value)) {
      const items = value.map((item) => String(item).trim()).filter(Boolean);
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
