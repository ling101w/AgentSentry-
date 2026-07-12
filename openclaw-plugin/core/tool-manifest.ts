import { createHash } from "node:crypto";
import type { DetectionFinding } from "./detect.ts";

export type ToolDataOrigin = "user" | "workspace" | "external_web" | "email" | "third_party_api" | "memory" | "unknown";
export type ToolSideEffect = "none" | "file_read" | "file_write" | "network_read" | "network_write" | "process_exec" | "persistent_state";

export interface ToolSecurityManifest {
  toolId: string;
  aliases: string[];
  dataOrigins: ToolDataOrigin[];
  sideEffects: ToolSideEffect[];
  acceptsSensitiveData: boolean;
  canExfiltrate: boolean;
  requiresExplicitAuthorization: boolean;
  defaultTrust: "trusted" | "workspace" | "external" | "unknown";
}

export interface ToolManifestEnvelope {
  manifest: ToolSecurityManifest;
  schema?: unknown;
  endpoint?: string;
  version?: string;
  digest: string;
}

const registry = new Map<string, ToolManifestEnvelope>();
const aliases = new Map<string, string>();
const DATA_ORIGINS = new Set<ToolDataOrigin>(["user", "workspace", "external_web", "email", "third_party_api", "memory", "unknown"]);
const SIDE_EFFECTS = new Set<ToolSideEffect>(["none", "file_read", "file_write", "network_read", "network_write", "process_exec", "persistent_state"]);
const TRUST_LEVELS = new Set<ToolSecurityManifest["defaultTrust"]>(["trusted", "workspace", "external", "unknown"]);

for (const manifest of builtinManifests()) registerToolManifest(manifest);

export function registerToolManifest(
  manifest: ToolSecurityManifest,
  metadata: { schema?: unknown; endpoint?: string; version?: string; expectedDigest?: string } = {},
): ToolManifestEnvelope {
  validateManifest(manifest);
  const digest = toolManifestDigest(manifest, metadata);
  if (metadata.expectedDigest && !constantTimeTextEqual(digest, metadata.expectedDigest)) {
    throw new Error(`tool_manifest_integrity_mismatch:${manifest.toolId}`);
  }
  const canonical = normalizeToolId(manifest.toolId);
  for (const candidate of [manifest.toolId, ...manifest.aliases]) {
    const normalizedAlias = normalizeToolId(candidate);
    const currentOwner = aliases.get(normalizedAlias);
    if (currentOwner && currentOwner !== canonical) {
      throw new Error(`tool_manifest_alias_conflict:${candidate}`);
    }
  }
  const envelope = {
    manifest: structuredClone(manifest),
    schema: metadata.schema,
    endpoint: metadata.endpoint,
    version: metadata.version,
    digest,
  };
  registry.set(canonical, envelope);
  for (const [alias, owner] of aliases) {
    if (owner === canonical) aliases.delete(alias);
  }
  aliases.set(canonical, canonical);
  for (const alias of manifest.aliases) aliases.set(normalizeToolId(alias), canonical);
  return structuredClone(envelope);
}

export function resolveToolManifest(toolId: string): ToolManifestEnvelope | null {
  const canonical = aliases.get(normalizeToolId(toolId)) || normalizeToolId(toolId);
  const envelope = registry.get(canonical);
  return envelope ? structuredClone(envelope) : null;
}

export function toolManifestDigest(
  manifest: ToolSecurityManifest,
  metadata: { schema?: unknown; endpoint?: string; version?: string } = {},
): string {
  const payload = stableSerialize({
    tool_schema: metadata.schema ?? null,
    endpoint: metadata.endpoint || "",
    capabilities: manifest,
    side_effects: manifest.sideEffects,
    version: metadata.version || "",
  });
  return createHash("sha256").update(payload, "utf8").digest("hex");
}

export function verifyToolManifest(envelope: ToolManifestEnvelope): boolean {
  return constantTimeTextEqual(envelope.digest, toolManifestDigest(envelope.manifest, envelope));
}

export function toolManifestFindings(toolName: string, normalizedTool: string, params: Record<string, unknown>): DetectionFinding[] {
  const rawSupplied = params.__toolSecurityManifest ?? params.toolSecurityManifest;
  const supplied = suppliedEnvelope(params);
  if (rawSupplied !== undefined && !supplied) {
    return [finding("block", "tool_manifest_invalid", {
      toolName,
      normalizedTool,
    })];
  }
  if (supplied && !verifyToolManifest(supplied)) {
    return [finding("block", "tool_manifest_integrity_mismatch", {
      toolName,
      normalizedTool,
      supplied_digest: supplied.digest,
      computed_digest: toolManifestDigest(supplied.manifest, supplied),
    })];
  }

  const registered = resolveToolManifest(toolName);
  if (!registered) {
    return [finding("require_approval", "unregistered tool has no trusted security manifest", {
      toolName,
      normalizedTool,
      inferred_effects: inferUnknownEffects(params),
    })];
  }

  if (supplied && normalizeToolId(supplied.manifest.toolId) !== normalizeToolId(registered.manifest.toolId)) {
    return [finding("block", "tool manifest identity differs from the registered tool", {
      toolName,
      registered_tool_id: registered.manifest.toolId,
      supplied_tool_id: supplied.manifest.toolId,
    })];
  }
  if (supplied && !constantTimeTextEqual(supplied.digest, registered.digest)) {
    return [finding("block", "tool_manifest_integrity_mismatch", {
      toolName,
      normalizedTool,
      registered_digest: registered.digest,
      supplied_digest: supplied.digest,
    })];
  }
  return [];
}

export function clearCustomToolManifests(): void {
  registry.clear();
  aliases.clear();
  for (const manifest of builtinManifests()) registerToolManifest(manifest);
}

function suppliedEnvelope(params: Record<string, unknown>): ToolManifestEnvelope | null {
  const raw = params.__toolSecurityManifest || params.toolSecurityManifest;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const manifest = obj.manifest;
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) || typeof obj.digest !== "string") return null;
  try {
    validateManifest(manifest as ToolSecurityManifest);
    return {
      manifest: manifest as ToolSecurityManifest,
      schema: obj.schema,
      endpoint: typeof obj.endpoint === "string" ? obj.endpoint : undefined,
      version: typeof obj.version === "string" ? obj.version : undefined,
      digest: obj.digest,
    };
  } catch {
    return null;
  }
}

function validateManifest(manifest: ToolSecurityManifest): void {
  if (!manifest || typeof manifest !== "object") throw new TypeError("tool manifest must be an object");
  if (!manifest.toolId?.trim()) throw new TypeError("tool manifest requires toolId");
  if (!Array.isArray(manifest.aliases) || !Array.isArray(manifest.dataOrigins) || !Array.isArray(manifest.sideEffects)) {
    throw new TypeError("tool manifest aliases, origins, and side effects must be arrays");
  }
  if (manifest.aliases.some((alias) => typeof alias !== "string" || !alias.trim())) {
    throw new TypeError("tool manifest aliases must be non-empty strings");
  }
  if (!manifest.dataOrigins.length || manifest.dataOrigins.some((origin) => !DATA_ORIGINS.has(origin))) {
    throw new TypeError("tool manifest contains an invalid data origin");
  }
  if (!manifest.sideEffects.length) throw new TypeError("tool manifest requires at least one side effect declaration");
  if (manifest.sideEffects.some((effect) => !SIDE_EFFECTS.has(effect)) || (manifest.sideEffects.includes("none") && manifest.sideEffects.length > 1)) {
    throw new TypeError("tool manifest contains an invalid side effect declaration");
  }
  if (
    typeof manifest.acceptsSensitiveData !== "boolean"
    || typeof manifest.canExfiltrate !== "boolean"
    || typeof manifest.requiresExplicitAuthorization !== "boolean"
  ) {
    throw new TypeError("tool manifest security flags must be boolean");
  }
  if (!TRUST_LEVELS.has(manifest.defaultTrust)) throw new TypeError("tool manifest contains an invalid default trust level");
}

function inferUnknownEffects(params: Record<string, unknown>): ToolSideEffect[] {
  const text = stableSerialize(params).toLowerCase();
  const effects: ToolSideEffect[] = [];
  if (/https?:\/\//.test(text)) effects.push(/"(?:body|payload|data|content)"/.test(text) ? "network_write" : "network_read");
  if (/"(?:command|cmd|script)"/.test(text)) effects.push("process_exec");
  if (/"(?:path|file|filename)"/.test(text)) effects.push(/"(?:content|patch|new_string|replacement)"/.test(text) ? "file_write" : "file_read");
  return effects.length ? Array.from(new Set(effects)) : ["none"];
}

function stableSerialize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableSerialize(item)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function constantTimeTextEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return mismatch === 0;
}

function normalizeToolId(value: string): string {
  return value.trim().toLowerCase();
}

function finding(verdict: "require_approval" | "block", reason: string, evidence: Record<string, unknown>): DetectionFinding {
  return {
    layer: "Tool Manifest",
    finding_type: "deterministic",
    verdict,
    reason,
    score: verdict === "block" ? 100 : 45,
    evidence,
  };
}

function builtinManifests(): ToolSecurityManifest[] {
  return [
    manifest("read_webpage", ["browser.open", "browser_open", "open_browser", "fetch_url", "web.open", "read_email", "read_pdf", "analyze_image"], ["external_web"], ["network_read"], false, false, false, "external"),
    manifest("call_api", [], ["third_party_api"], ["network_read", "network_write"], true, true, true, "external"),
    manifest("read_file", ["read", "open"], ["workspace"], ["file_read"], false, false, true, "workspace"),
    manifest("write_file", ["write", "create", "edit", "replace", "patch"], ["user", "workspace"], ["file_write", "persistent_state"], true, false, true, "workspace"),
    manifest("send_email", [], ["user", "workspace", "email"], ["network_write"], true, true, true, "external"),
    manifest("shell_exec", [], ["user", "workspace"], ["process_exec", "file_write", "network_write"], true, true, true, "unknown"),
    manifest("memory_read", [], ["memory"], ["none"], false, false, true, "workspace"),
    manifest("memory_write", ["webhook_wake"], ["user", "memory"], ["persistent_state"], true, false, true, "workspace"),
    manifest("web_search", [], ["external_web"], ["network_read"], false, false, false, "external"),
  ];
}

function manifest(
  toolId: string,
  toolAliases: string[],
  dataOrigins: ToolDataOrigin[],
  sideEffects: ToolSideEffect[],
  acceptsSensitiveData: boolean,
  canExfiltrate: boolean,
  requiresExplicitAuthorization: boolean,
  defaultTrust: ToolSecurityManifest["defaultTrust"],
): ToolSecurityManifest {
  return { toolId, aliases: toolAliases, dataOrigins, sideEffects, acceptsSensitiveData, canExfiltrate, requiresExplicitAuthorization, defaultTrust };
}
