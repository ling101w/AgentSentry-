import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { PluginConfig } from "../config.ts";
import { loadOrCreateStateSecret } from "./state-secret.ts";
import type { DetectionFinding } from "./detect.ts";
import { interventionEvidence } from "./policy/intervention-gate.ts";

export type ToolDataOrigin = "user" | "workspace" | "external_web" | "email" | "third_party_api" | "memory" | "unknown";
export type ToolSideEffect = "none" | "file_read" | "file_write" | "network_read" | "network_write" | "process_exec" | "persistent_state";
export type ToolAccessScope = "caller_bound" | "explicit_target" | "unscoped" | "unknown";
export type SensitiveInputHandling = "none" | "authentication_only" | "business_payload" | "unknown";
export type ToolDataClassification = "public" | "internal" | "user_private" | "secret" | "unknown";
export type ToolDataSubject = "caller" | "named_subject" | "third_party" | "unknown";
export type ToolPurposeBinding = "task_bound" | "operator_defined" | "unknown";
export type ToolPathScope = "host_workspace" | "isolated_environment";

export interface ToolSecurityManifest {
  toolId: string;
  aliases: string[];
  dataOrigins: ToolDataOrigin[];
  sideEffects: ToolSideEffect[];
  acceptsSensitiveData: boolean;
  canExfiltrate: boolean;
  requiresExplicitAuthorization: boolean;
  defaultTrust: "trusted" | "workspace" | "external" | "unknown";
  /**
   * Optional because existing administrator manifests remain valid. New
   * onboarding paths should declare both fields before receiving implicit
   * read permission.
   */
  accessScope?: ToolAccessScope;
  sensitiveInputHandling?: SensitiveInputHandling;
  credentialFields?: string[];
  targetFields?: string[];
  /** Fields that identify the person, account, device, or record being read. */
  subjectFields?: string[];
  dataClassification?: ToolDataClassification;
  /**
   * Declares whose data a tool normally exposes. This is metadata supplied at
   * onboarding, never inferred from a tool name or a prompt.
   */
  dataSubjects?: ToolDataSubject[];
  /**
   * States whether an operation is normally meaningful only inside a user
   * task. It lets the policy distinguish a task-scoped lookup from a generic
   * account or identity operation.
   */
  purposeBinding?: ToolPurposeBinding;
  /**
   * Distinguishes host filesystem paths from paths owned by an isolated tool
   * runtime (for example, a benchmark environment or remote workspace).
   */
  pathScope?: ToolPathScope;
}

export interface ToolManifestEnvelope {
  manifest: ToolSecurityManifest;
  schema?: unknown;
  endpoint?: string;
  version?: string;
  digest: string;
  signature: string;
  issuer?: "builtin" | "local-administrator";
  registeredAt?: string;
}

export type ToolManifestRevocation = {
  toolId: string;
  digest: string;
  reason: string;
  revokedAt: string;
};

const registry = new Map<string, ToolManifestEnvelope>();
const aliases = new Map<string, string>();
const customToolIds = new Set<string>();
const revocations = new Map<string, ToolManifestRevocation>();
let manifestSigningSecret: Buffer<ArrayBufferLike> = Buffer.from(
  process.env.AGENTSENTRY_TOOL_MANIFEST_SECRET || "agentsentry-tool-manifest-development-key",
  "utf8",
);
let configuredConfig: PluginConfig | null = null;
let loadingPersistedRegistry = false;
const DATA_ORIGINS = new Set<ToolDataOrigin>(["user", "workspace", "external_web", "email", "third_party_api", "memory", "unknown"]);
const SIDE_EFFECTS = new Set<ToolSideEffect>(["none", "file_read", "file_write", "network_read", "network_write", "process_exec", "persistent_state"]);
const TRUST_LEVELS = new Set<ToolSecurityManifest["defaultTrust"]>(["trusted", "workspace", "external", "unknown"]);
const ACCESS_SCOPES = new Set<ToolAccessScope>(["caller_bound", "explicit_target", "unscoped", "unknown"]);
const SENSITIVE_INPUT_HANDLING = new Set<SensitiveInputHandling>(["none", "authentication_only", "business_payload", "unknown"]);
const DATA_CLASSIFICATIONS = new Set<ToolDataClassification>(["public", "internal", "user_private", "secret", "unknown"]);
const DATA_SUBJECTS = new Set<ToolDataSubject>(["caller", "named_subject", "third_party", "unknown"]);
const PURPOSE_BINDINGS = new Set<ToolPurposeBinding>(["task_bound", "operator_defined", "unknown"]);
const PATH_SCOPES = new Set<ToolPathScope>(["host_workspace", "isolated_environment"]);

for (const manifest of builtinManifests()) registerToolManifest(manifest, { issuer: "builtin" });

export function configureToolManifestSigning(config: PluginConfig): void {
  configuredConfig = config;
  manifestSigningSecret = loadOrCreateStateSecret(config, "tool-manifest");
  resetRegistry();
  loadPersistedRegistry();
}

export function registerToolManifest(
  manifest: ToolSecurityManifest,
  metadata: {
    schema?: unknown;
    endpoint?: string;
    version?: string;
    expectedDigest?: string;
    issuer?: "builtin" | "local-administrator";
  } = {},
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
    signature: toolManifestSignature(manifest, { ...metadata, digest }),
    issuer: metadata.issuer || "local-administrator",
    registeredAt: new Date().toISOString(),
  };
  registry.set(canonical, envelope);
  for (const [alias, owner] of aliases) {
    if (owner === canonical) aliases.delete(alias);
  }
  aliases.set(canonical, canonical);
  for (const alias of manifest.aliases) aliases.set(normalizeToolId(alias), canonical);
  if (envelope.issuer !== "builtin") customToolIds.add(canonical);
  if (!loadingPersistedRegistry && envelope.issuer !== "builtin") persistRegistry();
  return structuredClone(envelope);
}

export function resolveToolManifest(toolId: string): ToolManifestEnvelope | null {
  const canonical = aliases.get(normalizeToolId(toolId)) || normalizeToolId(toolId);
  const envelope = registry.get(canonical);
  return envelope ? structuredClone(envelope) : null;
}

export function listToolManifests(): ToolManifestEnvelope[] {
  return [...registry.values()]
    .map((item) => structuredClone(item))
    .sort((left, right) => left.manifest.toolId.localeCompare(right.manifest.toolId));
}

export function listToolManifestRevocations(): ToolManifestRevocation[] {
  return [...revocations.values()].map((item) => structuredClone(item)).sort((left, right) => right.revokedAt.localeCompare(left.revokedAt));
}

export function revokeToolManifest(toolId: string, reason: string): ToolManifestRevocation {
  const resolved = resolveToolManifest(toolId);
  if (!resolved) throw new Error(`tool_manifest_not_registered:${toolId}`);
  const canonical = normalizeToolId(resolved.manifest.toolId);
  const revocation: ToolManifestRevocation = {
    toolId: canonical,
    digest: resolved.digest,
    reason: reason.trim() || "administrator revoked tool trust",
    revokedAt: new Date().toISOString(),
  };
  revocations.set(canonical, revocation);
  persistRegistry();
  return structuredClone(revocation);
}

export function restoreToolManifest(toolId: string): boolean {
  const canonical = normalizeToolId(resolveToolManifest(toolId)?.manifest.toolId || toolId);
  const removed = revocations.delete(canonical);
  if (removed) persistRegistry();
  return removed;
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
  const digest = toolManifestDigest(envelope.manifest, envelope);
  if (!constantTimeTextEqual(envelope.digest, digest)) return false;
  return verifyToolManifestSignature(envelope);
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
      signature_present: Boolean(supplied.signature),
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

  const revocation = revocations.get(normalizeToolId(registered.manifest.toolId));
  if (revocation && revocation.digest === registered.digest) {
    return [finding("block", "tool_manifest_revoked", {
      toolName,
      normalizedTool,
      revocation: structuredClone(revocation),
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
  resetRegistry();
  persistRegistry();
}

function resetRegistry(): void {
  registry.clear();
  aliases.clear();
  customToolIds.clear();
  revocations.clear();
  for (const manifest of builtinManifests()) registerToolManifest(manifest, { issuer: "builtin" });
}

function persistedRegistryPath(): string {
  const stateDir = configuredConfig?.storage.stateDir || process.env.OPENCLAW_STATE_DIR?.trim() || join(homedir(), ".openclaw");
  return join(stateDir, "agentsentry", "tool-manifest-registry.json");
}

function loadPersistedRegistry(): void {
  const path = persistedRegistryPath();
  if (!existsSync(path)) return;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as { manifests?: unknown; revocations?: unknown };
    loadingPersistedRegistry = true;
    if (Array.isArray(parsed.manifests)) {
      for (const raw of parsed.manifests) {
        const envelope = parsePersistedEnvelope(raw);
        if (!envelope || !verifyToolManifest(envelope)) continue;
        registerToolManifest(envelope.manifest, {
          schema: envelope.schema,
          endpoint: envelope.endpoint,
          version: envelope.version,
          expectedDigest: envelope.digest,
          issuer: "local-administrator",
        });
      }
    }
    if (Array.isArray(parsed.revocations)) {
      for (const raw of parsed.revocations) {
        const item = parseRevocation(raw);
        if (item) revocations.set(item.toolId, item);
      }
    }
  } catch {
    // A malformed local registry is ignored. Built-in manifests remain available.
  } finally {
    loadingPersistedRegistry = false;
  }
}

function persistRegistry(): void {
  if (!configuredConfig || loadingPersistedRegistry) return;
  const path = persistedRegistryPath();
  const temp = `${path}.${process.pid}.tmp`;
  const manifests = [...customToolIds]
    .map((toolId) => registry.get(toolId))
    .filter((item): item is ToolManifestEnvelope => Boolean(item));
  const payload = JSON.stringify({ version: 1, manifests, revocations: listToolManifestRevocations() }, null, 2) + "\n";
  mkdirSync(dirname(path), { recursive: true });
  try {
    writeFileSync(temp, payload, { encoding: "utf8", mode: 0o600, flag: "w" });
    renameSync(temp, path);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
}

function parsePersistedEnvelope(value: unknown): ToolManifestEnvelope | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  if (!item.manifest || typeof item.manifest !== "object" || Array.isArray(item.manifest) || typeof item.digest !== "string" || typeof item.signature !== "string") return null;
  try {
    validateManifest(item.manifest as ToolSecurityManifest);
    return {
      manifest: item.manifest as ToolSecurityManifest,
      schema: item.schema,
      endpoint: typeof item.endpoint === "string" ? item.endpoint : undefined,
      version: typeof item.version === "string" ? item.version : undefined,
      digest: item.digest,
      signature: item.signature,
      issuer: "local-administrator",
      registeredAt: typeof item.registeredAt === "string" ? item.registeredAt : undefined,
    };
  } catch {
    return null;
  }
}

function parseRevocation(value: unknown): ToolManifestRevocation | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  if (typeof item.toolId !== "string" || typeof item.digest !== "string" || typeof item.reason !== "string" || typeof item.revokedAt !== "string") return null;
  return { toolId: normalizeToolId(item.toolId), digest: item.digest, reason: item.reason, revokedAt: item.revokedAt };
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
      signature: typeof obj.signature === "string" ? obj.signature : "",
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
  if (manifest.accessScope !== undefined && !ACCESS_SCOPES.has(manifest.accessScope)) {
    throw new TypeError("tool manifest contains an invalid access scope");
  }
  if (manifest.sensitiveInputHandling !== undefined && !SENSITIVE_INPUT_HANDLING.has(manifest.sensitiveInputHandling)) {
    throw new TypeError("tool manifest contains an invalid sensitive input handling declaration");
  }
  for (const fieldList of [manifest.credentialFields, manifest.targetFields, manifest.subjectFields]) {
    if (fieldList !== undefined && (!Array.isArray(fieldList) || fieldList.some((field) => typeof field !== "string" || !field.trim()))) {
      throw new TypeError("tool manifest field declarations must be non-empty strings");
    }
  }
  if (manifest.dataClassification !== undefined && !DATA_CLASSIFICATIONS.has(manifest.dataClassification)) {
    throw new TypeError("tool manifest contains an invalid data classification");
  }
  if (manifest.dataSubjects !== undefined && (!Array.isArray(manifest.dataSubjects) || !manifest.dataSubjects.length || manifest.dataSubjects.some((subject) => !DATA_SUBJECTS.has(subject)))) {
    throw new TypeError("tool manifest contains an invalid data subject declaration");
  }
  if (manifest.purposeBinding !== undefined && !PURPOSE_BINDINGS.has(manifest.purposeBinding)) {
    throw new TypeError("tool manifest contains an invalid purpose binding");
  }
  if (manifest.pathScope !== undefined && !PATH_SCOPES.has(manifest.pathScope)) {
    throw new TypeError("tool manifest contains an invalid path scope");
  }
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

export function toolManifestSignature(
  manifest: ToolSecurityManifest,
  metadata: { schema?: unknown; endpoint?: string; version?: string; digest?: string } = {},
): string {
  const payload = stableSerialize({
    digest: metadata.digest || toolManifestDigest(manifest, metadata),
    tool_id: manifest.toolId,
    endpoint: metadata.endpoint || "",
    version: metadata.version || "",
  });
  return createHmac("sha256", manifestSigningSecret).update(payload, "utf8").digest("base64url");
}

function verifyToolManifestSignature(envelope: ToolManifestEnvelope): boolean {
  if (!envelope.signature) return false;
  const expected = Buffer.from(toolManifestSignature(envelope.manifest, envelope));
  const supplied = Buffer.from(envelope.signature);
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
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
    evidence: {
      ...evidence,
      ...(verdict === "block"
        ? interventionEvidence("safety_boundary", { causal_certainty: "observed" })
        : interventionEvidence("risk_only")),
    },
  };
}

function builtinManifests(): ToolSecurityManifest[] {
  return [
    manifest("read_webpage", ["browser.open", "browser_open", "open_browser", "fetch_url", "web.open", "read_email", "read_pdf", "analyze_image"], ["external_web"], ["network_read"], false, false, false, "external"),
    manifest("call_api", [], ["third_party_api"], ["network_read", "network_write"], true, true, true, "external"),
    manifest("read_file", ["read", "open"], ["workspace"], ["file_read"], false, false, true, "workspace"),
    manifest("write_file", ["write", "create", "edit", "replace", "patch"], ["user", "workspace"], ["file_write", "persistent_state"], true, false, true, "workspace"),
    manifest("send_email", [], ["user", "workspace", "email"], ["network_write"], true, true, true, "external"),
    manifest("sessions_send", ["agent.send", "send_to_agent", "handoff_message", "agent_message"], ["unknown"], ["none"], false, false, false, "unknown"),
    manifest("shell_exec", ["exec", "shell", "bash", "run_shell", "terminal"], ["user", "workspace"], ["process_exec", "file_write", "network_write"], true, true, true, "unknown"),
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
