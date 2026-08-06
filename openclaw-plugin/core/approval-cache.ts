import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { PluginConfig } from "../config.ts";
import { loadOrCreateStateSecret } from "./state-secret.ts";

export type ApprovalCacheEntry = {
  operation_key: string;
  toolName: string;
  created_at: string;
  expires_at: string | null;
  max_hits: number | null;
  last_hit_at: string | null;
  hits: number;
  token_id: string;
  signature: string;
};

export class ApprovalCache {
  readonly path: string;
  private entries = new Map<string, ApprovalCacheEntry>();
  private readonly config: PluginConfig;
  private readonly secret: Buffer;

  constructor(config: PluginConfig) {
    this.config = config;
    this.path = approvalCachePath(config);
    this.secret = loadOrCreateStateSecret(config, "capability-token");
    this.load();
  }

  has(operationKey: string): boolean {
    const entry = this.entries.get(operationKey);
    if (!entry) return false;
    return this.isUsable(entry);
  }

  add(operationKey: string, toolName: string): ApprovalCacheEntry {
    const existing = this.entries.get(operationKey);
    if (existing && this.isUsable(existing)) return existing;
    const issuedAt = new Date();
    const expiresAt = this.config.capabilityTokens.enabled
      ? new Date(issuedAt.getTime() + this.config.capabilityTokens.ttlMs).toISOString()
      : null;
    const entry: ApprovalCacheEntry = {
      operation_key: operationKey,
      toolName,
      created_at: issuedAt.toISOString(),
      expires_at: expiresAt,
      max_hits: this.config.capabilityTokens.enabled ? this.config.capabilityTokens.maxInvocations : null,
      last_hit_at: null,
      hits: 0,
      token_id: tokenId(operationKey, toolName, issuedAt.toISOString()),
      signature: "",
    };
    entry.signature = signEntry(entry, this.secret);
    this.entries.set(operationKey, entry);
    this.save();
    return entry;
  }

  recordHit(operationKey: string): ApprovalCacheEntry | null {
    const entry = this.entries.get(operationKey);
    if (!entry || !this.isUsable(entry)) return null;
    entry.hits += 1;
    entry.last_hit_at = new Date().toISOString();
    entry.signature = signEntry(entry, this.secret);
    this.save();
    return entry;
  }

  size(): number {
    return this.entries.size;
  }

  list(): ApprovalCacheEntry[] {
    return Array.from(this.entries.values()).sort((a, b) => b.created_at.localeCompare(a.created_at));
  }

  reset(): void {
    this.entries.clear();
    rmSync(this.path, { force: true });
  }

  private load(): void {
    if (!existsSync(this.path)) return;
    try {
      const parsed = JSON.parse(readFileSync(this.path, "utf8")) as { entries?: unknown };
      if (!Array.isArray(parsed.entries)) return;
      for (const item of parsed.entries) {
        const entry = normalizeEntry(item);
        if (entry && this.verify(entry)) this.entries.set(entry.operation_key, entry);
      }
    } catch {
      this.entries.clear();
    }
  }

  private save(): void {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify({ entries: this.list() }, null, 2) + "\n", "utf8");
  }

  private isUsable(entry: ApprovalCacheEntry): boolean {
    if (!this.verify(entry)) return false;
    if (entry.expires_at && Date.parse(entry.expires_at) <= Date.now()) return false;
    if (entry.max_hits !== null && entry.hits >= entry.max_hits) return false;
    return true;
  }

  private verify(entry: ApprovalCacheEntry): boolean {
    if (!this.config.capabilityTokens.enabled) return true;
    return verifySignature(entry, this.secret);
  }
}

export function approvalCachePath(config: PluginConfig): string {
  const stateDir = config.storage.stateDir || process.env.OPENCLAW_STATE_DIR?.trim() || join(homedir(), ".openclaw");
  return join(stateDir, "agentsentry", "approval-cache.json");
}

function normalizeEntry(value: unknown): ApprovalCacheEntry | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const obj = value as Record<string, unknown>;
  const operationKey = typeof obj.operation_key === "string" ? obj.operation_key : "";
  const toolName = typeof obj.toolName === "string" ? obj.toolName : "";
  if (!operationKey || !toolName) return null;
  const createdAt = typeof obj.created_at === "string" ? obj.created_at : new Date().toISOString();
  return {
    operation_key: operationKey,
    toolName,
    created_at: createdAt,
    expires_at: typeof obj.expires_at === "string" ? obj.expires_at : null,
    max_hits: typeof obj.max_hits === "number" && Number.isFinite(obj.max_hits) ? Math.max(1, Math.trunc(obj.max_hits)) : null,
    last_hit_at: typeof obj.last_hit_at === "string" ? obj.last_hit_at : null,
    hits: typeof obj.hits === "number" && Number.isFinite(obj.hits) ? Math.max(0, Math.trunc(obj.hits)) : 0,
    token_id: typeof obj.token_id === "string" && obj.token_id ? obj.token_id : tokenId(operationKey, toolName, createdAt),
    signature: typeof obj.signature === "string" ? obj.signature : "",
  };
}

function tokenId(operationKey: string, toolName: string, createdAt: string): string {
  return createHash("sha256").update(`${operationKey}\n${toolName}\n${createdAt}`).digest("hex").slice(0, 24);
}

function signEntry(entry: ApprovalCacheEntry, secret: Buffer): string {
  return createHmac("sha256", secret).update(stableSerialize(signaturePayload(entry)), "utf8").digest("base64url");
}

function verifySignature(entry: ApprovalCacheEntry, secret: Buffer): boolean {
  if (!entry.signature) return false;
  const expected = Buffer.from(signEntry({ ...entry, signature: "" }, secret));
  const supplied = Buffer.from(entry.signature);
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}

function signaturePayload(entry: ApprovalCacheEntry): Record<string, unknown> {
  return {
    operation_key: entry.operation_key,
    toolName: entry.toolName,
    created_at: entry.created_at,
    expires_at: entry.expires_at,
    max_hits: entry.max_hits,
    hits: entry.hits,
    token_id: entry.token_id,
  };
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
