import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { PluginConfig } from "../config.ts";

export type ApprovalCacheEntry = {
  operation_key: string;
  toolName: string;
  created_at: string;
  last_hit_at: string | null;
  hits: number;
};

export class ApprovalCache {
  readonly path: string;
  private entries = new Map<string, ApprovalCacheEntry>();

  constructor(config: PluginConfig) {
    this.path = approvalCachePath(config);
    this.load();
  }

  has(operationKey: string): boolean {
    return this.entries.has(operationKey);
  }

  add(operationKey: string, toolName: string): ApprovalCacheEntry {
    const existing = this.entries.get(operationKey);
    if (existing) return existing;
    const entry: ApprovalCacheEntry = {
      operation_key: operationKey,
      toolName,
      created_at: new Date().toISOString(),
      last_hit_at: null,
      hits: 0,
    };
    this.entries.set(operationKey, entry);
    this.save();
    return entry;
  }

  recordHit(operationKey: string): ApprovalCacheEntry | null {
    const entry = this.entries.get(operationKey);
    if (!entry) return null;
    entry.hits += 1;
    entry.last_hit_at = new Date().toISOString();
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
        if (entry) this.entries.set(entry.operation_key, entry);
      }
    } catch {
      this.entries.clear();
    }
  }

  private save(): void {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify({ entries: this.list() }, null, 2) + "\n", "utf8");
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
  return {
    operation_key: operationKey,
    toolName,
    created_at: typeof obj.created_at === "string" ? obj.created_at : new Date().toISOString(),
    last_hit_at: typeof obj.last_hit_at === "string" ? obj.last_hit_at : null,
    hits: typeof obj.hits === "number" && Number.isFinite(obj.hits) ? Math.max(0, Math.trunc(obj.hits)) : 0,
  };
}
