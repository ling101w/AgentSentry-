import { appendFileSync, existsSync, mkdirSync, openSync, readSync, closeSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { PluginConfig } from "../config.ts";

export type RecordSeverity = "info" | "success" | "warning" | "danger";

export type AgentSentryRecord = {
  id: string;
  run_id: string;
  session_key: string;
  type: string;
  layer: string;
  severity: RecordSeverity;
  title: string;
  summary: string;
  payload: Record<string, unknown>;
  created_at: string;
};

export class RecordStore {
  readonly stateDir: string;
  readonly dataDir: string;
  readonly recordsPath: string;
  private maxRecords: number;
  private writeCount = 0;
  private countCache: { size: number; mtimeMs: number; count: number } | null = null;
  private statsCache = new Map<number, { size: number; mtimeMs: number; value: Record<string, unknown> }>();

  constructor(config: PluginConfig) {
    this.stateDir = config.storage.stateDir || process.env.OPENCLAW_STATE_DIR?.trim() || join(homedir(), ".openclaw");
    this.dataDir = join(this.stateDir, "agentsentry");
    this.recordsPath = join(this.dataDir, "records.jsonl");
    this.maxRecords = config.storage.maxRecords;
    mkdirSync(this.dataDir, { recursive: true });
    if (!existsSync(this.recordsPath)) writeFileSync(this.recordsPath, "", "utf8");
  }

  add(input: Omit<AgentSentryRecord, "id" | "created_at"> & { id?: string; created_at?: string }): AgentSentryRecord {
    const record: AgentSentryRecord = {
      id: input.id || newId("rec"),
      created_at: input.created_at || new Date().toISOString(),
      run_id: input.run_id,
      session_key: input.session_key,
      type: input.type,
      layer: input.layer,
      severity: input.severity,
      title: input.title,
      summary: input.summary,
      payload: input.payload,
    };
    appendFileSync(this.recordsPath, `${JSON.stringify(record)}\n`, "utf8");
    this.writeCount += 1;
    this.invalidateCachesAfterAppend();
    if (this.writeCount % 200 === 0) this.compact();
    return record;
  }

  list(limit = 500): AgentSentryRecord[] {
    const lines = readTailLines(this.recordsPath, Math.max(1, limit));
    const records: AgentSentryRecord[] = [];
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        records.push(JSON.parse(line) as AgentSentryRecord);
      } catch {
        // Ignore malformed partial lines; JSONL append can leave one if the process is killed.
      }
    }
    return records.reverse();
  }

  get(id: string): AgentSentryRecord | null {
    const safeId = String(id || "").trim();
    if (!safeId) return null;
    if (!existsSync(this.recordsPath)) return null;
    return findRecordById(this.recordsPath, safeId);
  }

  count(): number {
    if (!existsSync(this.recordsPath)) return 0;
    const stat = statSync(this.recordsPath);
    if (!stat.size) return 0;
    if (this.countCache && this.countCache.size === stat.size && this.countCache.mtimeMs === stat.mtimeMs) {
      return this.countCache.count;
    }
    const fd = openSync(this.recordsPath, "r");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    let bytesRead = 0;
    try {
      do {
        bytesRead = readSync(fd, buffer, 0, buffer.length, null);
        for (let i = 0; i < bytesRead; i += 1) {
          if (buffer[i] === 10) total += 1;
        }
      } while (bytesRead > 0);
    } finally {
      closeSync(fd);
    }
    this.countCache = { size: stat.size, mtimeMs: stat.mtimeMs, count: total };
    return total;
  }

  stats(limit = 2000): Record<string, unknown> {
    const safeLimit = Math.max(1, Math.trunc(limit));
    const stat = existsSync(this.recordsPath) ? statSync(this.recordsPath) : { size: 0, mtimeMs: 0 };
    const cached = this.statsCache.get(safeLimit);
    if (cached && cached.size === stat.size && cached.mtimeMs === stat.mtimeMs) {
      return cached.value;
    }
    const records = this.list(safeLimit);
    const totalRecords = this.count();
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const byLayer: Record<string, number> = {};
    const sessions = new Set<string>();
    const runs = new Set<string>();

    for (const record of records) {
      byType[record.type] = (byType[record.type] || 0) + 1;
      bySeverity[record.severity] = (bySeverity[record.severity] || 0) + 1;
      byLayer[record.layer] = (byLayer[record.layer] || 0) + 1;
      sessions.add(record.session_key);
      runs.add(record.run_id);
    }

    const value = {
      total: totalRecords,
      totalRecords,
      windowRecords: records.length,
      windowLimit: safeLimit,
      sessions: sessions.size,
      runs: runs.size,
      byType,
      bySeverity,
      byLayer,
      latest: records[0]?.created_at || null,
      recordsPath: this.recordsPath,
    };
    this.statsCache.set(safeLimit, { size: stat.size, mtimeMs: stat.mtimeMs, value });
    return value;
  }

  reset(): void {
    writeFileSync(this.recordsPath, "", "utf8");
    this.countCache = { size: 0, mtimeMs: statSync(this.recordsPath).mtimeMs, count: 0 };
    this.statsCache.clear();
  }

  compact(): void {
    const records = this.list(this.maxRecords);
    const tmpPath = `${this.recordsPath}.tmp`;
    writeFileSync(tmpPath, records.reverse().map((record) => JSON.stringify(record)).join("\n") + (records.length ? "\n" : ""), "utf8");
    try {
      renameSync(tmpPath, this.recordsPath);
      const stat = statSync(this.recordsPath);
      this.countCache = { size: stat.size, mtimeMs: stat.mtimeMs, count: records.length };
      this.statsCache.clear();
    } catch {
      rmSync(tmpPath, { force: true });
    }
  }

  private invalidateCachesAfterAppend(): void {
    this.statsCache.clear();
    if (!this.countCache) return;
    try {
      const stat = statSync(this.recordsPath);
      this.countCache = {
        size: stat.size,
        mtimeMs: stat.mtimeMs,
        count: this.countCache.count + 1,
      };
    } catch {
      this.countCache = null;
    }
  }
}

export function newId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(16).slice(2, 10)}`;
}

export function runIdForSession(sessionKey: string | undefined): string {
  if (!sessionKey) return "session_unknown";
  return `session_${Buffer.from(sessionKey).toString("base64url").slice(0, 24)}`;
}

function readTailLines(path: string, limit: number): string[] {
  if (!existsSync(path)) return [];
  const stat = statSync(path);
  if (!stat.size) return [];
  const fd = openSync(path, "r");
  const chunkSize = 128 * 1024;
  const chunks: Buffer[] = [];
  let position = stat.size;
  let newlineCount = 0;
  try {
    while (position > 0 && newlineCount <= limit) {
      const readSize = Math.min(chunkSize, position);
      position -= readSize;
      const buffer = Buffer.allocUnsafe(readSize);
      const bytesRead = readSync(fd, buffer, 0, readSize, position);
      if (bytesRead <= 0) break;
      const chunk = bytesRead === buffer.length ? buffer : buffer.subarray(0, bytesRead);
      chunks.push(chunk);
      for (let i = 0; i < chunk.length; i += 1) {
        if (chunk[i] === 10) newlineCount += 1;
      }
    }
  } finally {
    closeSync(fd);
  }
  const text = Buffer.concat(chunks.reverse()).toString("utf8");
  const lines = text.split(/\r?\n/).filter(Boolean);
  return lines.slice(Math.max(0, lines.length - limit));
}

function findRecordById(path: string, id: string): AgentSentryRecord | null {
  const stat = statSync(path);
  if (!stat.size) return null;
  const fd = openSync(path, "r");
  const chunkSize = 256 * 1024;
  const tailParts: string[] = [];
  let position = stat.size;
  try {
    while (position > 0) {
      const readSize = Math.min(chunkSize, position);
      position -= readSize;
      const buffer = Buffer.allocUnsafe(readSize);
      const bytesRead = readSync(fd, buffer, 0, readSize, position);
      if (bytesRead <= 0) break;
      const chunkText = buffer.subarray(0, bytesRead).toString("utf8");
      tailParts.unshift(chunkText);
      const text = tailParts.join("");
      if (!text.includes(id) && tailParts.length < 8) continue;
      const lines = text.split(/\r?\n/);
      const start = position === 0 ? 0 : 1;
      for (let i = lines.length - 1; i >= start; i -= 1) {
        const line = lines[i];
        if (!line || !line.includes(id)) continue;
        try {
          const record = JSON.parse(line) as AgentSentryRecord;
          if (record.id === id) return record;
        } catch {
          // Ignore malformed partial lines; keep scanning older chunks.
        }
      }
      if (tailParts.length > 8) {
        tailParts.splice(0, tailParts.length - 8);
      }
    }
  } finally {
    closeSync(fd);
  }
  return null;
}
