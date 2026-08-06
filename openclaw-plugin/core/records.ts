import { createHash, randomBytes } from "node:crypto";
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { PluginConfig } from "../config.ts";
import { clampText, redactObject } from "./redact.ts";
import { EventWriter } from "./persistence/event-writer.ts";

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
  private previewChars: number;
  private writer: EventWriter<AgentSentryRecord>;
  private recentRecords: AgentSentryRecord[] = [];
  private knownCount: number;
  private resetPending = false;
  private countCache: { size: number; mtimeMs: number; count: number } | null = null;
  private statsCache = new Map<number, { size: number; mtimeMs: number; value: Record<string, unknown> }>();

  constructor(config: PluginConfig) {
    this.stateDir = config.storage.stateDir || process.env.OPENCLAW_STATE_DIR?.trim() || join(homedir(), ".openclaw");
    this.dataDir = join(this.stateDir, "agentsentry");
    this.recordsPath = join(this.dataDir, "records.jsonl");
    this.maxRecords = config.storage.maxRecords;
    this.previewChars = config.capture.previewChars;
    mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    if (!existsSync(this.recordsPath)) writeFileSync(this.recordsPath, "", { encoding: "utf8", mode: 0o600 });
    restrictAuditPermissions(this.dataDir, this.recordsPath);
    this.knownCount = countValidRecords(this.recordsPath);
    this.writer = new EventWriter(this.recordsPath, { maxRecords: this.maxRecords });
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
    const persistedRecord = recordForStorage(record, this.previewChars);
    if (this.writer.enqueue(persistedRecord)) {
      this.recentRecords.push(persistedRecord);
      if (this.recentRecords.length > this.maxRecords) this.recentRecords = this.recentRecords.slice(-this.maxRecords);
      this.knownCount = Math.min(this.maxRecords, this.knownCount + 1);
      this.countCache = null;
      this.statsCache.clear();
    }
    return persistedRecord;
  }

  list(limit = 500): AgentSentryRecord[] {
    const safeLimit = normalizeLimit(limit, 500);
    const persisted = this.resetPending ? [] : readTailRecords(this.recordsPath, safeLimit);
    const seen = new Set<string>();
    return [...this.recentRecords].reverse().concat(persisted)
      .filter((record) => {
        if (seen.has(record.id)) return false;
        seen.add(record.id);
        return true;
      })
      .sort((left, right) => right.created_at.localeCompare(left.created_at))
      .slice(0, safeLimit);
  }

  get(id: string): AgentSentryRecord | null {
    const safeId = String(id || "").trim();
    if (!safeId) return null;
    const inMemory = this.recentRecords.find((record) => record.id === safeId);
    if (inMemory) return inMemory;
    if (this.resetPending) return null;
    if (!existsSync(this.recordsPath)) return null;
    return findRecordById(this.recordsPath, safeId);
  }

  count(): number {
    if (this.resetPending) return this.recentRecords.length;
    if (!existsSync(this.recordsPath)) {
      this.knownCount = Math.min(this.maxRecords, this.recentRecords.length);
      this.countCache = null;
      return this.knownCount;
    }
    const stat = statSync(this.recordsPath);
    let persisted: number;
    if (this.countCache && this.countCache.size === stat.size && this.countCache.mtimeMs === stat.mtimeMs) {
      persisted = this.countCache.count;
    } else {
      persisted = countValidRecords(this.recordsPath);
      this.countCache = { size: stat.size, mtimeMs: stat.mtimeMs, count: persisted };
    }
    if (!this.recentRecords.length) {
      this.knownCount = Math.min(this.maxRecords, persisted);
      return this.knownCount;
    }

    const dedupeWindow = Math.min(this.maxRecords, Math.max(50, this.recentRecords.length * 4));
    const persistedIds = new Set(readTailRecords(this.recordsPath, dedupeWindow).map((record) => record.id));
    const queued = this.recentRecords.filter((record) => !persistedIds.has(record.id)).length;
    this.knownCount = Math.min(this.maxRecords, persisted + queued);
    return this.knownCount;
  }

  stats(limit = 2000): Record<string, unknown> {
    const safeLimit = normalizeLimit(limit, 2000);
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
    this.recentRecords = [];
    this.knownCount = 0;
    this.countCache = null;
    this.statsCache.clear();
    this.resetPending = true;
    void this.writer.reset().finally(() => {
      this.resetPending = false;
    });
  }

  compact(): Promise<void> {
    return this.writer.compact();
  }

  async flush(): Promise<void> {
    await this.writer.flush();
    this.recentRecords = [];
    restrictAuditPermissions(this.dataDir, this.recordsPath);
  }

  async close(): Promise<void> {
    await this.writer.close();
    this.recentRecords = [];
    restrictAuditPermissions(this.dataDir, this.recordsPath);
  }
}

export function newId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`;
}

function restrictAuditPermissions(dataDir: string, recordsPath: string): void {
  if (process.platform === "win32") return;
  try {
    chmodSync(dataDir, 0o700);
    chmodSync(recordsPath, 0o600);
  } catch {
    // Some mounted filesystems do not expose POSIX modes; redaction remains mandatory.
  }
}

export function runIdForSession(sessionKey: string | undefined): string {
  if (!sessionKey) return "session_unknown";
  const digest = createHash("sha256").update(sessionKey, "utf8").digest("base64url").slice(0, 24);
  return `session_${digest}`;
}

function recordForStorage(record: AgentSentryRecord, previewChars: number): AgentSentryRecord {
  let payload: Record<string, unknown>;
  try {
    const redacted = redactObject(record.payload, previewChars);
    payload = isPlainRecord(redacted) ? redacted : { value: redacted };
  } catch {
    payload = { persistence_error: "payload could not be safely serialized" };
  }
  return {
    ...record,
    title: clampText(record.title, previewChars),
    summary: clampText(record.summary, previewChars),
    payload,
  };
}

function readTailRecords(path: string, limit: number): AgentSentryRecord[] {
  if (!existsSync(path)) return [];
  const stat = statSync(path);
  if (!stat.size) return [];
  const fd = openSync(path, "r");
  const chunkSize = 128 * 1024;
  const records: AgentSentryRecord[] = [];
  let carry = Buffer.alloc(0);
  let position = stat.size;
  try {
    while (position > 0 && records.length < limit) {
      const readSize = Math.min(chunkSize, position);
      position -= readSize;
      const buffer = Buffer.allocUnsafe(readSize);
      const bytesRead = readSync(fd, buffer, 0, readSize, position);
      if (bytesRead <= 0) break;
      const chunk = bytesRead === buffer.length ? buffer : buffer.subarray(0, bytesRead);
      const data = carry.length ? Buffer.concat([chunk, carry]) : chunk;
      let lineEnd = data.length;
      for (let i = data.length - 1; i >= 0 && records.length < limit; i -= 1) {
        if (data[i] !== 10) continue;
        const record = parseRecordLine(data.subarray(i + 1, lineEnd).toString("utf8"));
        if (record) records.push(record);
        lineEnd = i;
      }
      carry = data.subarray(0, lineEnd);
    }
    if (position === 0 && records.length < limit && carry.length) {
      const record = parseRecordLine(carry.toString("utf8"));
      if (record) records.push(record);
    }
  } finally {
    closeSync(fd);
  }
  return records;
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
          const record = parseRecordLine(line);
          if (!record) continue;
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

function countValidRecords(path: string): number {
  const fd = openSync(path, "r");
  const chunkSize = 1024 * 1024;
  let carry = Buffer.alloc(0);
  let total = 0;
  try {
    while (true) {
      const buffer = Buffer.allocUnsafe(chunkSize);
      const bytesRead = readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead <= 0) break;
      const chunk = bytesRead === buffer.length ? buffer : buffer.subarray(0, bytesRead);
      const data = carry.length ? Buffer.concat([carry, chunk]) : chunk;
      let lineStart = 0;
      for (let i = 0; i < data.length; i += 1) {
        if (data[i] !== 10) continue;
        if (parseRecordLine(data.subarray(lineStart, i).toString("utf8"))) total += 1;
        lineStart = i + 1;
      }
      carry = data.subarray(lineStart);
    }
    if (carry.length && parseRecordLine(carry.toString("utf8"))) total += 1;
  } finally {
    closeSync(fd);
  }
  return total;
}

function parseRecordLine(line: string): AgentSentryRecord | null {
  if (!line.trim()) return null;
  try {
    const value = JSON.parse(line) as unknown;
    if (!isPlainRecord(value) || !isPlainRecord(value.payload)) return null;
    if (
      !isStringField(value, "id")
      || !isStringField(value, "run_id")
      || !isStringField(value, "session_key")
      || !isStringField(value, "type")
      || !isStringField(value, "layer")
      || !isStringField(value, "title")
      || !isStringField(value, "summary")
      || !isStringField(value, "created_at")
      || !isRecordSeverity(value.severity)
    ) return null;
    return value as AgentSentryRecord;
  } catch {
    return null;
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isStringField(value: Record<string, unknown>, key: string): boolean {
  return typeof value[key] === "string";
}

function isRecordSeverity(value: unknown): value is RecordSeverity {
  return value === "info" || value === "success" || value === "warning" || value === "danger";
}

function normalizeLimit(value: number, fallback: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(1, Math.trunc(value));
}
