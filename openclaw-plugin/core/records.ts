import { createHash, randomBytes } from "node:crypto";
import { appendFileSync, chmodSync, closeSync, existsSync, mkdirSync, openSync, readSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { PluginConfig } from "../config.ts";
import { clampText, redactObject } from "./redact.ts";

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
  private writeCount = 0;
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
    const beforeAppend = fileFingerprint(this.recordsPath);
    const persistedRecord = recordForStorage(record, this.previewChars);
    const separator = needsLeadingNewline(this.recordsPath) ? "\n" : "";
    appendFileSync(this.recordsPath, `${separator}${JSON.stringify(persistedRecord)}\n`, "utf8");
    this.writeCount += 1;
    this.invalidateCachesAfterAppend(beforeAppend);
    if (this.writeCount % 200 === 0) this.compact();
    return persistedRecord;
  }

  list(limit = 500): AgentSentryRecord[] {
    return readTailRecords(this.recordsPath, normalizeLimit(limit, 500));
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
    const total = countValidRecords(this.recordsPath);
    this.countCache = { size: stat.size, mtimeMs: stat.mtimeMs, count: total };
    return total;
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
    writeFileSync(this.recordsPath, "", "utf8");
    this.writeCount = 0;
    this.countCache = { size: 0, mtimeMs: statSync(this.recordsPath).mtimeMs, count: 0 };
    this.statsCache.clear();
  }

  compact(): void {
    const records = this.list(this.maxRecords);
    const tmpPath = `${this.recordsPath}.tmp`;
    writeFileSync(
      tmpPath,
      records.reverse().map((record) => JSON.stringify(record)).join("\n") + (records.length ? "\n" : ""),
      { encoding: "utf8", mode: 0o600 },
    );
    try {
      renameSync(tmpPath, this.recordsPath);
      const stat = statSync(this.recordsPath);
      this.countCache = { size: stat.size, mtimeMs: stat.mtimeMs, count: records.length };
      this.statsCache.clear();
    } catch {
      rmSync(tmpPath, { force: true });
    }
  }

  private invalidateCachesAfterAppend(beforeAppend: FileFingerprint | null): void {
    this.statsCache.clear();
    if (!this.countCache) return;
    if (
      !beforeAppend
      || this.countCache.size !== beforeAppend.size
      || this.countCache.mtimeMs !== beforeAppend.mtimeMs
    ) {
      this.countCache = null;
      return;
    }
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

function needsLeadingNewline(path: string): boolean {
  if (!existsSync(path)) return false;
  const stat = statSync(path);
  if (!stat.size) return false;
  const fd = openSync(path, "r");
  const byte = Buffer.allocUnsafe(1);
  try {
    return readSync(fd, byte, 0, 1, stat.size - 1) === 1 && byte[0] !== 10;
  } finally {
    closeSync(fd);
  }
}

type FileFingerprint = { size: number; mtimeMs: number };

function fileFingerprint(path: string): FileFingerprint | null {
  if (!existsSync(path)) return null;
  const stat = statSync(path);
  return { size: stat.size, mtimeMs: stat.mtimeMs };
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
