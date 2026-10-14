import { appendFile, chmod, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";

type WritableEvent = {
  severity: string;
};

export type EventWriterOptions = {
  batchIntervalMs?: number;
  batchSize?: number;
  maxQueue?: number;
  maxQueuedBytes?: number;
  reservedEvents?: number;
  reservedBytes?: number;
  compactEvery?: number;
  maxRecords: number;
};

export type EventWriterStatus = {
  state: "healthy" | "backpressured" | "failed" | "closed";
  pendingEvents: number;
  pendingBytes: number;
  inFlightBatches: number;
  maxEvents: number;
  maxBytes: number;
  droppedEvents: number;
  droppedBySeverity: Record<string, number>;
  writeFailures: number;
  failedEvents: number;
  lastSuccessfulWrite: string | null;
  lastError: string | null;
};

type QueuedEvent = { line: string; bytes: number; generation: number };

export class EventWriter<T extends WritableEvent> {
  private readonly recordsPath: string;
  private readonly batchIntervalMs: number;
  private batchSize: number;
  private readonly maxQueue: number;
  private readonly compactEvery: number;
  private readonly maxRecords: number;
  private readonly maxQueuedBytes: number;
  private readonly reservedEvents: number;
  private readonly reservedBytes: number;
  private queue: QueuedEvent[] = [];
  private pendingEvents = 0;
  private pendingBytes = 0;
  private inFlightBatches = 0;
  private droppedBySeverity: Record<string, number> = {};
  private writeFailures = 0;
  private failedEvents = 0;
  private lastSuccessfulWrite: string | null = null;
  private lastError: string | null = null;
  private generation = 0;
  private flushTask: Promise<void> | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private operation: Promise<void> = Promise.resolve();
  private persistedSinceCompact = 0;
  private closing = false;

  constructor(recordsPath: string, options: EventWriterOptions) {
    this.recordsPath = recordsPath;
    this.batchIntervalMs = options.batchIntervalMs ?? 30;
    this.batchSize = options.batchSize ?? 64;
    this.maxQueue = options.maxQueue ?? 5000;
    this.maxQueuedBytes = options.maxQueuedBytes ?? 8 * 1024 * 1024;
    this.reservedEvents = Math.min(this.maxQueue, options.reservedEvents ?? Math.floor(this.maxQueue / 5));
    this.reservedBytes = Math.min(this.maxQueuedBytes, options.reservedBytes ?? Math.floor(this.maxQueuedBytes / 5));
    this.compactEvery = options.compactEvery ?? Math.max(200, options.maxRecords);
    this.maxRecords = options.maxRecords;
  }

  enqueue(event: T): boolean {
    let line: string;
    try { line = JSON.stringify(event) + "\n"; } catch { return this.drop(event.severity); }
    const bytes = Buffer.byteLength(line, "utf8");
    const priority = event.severity === "warning" || event.severity === "danger";
    const maxEvents = this.maxQueue - (priority ? 0 : this.reservedEvents);
    const maxBytes = this.maxQueuedBytes - (priority ? 0 : this.reservedBytes);
    if (this.closing || this.pendingEvents >= maxEvents || this.pendingBytes + bytes > maxBytes) return this.drop(event.severity);
    this.queue.push({ line, bytes, generation: this.generation });
    this.pendingEvents += 1;
    this.pendingBytes += bytes;
    if (this.queue.length >= this.batchSize) this.scheduleFlush(0);
    else this.scheduleFlush(this.batchIntervalMs);
    return true;
  }

  status(): EventWriterStatus {
    return {
      state: this.closing ? "closed" : this.lastError ? "failed"
        : this.pendingEvents >= this.maxQueue - this.reservedEvents || this.pendingBytes >= this.maxQueuedBytes - this.reservedBytes ? "backpressured" : "healthy",
      pendingEvents: this.pendingEvents, pendingBytes: this.pendingBytes, inFlightBatches: this.inFlightBatches,
      maxEvents: this.maxQueue, maxBytes: this.maxQueuedBytes,
      droppedEvents: Object.values(this.droppedBySeverity).reduce((sum, value) => sum + value, 0),
      droppedBySeverity: { ...this.droppedBySeverity }, writeFailures: this.writeFailures, failedEvents: this.failedEvents,
      lastSuccessfulWrite: this.lastSuccessfulWrite, lastError: this.lastError,
    };
  }

  private drop(severity: string): false {
    Object.defineProperty(this.droppedBySeverity, severity, {
      value: (Object.hasOwn(this.droppedBySeverity, severity) ? this.droppedBySeverity[severity] : 0) + 1,
      writable: true, enumerable: true, configurable: true,
    });
    return false;
  }

  setBatchSize(batchSize: number): void {
    if (!Number.isFinite(batchSize)) return;
    this.batchSize = Math.max(1, Math.min(1000, Math.trunc(batchSize)));
    if (this.queue.length >= this.batchSize) this.scheduleFlush(0);
  }

  flush(): Promise<void> {
    this.clearTimer();
    if (this.flushTask) return this.flushTask;
    const generation = this.generation;
    const task = this.operation.then(() => this.drain(generation));
    const completion = task.finally(() => { if (this.flushTask === completion) this.flushTask = null; });
    this.flushTask = completion;
    this.operation = completion.catch(() => undefined);
    return completion;
  }

  private async drain(generation: number): Promise<void> {
    let firstError: unknown;
    while (this.queue[0]?.generation === generation) {
      const batch = this.queue.splice(0, this.batchSize);
      const bytes = batch.reduce((sum, item) => sum + item.bytes, 0);
      this.inFlightBatches = 1;
      let appended = false;
      try {
        const prefix = await needsLeadingNewline(this.recordsPath) ? "\n" : "";
        await appendFile(this.recordsPath, prefix + batch.map((item) => item.line).join(""), "utf8");
        appended = true;
        this.lastSuccessfulWrite = new Date().toISOString();
        this.lastError = null;
        this.persistedSinceCompact += batch.length;
        if (this.persistedSinceCompact >= this.compactEvery) {
          this.persistedSinceCompact %= this.compactEvery;
          await compactFile(this.recordsPath, this.maxRecords);
        }
      } catch (error) {
        firstError ??= error;
        this.writeFailures += 1;
        if (!appended) this.failedEvents += batch.length;
        this.lastError = error instanceof Error ? error.message : String(error);
      } finally {
        this.pendingEvents -= batch.length;
        this.pendingBytes -= bytes;
        this.inFlightBatches = 0;
      }
    }
    if (firstError) throw firstError;
  }

  reset(): Promise<void> {
    this.clearTimer();
    this.pendingEvents -= this.queue.length;
    this.pendingBytes -= this.queue.reduce((sum, item) => sum + item.bytes, 0);
    this.queue = [];
    this.generation += 1;
    this.flushTask = null;
    this.persistedSinceCompact = 0;
    const task = this.operation.then(() => this.maintenance(() => writeFile(this.recordsPath, "", { encoding: "utf8", mode: 0o600 })));
    this.operation = task.catch(() => undefined);
    return task;
  }

  compact(): Promise<void> {
    const flushed = this.flush();
    const task = flushed.then(() => this.maintenance(() => compactFile(this.recordsPath, this.maxRecords)));
    this.flushTask = null;
    this.operation = task.catch(() => undefined);
    return task;
  }

  pruneBefore(cutoff: string): Promise<void> {
    const flushed = this.flush();
    const task = flushed.then(() => this.maintenance(() => compactFile(this.recordsPath, this.maxRecords, cutoff)));
    this.flushTask = null;
    this.operation = task.catch(() => undefined);
    return task;
  }

  private async maintenance(operation: () => Promise<void>): Promise<void> {
    try { await operation(); this.lastError = null; }
    catch (error) {
      this.writeFailures += 1;
      this.lastError = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  async close(): Promise<void> {
    this.closing = true;
    await this.flush();
  }

  private scheduleFlush(delay: number): void {
    if (this.timer) {
      if (delay > 0) return;
      this.clearTimer();
    }
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.flush().catch(() => {
        // Failures remain visible through status(); timer callbacks never reject globally.
      });
    }, delay);
    this.timer.unref?.();
  }

  private clearTimer(): void {
    if (!this.timer) return;
    clearTimeout(this.timer);
    this.timer = null;
  }
}

async function needsLeadingNewline(recordsPath: string): Promise<boolean> {
  try {
    const info = await stat(recordsPath);
    if (!info.size) return false;
    const handle = await open(recordsPath, "r");
    try {
      const byte = Buffer.allocUnsafe(1);
      const result = await handle.read(byte, 0, 1, info.size - 1);
      return result.bytesRead === 1 && byte[0] !== 10;
    } finally {
      await handle.close();
    }
  } catch {
    return false;
  }
}

async function compactFile(recordsPath: string, maxRecords: number, cutoff?: string): Promise<void> {
  const tmpPath = `${recordsPath}.tmp`;
  try {
    const content = await readFile(recordsPath, "utf8");
    const cutoffMs = cutoff ? new Date(cutoff).getTime() : Number.NaN;
    const lines = content.split(/\r?\n/).filter(Boolean).filter((line) => {
      if (!Number.isFinite(cutoffMs)) return true;
      try {
        const parsed = JSON.parse(line) as { created_at?: unknown };
        const createdAt = new Date(String(parsed.created_at || "")).getTime();
        return !Number.isFinite(createdAt) || createdAt >= cutoffMs;
      } catch {
        // Preserve malformed lines for forensic review; normal compaction still bounds the file.
        return true;
      }
    }).slice(-maxRecords);
    await writeFile(tmpPath, `${lines.join("\n")}${lines.length ? "\n" : ""}`, { encoding: "utf8", mode: 0o600 });
    await rename(tmpPath, recordsPath);
    if (process.platform !== "win32") await chmod(recordsPath, 0o600);
  } catch (error) {
    await rm(tmpPath, { force: true }).catch(() => undefined);
    throw error;
  }
}
