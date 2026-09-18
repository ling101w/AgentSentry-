import { appendFile, chmod, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";

type WritableEvent = {
  severity: string;
};

export type EventWriterOptions = {
  batchIntervalMs?: number;
  batchSize?: number;
  maxQueue?: number;
  compactEvery?: number;
  maxRecords: number;
};

export class EventWriter<T extends WritableEvent> {
  private readonly recordsPath: string;
  private readonly batchIntervalMs: number;
  private batchSize: number;
  private readonly maxQueue: number;
  private readonly compactEvery: number;
  private readonly maxRecords: number;
  private queue: T[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  private operation: Promise<void> = Promise.resolve();
  private persistedSinceCompact = 0;
  private closing = false;

  constructor(recordsPath: string, options: EventWriterOptions) {
    this.recordsPath = recordsPath;
    this.batchIntervalMs = options.batchIntervalMs ?? 30;
    this.batchSize = options.batchSize ?? 64;
    this.maxQueue = options.maxQueue ?? 5000;
    this.compactEvery = options.compactEvery ?? 200;
    this.maxRecords = options.maxRecords;
  }

  enqueue(event: T): boolean {
    if (this.closing) return false;
    if (this.queue.length >= this.maxQueue && event.severity === "info") return false;
    this.queue.push(event);
    if (this.queue.length >= this.batchSize) this.scheduleFlush(0);
    else this.scheduleFlush(this.batchIntervalMs);
    return true;
  }

  setBatchSize(batchSize: number): void {
    if (!Number.isFinite(batchSize)) return;
    this.batchSize = Math.max(1, Math.min(1000, Math.trunc(batchSize)));
    if (this.queue.length >= this.batchSize) this.scheduleFlush(0);
  }

  flush(): Promise<void> {
    this.clearTimer();
    let completion = this.operation;
    while (this.queue.length) {
      const batch = this.queue.splice(0, this.batchSize);
      const task = this.operation.then(async () => {
        const prefix = await needsLeadingNewline(this.recordsPath) ? "\n" : "";
        await appendFile(this.recordsPath, `${prefix}${batch.map((item) => JSON.stringify(item)).join("\n")}\n`, "utf8");
        this.persistedSinceCompact += batch.length;
        if (this.persistedSinceCompact >= this.compactEvery) {
          this.persistedSinceCompact %= this.compactEvery;
          await compactFile(this.recordsPath, this.maxRecords);
        }
      });
      this.operation = task.catch(() => undefined);
      completion = task;
    }
    return completion;
  }

  reset(): Promise<void> {
    this.clearTimer();
    this.queue = [];
    this.persistedSinceCompact = 0;
    const task = this.operation.then(() => writeFile(this.recordsPath, "", { encoding: "utf8", mode: 0o600 }));
    this.operation = task.catch(() => undefined);
    return task;
  }

  compact(): Promise<void> {
    const flushed = this.flush();
    const task = flushed.then(() => compactFile(this.recordsPath, this.maxRecords));
    this.operation = task.catch(() => undefined);
    return task;
  }

  pruneBefore(cutoff: string): Promise<void> {
    const flushed = this.flush();
    const task = flushed.then(() => compactFile(this.recordsPath, this.maxRecords, cutoff));
    this.operation = task.catch(() => undefined);
    return task;
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
        // Telemetry writes are best-effort; the in-memory view remains available.
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
  } catch {
    await rm(tmpPath, { force: true }).catch(() => undefined);
  }
}
