import { mkdtemp, readFile, rm, appendFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EventWriter } from "../../core/persistence/event-writer.ts";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, appendFile: vi.fn(actual.appendFile) };
});
const roots: string[] = [];
const writers: EventWriter<{ severity: string; payload?: string }>[] = [];
afterEach(async () => {
  for (const writer of writers.splice(0)) await writer.close().catch(() => undefined);
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
  vi.mocked(appendFile).mockClear();
});
async function fixture(options = {}) {
  const root = await mkdtemp(join(tmpdir(), "agentsentry-writer-"));
  roots.push(root);
  const path = join(root, "records.jsonl");
  const writer = new EventWriter<{ severity: string; payload?: string }>(path, { maxRecords: 100, batchIntervalMs: 10000, ...options });
  writers.push(writer);
  return { writer, path };
}

describe("bounded audit persistence", () => {
  it("reserves priority capacity but bounds every severity", async () => {
    const { writer } = await fixture({ maxQueue: 5, reservedEvents: 1 });
    for (let index = 0; index < 4; index++) expect(writer.enqueue({ severity: "info" })).toBe(true);
    expect(writer.enqueue({ severity: "info" })).toBe(false);
    expect(writer.enqueue({ severity: "danger" })).toBe(true);
    expect(writer.enqueue({ severity: "warning" })).toBe(false);
    expect(writer.status()).toMatchObject({ pendingEvents: 5, droppedEvents: 2, droppedBySeverity: { info: 1, warning: 1 } });
    await writer.flush();
    expect(writer.status()).toMatchObject({ pendingEvents: 0, pendingBytes: 0, inFlightBatches: 0 });
  });

  it("bounds bytes including oversized priority events and snapshots serialized content", async () => {
    const { writer, path } = await fixture({ maxQueuedBytes: 140, reservedBytes: 30 });
    const event = { severity: "info", payload: "original" };
    expect(writer.enqueue(event)).toBe(true);
    event.payload = "mutated";
    expect(writer.enqueue({ severity: "danger", payload: "x".repeat(200) })).toBe(false);
    await writer.flush();
    expect(await readFile(path, "utf8")).toContain("original");
    expect(await readFile(path, "utf8")).not.toContain("mutated");
  });

  it("counts in-flight writes and coalesces simultaneous flush requests", async () => {
    const { writer } = await fixture({ maxQueue: 2, reservedEvents: 0, batchSize: 1 });
    let release!: () => void;
    vi.mocked(appendFile).mockImplementationOnce(() => new Promise<void>((resolve) => { release = resolve; }));
    writer.enqueue({ severity: "danger" });
    writer.enqueue({ severity: "danger" });
    const flushing = writer.flush();
    expect(writer.flush()).toBe(flushing);
    await vi.waitFor(() => expect(writer.status().inFlightBatches).toBe(1));
    expect(writer.status().pendingEvents).toBe(2);
    expect(writer.enqueue({ severity: "danger" })).toBe(false);
    release();
    await flushing;
    expect(writer.status().pendingEvents).toBe(0);
  });

  it("reports any failed batch even when a later batch succeeds", async () => {
    const { writer } = await fixture({ batchSize: 1 });
    vi.mocked(appendFile).mockRejectedValueOnce(new Error("disk failure"));
    writer.enqueue({ severity: "danger" });
    writer.enqueue({ severity: "danger" });
    await expect(writer.flush()).rejects.toThrow("disk failure");
    expect(writer.status()).toMatchObject({ writeFailures: 1, failedEvents: 1, pendingEvents: 0 });
    expect(writer.status().lastSuccessfulWrite).toMatch(/^\d{4}-/);
  });

  it("keeps automatic failure visible and recovers after a successful write", async () => {
    const { writer } = await fixture({ batchIntervalMs: 1 });
    vi.mocked(appendFile).mockRejectedValueOnce(new Error("disk offline"));
    writer.enqueue({ severity: "warning" });
    await vi.waitFor(() => expect(writer.status()).toMatchObject({ state: "failed", writeFailures: 1, failedEvents: 1, lastError: "disk offline" }));
    writer.enqueue({ severity: "warning" });
    await writer.flush();
    expect(writer.status()).toMatchObject({ state: "healthy", lastError: null, writeFailures: 1, failedEvents: 1 });
  });

  it("surfaces compaction errors instead of reporting a successful maintenance operation", async () => {
    const { writer } = await fixture();
    await expect(writer.compact()).rejects.toThrow();
    expect(writer.status()).toMatchObject({ state: "failed", writeFailures: 1 });
  });

  it("orders reset behind the active batch and preserves records enqueued after reset", async () => {
    const { writer, path } = await fixture({ batchSize: 1 });
    let release!: () => void;
    vi.mocked(appendFile).mockImplementationOnce(() => new Promise<void>((resolve) => { release = resolve; }));
    writer.enqueue({ severity: "warning", payload: "old" });
    const oldFlush = writer.flush();
    await vi.waitFor(() => expect(writer.status().inFlightBatches).toBe(1));
    const reset = writer.reset();
    writer.enqueue({ severity: "warning", payload: "new" });
    const newFlush = writer.flush();
    release();
    await Promise.all([oldFlush, reset, newFlush]);
    expect(await readFile(path, "utf8")).toContain("new");
    expect(await readFile(path, "utf8")).not.toContain("old");
    expect(writer.status()).toMatchObject({ pendingEvents: 0, pendingBytes: 0 });
  });
});
