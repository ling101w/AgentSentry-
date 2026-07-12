import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { newId, RecordStore, runIdForSession, type AgentSentryRecord } from "../../core/records.ts";

type RecordInput = Omit<AgentSentryRecord, "id" | "created_at"> & { id?: string; created_at?: string };

const tempRoots: string[] = [];

afterEach(() => {
  for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function createStore(maxRecords = 1000, previewChars = 1200): RecordStore {
  const stateDir = mkdtempSync(join(tmpdir(), "agentsentry-records-"));
  tempRoots.push(stateDir);
  const config = new PluginConfig();
  config.storage.stateDir = stateDir;
  config.storage.maxRecords = maxRecords;
  config.capture.previewChars = previewChars;
  return new RecordStore(config);
}

function recordInput(index: number, overrides: Partial<RecordInput> = {}): RecordInput {
  return {
    id: `rec-${index}`,
    created_at: `2026-07-12T00:00:${String(index).padStart(2, "0")}.000Z`,
    run_id: `run-${index % 2}`,
    session_key: `session-${index % 3}`,
    type: index % 2 ? "tool_decision" : "session_start",
    layer: index % 2 ? "Tool Boundary" : "Runtime",
    severity: index % 2 ? "warning" : "info",
    title: `record ${index}`,
    summary: `summary ${index}`,
    payload: { index },
    ...overrides,
  };
}

describe("RecordStore persistence boundary", () => {
  it("persists records, returns newest first, and keeps cached statistics coherent", () => {
    const store = createStore();
    expect(store.count()).toBe(0);

    store.add(recordInput(1));
    expect(store.count()).toBe(1);
    store.add(recordInput(2));
    store.add(recordInput(3));

    expect(store.list(2).map((record) => record.id)).toEqual(["rec-3", "rec-2"]);
    expect(store.get(" rec-1 ")).toMatchObject({ id: "rec-1", payload: { index: 1 } });
    expect(store.get("")).toBeNull();
    expect(store.get("missing")).toBeNull();
    expect(store.count()).toBe(3);
    expect(store.stats(10)).toMatchObject({
      total: 3,
      totalRecords: 3,
      windowRecords: 3,
      sessions: 3,
      runs: 2,
      byType: { session_start: 1, tool_decision: 2 },
      bySeverity: { info: 1, warning: 2 },
      byLayer: { Runtime: 1, "Tool Boundary": 2 },
      latest: "2026-07-12T00:00:03.000Z",
    });
  });

  it("deeply redacts both the persisted and API-facing record", () => {
    const store = createStore();
    const apiKey = "sk-abcdefghijklmnopqrstuvwxyz";
    const bearer = "Bearer abcdefghijklmnopqrstuvwxyz";
    const password = "opaqueCredentialValue123456789";
    const privateKey = [
      "-----BEGIN " + "PRIVATE KEY-----",
      "super-sensitive-private-key-material",
      "-----END PRIVATE KEY-----",
    ].join("\n");
    const payload = {
      apiKey,
      nested: {
        authorization: bearer,
        array: [{ password }, `token=${apiKey}`],
      },
    };
    const title = `API token=${apiKey}`;
    const summary = `Captured credential ${bearer}\n${privateKey}`;

    const returned = store.add(recordInput(1, { title, summary, payload }));
    expect(returned.title).not.toBe(title);
    expect(returned.summary).toContain("[redacted]");
    expect(returned.payload).toMatchObject({
      apiKey: "[redacted]",
      nested: { authorization: "[redacted]" },
    });

    const disk = readFileSync(store.recordsPath, "utf8");
    for (const secret of [apiKey, bearer, password, "super-sensitive-private-key-material"]) {
      expect(disk).not.toContain(secret);
    }
    expect(disk).toContain("[redacted]");
    const persisted = store.list(1)[0];
    expect(persisted.title).not.toBe(title);
    expect(persisted.summary).toContain("[redacted]");
    expect(persisted.payload).toMatchObject({
      apiKey: "[redacted]",
      nested: {
        authorization: "[redacted]",
        array: expect.arrayContaining([{ password: "[redacted]" }, expect.stringContaining("[redacted]")]),
      },
    });
  });

  it("compacts to maxRecords and keeps the newest records in chronological file order", () => {
    const store = createStore(3);
    for (let index = 1; index <= 8; index += 1) store.add(recordInput(index));

    store.compact();

    expect(store.count()).toBe(3);
    expect(store.list(10).map((record) => record.id)).toEqual(["rec-8", "rec-7", "rec-6"]);
    const diskIds = readFileSync(store.recordsPath, "utf8")
      .trim()
      .split("\n")
      .map((line) => (JSON.parse(line) as AgentSentryRecord).id);
    expect(diskIds).toEqual(["rec-6", "rec-7", "rec-8"]);
  });

  it("automatically compacts every 200 successful writes", () => {
    const store = createStore(5);
    for (let index = 1; index <= 200; index += 1) store.add(recordInput(index));

    expect(store.count()).toBe(5);
    expect(store.list(10).map((record) => record.id)).toEqual(["rec-200", "rec-199", "rec-198", "rec-197", "rec-196"]);
  });

  it("skips malformed and structurally invalid JSONL without consuming the result limit", () => {
    const store = createStore();
    store.add(recordInput(1));
    appendFileSync(store.recordsPath, "{\"broken\":\nnull\n{}\n", "utf8");
    store.add(recordInput(2));

    expect(store.list(2).map((record) => record.id)).toEqual(["rec-2", "rec-1"]);
    expect(store.count()).toBe(2);
    expect(store.stats(2)).toMatchObject({ totalRecords: 2, windowRecords: 2 });
    expect(store.get("rec-1")?.id).toBe("rec-1");
  });

  it("separates a new append from a crash-truncated tail", () => {
    const store = createStore();
    store.add(recordInput(1));
    appendFileSync(store.recordsPath, "{\"partial\":", "utf8");

    store.add(recordInput(2));

    expect(store.list(2).map((record) => record.id)).toEqual(["rec-2", "rec-1"]);
    expect(store.count()).toBe(2);
    expect(readFileSync(store.recordsPath, "utf8")).toContain("{\"partial\":\n{");
  });

  it("reset clears persisted data and invalidates count and stats caches", () => {
    const store = createStore();
    store.add(recordInput(1));
    expect(store.count()).toBe(1);
    expect(store.stats()).toMatchObject({ totalRecords: 1 });

    store.reset();

    expect(readFileSync(store.recordsPath, "utf8")).toBe("");
    expect(store.list()).toEqual([]);
    expect(store.get("rec-1")).toBeNull();
    expect(store.count()).toBe(0);
    expect(store.stats()).toMatchObject({ totalRecords: 0, windowRecords: 0, latest: null });
    store.add(recordInput(2));
    expect(store.count()).toBe(1);
  });

  it("keeps counts coherent across interleaved store instances", () => {
    const first = createStore();
    const config = new PluginConfig();
    config.storage.stateDir = first.stateDir;
    config.storage.maxRecords = 1000;
    const second = new RecordStore(config);
    expect(first.count()).toBe(0);
    expect(second.count()).toBe(0);

    for (let index = 1; index <= 20; index += 1) {
      first.add(recordInput(index * 2 - 1));
      second.add(recordInput(index * 2));
      expect(first.count()).toBe(index * 2);
      expect(second.count()).toBe(index * 2);
    }

    expect(new Set(first.list(100).map((record) => record.id)).size).toBe(40);
  });

  it("contains serialization failures and does not update caches after an I/O failure", () => {
    const store = createStore();
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const returned = store.add(recordInput(1, { payload: circular }));
    expect(returned.payload).toEqual({ persistence_error: "payload could not be safely serialized" });
    expect(store.list(1)[0].payload).toEqual({ persistence_error: "payload could not be safely serialized" });
    expect(store.count()).toBe(1);

    rmSync(store.dataDir, { recursive: true, force: true });
    expect(() => store.add(recordInput(2))).toThrow();
    mkdirSync(store.dataDir, { recursive: true });
    writeFileSync(store.recordsPath, "", "utf8");
    store.add(recordInput(3));
    expect(store.count()).toBe(1);
    expect(store.list()).toMatchObject([{ id: "rec-3" }]);
  });

  it("uses owner-only audit storage permissions where POSIX modes are available", () => {
    if (process.platform === "win32") return;
    const store = createStore();
    expect(statSync(store.dataDir).mode & 0o777).toBe(0o700);
    expect(statSync(store.recordsPath).mode & 0o777).toBe(0o600);
  });
});

describe("record identifiers", () => {
  it("creates prefixed unique record identifiers", () => {
    const first = newId("alert");
    const second = newId("alert");
    expect(first).toMatch(/^alert_[a-z0-9]+_[a-f0-9]{8}$/);
    expect(second).not.toBe(first);
  });

  it("derives stable, opaque, collision-resistant run IDs from the full session key", () => {
    const commonPrefix = "shared-session-prefix-that-used-to-collide:";
    const first = runIdForSession(`${commonPrefix}one`);
    const repeated = runIdForSession(`${commonPrefix}one`);
    const second = runIdForSession(`${commonPrefix}two`);

    expect(first).toBe(repeated);
    expect(first).toMatch(/^session_[A-Za-z0-9_-]{24}$/);
    expect(first).not.toContain(commonPrefix);
    expect(second).not.toBe(first);
    expect(runIdForSession(undefined)).toBe("session_unknown");
    expect(runIdForSession("")).toBe("session_unknown");
  });
});
