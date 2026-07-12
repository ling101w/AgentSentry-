import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { ApprovalCache } from "../../core/approval-cache.ts";
import { computeOperationKey } from "../../core/operation.ts";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("allow-always cache", () => {
  it("matches normalized parameters and the same policy context only", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentsentry-cache-"));
    tempDirs.push(dir);
    const config = new PluginConfig();
    config.storage.stateDir = dir;
    const cache = new ApprovalCache(config);
    const context = { profile: "competition", policy: { deterministic: true }, taskSpec: { version: 2, sourceMessageHash: "task-a" } };
    const key = computeOperationKey("send_email", { body: "status", recipient: "user@example.com" }, context);
    cache.add(key, "send_email");

    expect(cache.has(computeOperationKey("send_email", { recipient: "user@example.com", body: "status" }, context))).toBe(true);
    expect(cache.has(computeOperationKey("send_email", { recipient: "other@example.com", body: "status" }, context))).toBe(false);
    expect(cache.has(computeOperationKey("send_email", { recipient: "user@example.com", body: "status" }, { profile: "high-security" }))).toBe(false);
    expect(cache.has(computeOperationKey("send_email", { recipient: "user@example.com", body: "status" }, {
      ...context,
      taskSpec: { version: 2, sourceMessageHash: "task-b" },
    }))).toBe(false);
  });

  it("persists hits and resets cleanly", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentsentry-cache-"));
    tempDirs.push(dir);
    const config = new PluginConfig();
    config.storage.stateDir = dir;
    const cache = new ApprovalCache(config);
    cache.add("key", "tool");
    expect(cache.recordHit("key")?.hits).toBe(1);
    expect(new ApprovalCache(config).has("key")).toBe(true);
    cache.reset();
    expect(cache.size()).toBe(0);
  });
});
