import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import {
  commitSandboxWorkspace,
  createShellSandboxTransaction,
  discardSandboxWorkspace,
  shouldSandboxShellCommand,
} from "../../core/sandbox.ts";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("workspace shadow sandbox", () => {
  it("wraps side-effecting shell commands but leaves low-risk reads alone", () => {
    expect(shouldSandboxShellCommand("pwd")).toBe(false);
    expect(shouldSandboxShellCommand("echo hi > notes/out.txt")).toBe(true);
  });

  it("commits sandbox changes back to the workspace only on success path", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentsentry-sandbox-test-"));
    tempDirs.push(dir);
    const workspace = join(dir, "workspace");
    mkdirSync(join(workspace, "notes"), { recursive: true });
    writeFileSync(join(workspace, "notes", "a.txt"), "before", "utf8");

    const config = new PluginConfig();
    const transaction = createShellSandboxTransaction(config, workspace, "echo after > notes/a.txt");
    expect(transaction).not.toBeNull();
    mkdirSync(join(transaction!.tempDir, "notes"), { recursive: true });
    writeFileSync(join(transaction!.tempDir, "notes", "a.txt"), "after\n", "utf8");

    expect(commitSandboxWorkspace(transaction!)).toMatchObject({ committed: true });
    expect(readFileSync(join(workspace, "notes", "a.txt"), "utf8")).toBe("after\n");
    discardSandboxWorkspace(transaction!);
    expect(existsSync(transaction!.tempDir)).toBe(false);
  });

  it.skipIf(process.platform === "win32")("executes a real wrapped command in the shadow workspace before commit", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentsentry-sandbox-test-"));
    tempDirs.push(dir);
    const workspace = join(dir, "workspace");
    mkdirSync(join(workspace, "notes"), { recursive: true });
    writeFileSync(join(workspace, "notes", "a.txt"), "before", "utf8");

    const transaction = createShellSandboxTransaction(new PluginConfig(), workspace, "echo after > notes/a.txt");
    expect(transaction).not.toBeNull();
    const executed = spawnSync("/bin/bash", ["-lc", transaction!.wrappedCommand], { encoding: "utf8" });
    expect(executed.status).toBe(0);
    expect(readFileSync(join(workspace, "notes", "a.txt"), "utf8")).toBe("before");
    expect(readFileSync(join(transaction!.tempDir, "notes", "a.txt"), "utf8")).toBe("after\n");

    expect(commitSandboxWorkspace(transaction!)).toMatchObject({ committed: true });
    expect(readFileSync(join(workspace, "notes", "a.txt"), "utf8")).toBe("after\n");
    discardSandboxWorkspace(transaction!);
  });
});
