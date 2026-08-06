import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { RollbackManager } from "../../core/rollback.ts";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("rollback checkpoints", () => {
  it("captures and restores protected memory/config writes", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentsentry-rollback-"));
    tempDirs.push(dir);
    const config = new PluginConfig();
    config.storage.stateDir = dir;
    const workspace = join(dir, "workspace");
    mkdirSync(workspace, { recursive: true });
    const target = join(workspace, "MEMORY.md");
    writeFileSync(target, "before", { encoding: "utf8", flag: "w" });

    const rollback = new RollbackManager(config);
    const snapshots = rollback.checkpoint({
      tool: "memory_write",
      originalTool: "write_file",
      args: { path: "MEMORY.md", content: "after" },
      reason: "",
    }, workspace, "operation-1");
    expect(snapshots).toHaveLength(1);

    writeFileSync(target, "after", "utf8");
    const restored = rollback.restoreOperation("operation-1");
    expect(restored.restored).toHaveLength(1);
    expect(restored.errors).toEqual([]);
    expect(readFileSync(target, "utf8")).toBe("before");
  });

  it("persists an operation checkpoint with session and boundary metadata", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentsentry-rollback-"));
    tempDirs.push(dir);
    const config = new PluginConfig();
    config.storage.stateDir = dir;
    const workspace = join(dir, "workspace");
    mkdirSync(workspace, { recursive: true });
    writeFileSync(join(workspace, "openclaw.json"), "{\"before\":true}", "utf8");

    const rollback = new RollbackManager(config);
    const checkpoint = rollback.checkpointOperation({
      action: {
        tool: "write_file",
        originalTool: "write_file",
        args: { path: "openclaw.json", content: "{\"after\":true}" },
        reason: "",
      },
      workspaceDir: workspace,
      operationKey: "operation-checkpoint-1",
      sessionState: {
        currentTask: "update config",
        taskSpec: { allowed_tools: ["write_file"] },
        history: [{ tool: "read_file", decision: "allow", risk_score: 5 }],
      },
    });

    expect(checkpoint).toMatchObject({
      operation_key: "operation-checkpoint-1",
      tool: "write_file",
      file_snapshots: [expect.objectContaining({ path: join(workspace, "openclaw.json") })],
      boundary: expect.objectContaining({ kind: "file-workspace-session" }),
    });
    expect(checkpoint?.session_state).toMatchObject({ currentTask: "update config" });

    const reloaded = new RollbackManager(config);
    expect(reloaded.listCheckpoints(1)[0]).toMatchObject({
      operation_key: "operation-checkpoint-1",
      execution_history: [expect.objectContaining({ tool: "read_file" })],
    });
  });

  it("removes files created after a checkpoint and reloads persisted snapshots", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentsentry-rollback-"));
    tempDirs.push(dir);
    const config = new PluginConfig();
    config.storage.stateDir = dir;
    const workspace = join(dir, "workspace");
    mkdirSync(workspace, { recursive: true });
    const target = join(workspace, "reports", "new.md");

    const rollback = new RollbackManager(config);
    const snapshots = rollback.checkpoint({
      tool: "write_file",
      originalTool: "write_file",
      args: { path: "reports/new.md", content: "created" },
      reason: "",
    }, workspace, "operation-2");
    expect(snapshots[0]).toMatchObject({ existed: false, reason: "file checkpoint before write" });

    mkdirSync(join(workspace, "reports"), { recursive: true });
    writeFileSync(target, "created", "utf8");
    const reloaded = new RollbackManager(config);
    expect(reloaded.restoreOperation("operation-2").restored).toHaveLength(1);
    expect(existsSync(target)).toBe(false);

    reloaded.reset();
    expect(existsSync(reloaded.path)).toBe(false);
  });

  it("ignores non-write tools and disabled rollback policy", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentsentry-rollback-"));
    tempDirs.push(dir);
    const config = new PluginConfig();
    config.storage.stateDir = dir;
    const rollback = new RollbackManager(config);
    expect(rollback.checkpoint({
      tool: "read_file",
      originalTool: "read_file",
      args: { path: "README.md" },
      reason: "",
    }, dir, "operation-3")).toEqual([]);

    config.rollback.enabled = false;
    expect(new RollbackManager(config).checkpoint({
      tool: "write_file",
      originalTool: "write_file",
      args: { path: "openclaw.json", content: "{}" },
      reason: "",
    }, dir, "operation-4")).toEqual([]);
  });
});
