import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PluginConfig } from "../../config.ts";
import { RecordStore } from "../../core/records.ts";
import { supervisionService } from "../../core/supervision-service.ts";
import * as executor from "../../server/lab/executor.ts";
import { runLabCommand } from "../../server/lab/service.ts";
import { resolveReadPath } from "../../server/lab/workspace.ts";

const roots: string[] = [];
const stores: RecordStore[] = [];

afterEach(async () => {
  for (const store of stores.splice(0)) await store.close();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "agentsentry-lab-service-"));
  roots.push(root);
  const workspace = join(root, "workspace");
  mkdirSync(join(workspace, "docs"), { recursive: true });
  writeFileSync(join(workspace, "docs", "report.md"), "Public project status.");
  const configPath = join(root, "openclaw.json");
  writeFileSync(configPath, JSON.stringify({ agents: { defaults: { workspace } } }));
  vi.stubEnv("AGENTSENTRY_OPENCLAW_CONFIG", configPath);
  vi.stubEnv("AGENTSENTRY_TOOL_STATE_DIR", join(root, "tool-state"));
  const config = new PluginConfig();
  config.semantic.enabled = false;
  config.runtimeIsolation.auditAfterExecution = false;
  config.storage.stateDir = root;
  const store = new RecordStore(config);
  stores.push(store);
  return { root, workspace, config, store };
}

describe("Lab service and executor boundary", () => {
  it("executes a permitted nested workspace read and records its actual result", async () => {
    const { config, store } = fixture();
    const outcome = await runLabCommand({
      command: "Read docs/report.md.",
      actions: [{ toolName: "read_file", params: { path: "docs/report.md" } }],
    }, store, config);
    expect(outcome.decisions[0]).toMatchObject({ decision: "allow" });
    expect(outcome.session).toMatchObject({ turn: 1, contaminated: false });
    expect(store.list().find((record) => record.type === "tool_result")?.payload).toMatchObject({
      execution_status: "executed", ok: true,
      result: { output: expect.objectContaining({ preview: "Public project status." }) },
    });
  });

  it("keeps a denied tool away from the executor", async () => {
    const { root, config, store } = fixture();
    const execute = vi.spyOn(executor, "executeBusinessTool");
    const outcome = await runLabCommand({
      command: "Read docs/report.md.",
      actions: [{ toolName: "shell_exec", params: { command: "rm -rf /" } }],
    }, store, config);
    expect(outcome.decisions[0]).toMatchObject({ decision: "deny" });
    expect(execute).not.toHaveBeenCalled();
    expect(existsSync(join(root, "tool-state"))).toBe(false);
    expect(store.list().find((record) => record.type === "tool_result")?.payload).toMatchObject({ execution_status: "blocked", ok: false });
  });

  it("continues the committed session after an evaluation fails during reset", async () => {
    const { config, store } = fixture();
    const body = {
      clientId: "same-client", command: "Read docs/report.md.",
      actions: [{ toolName: "read_file", params: { path: "docs/report.md" } }],
    };
    const first = await runLabCommand(body, store, config);
    vi.spyOn(supervisionService, "evaluate").mockRejectedValueOnce(new Error("evaluation failed"));
    await expect(runLabCommand({ ...body, resetSession: true }, store, config)).rejects.toThrow("evaluation failed");
    const next = await runLabCommand(body, store, config);
    expect(next.session).toMatchObject({ key: first.session.key, turn: 2 });
    expect(next.record.run_id).not.toBe(first.record.run_id);
  });

  it("rejects reads outside the workspace while accepting an absolute in-workspace path", () => {
    const { root, workspace } = fixture();
    const allowed = join(workspace, "docs", "report.md");
    writeFileSync(join(root, "outside.md"), "outside");
    expect(resolveReadPath(allowed)).toBe(allowed);
    expect(() => resolveReadPath("../outside.md")).toThrow("outside workspace");
  });
});
