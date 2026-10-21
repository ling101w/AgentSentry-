import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { detectToolCall } from "../../core/detect.ts";
import { trustedNamedServices } from "../../core/named-services.ts";
import { parseNamedServiceBindings } from "../../core/named-service-config.ts";
import { createPolicyState, updateAfterDecision, updateTaskSpec } from "../../core/policy.ts";
import { deriveTaskSpecV2 } from "../../core/task-spec/index.ts";
import { loadRuntimeConfig, runtimeConfigPath, saveRuntimeConfig } from "../../core/runtime-config.ts";
import { SupervisionService } from "../../core/supervision-service.ts";
import { executeBusinessTool } from "../../server/lab/executor.ts";
import { clearCustomToolManifests, registerToolManifest, resolveToolManifest } from "../../core/tool-manifest.ts";

const roots: string[] = [];
const servers: Server[] = [];
afterEach(async () => {
  clearCustomToolManifests();
  for (const server of servers.splice(0)) await new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); });
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const task = "请调用本地 API 健康检查接口确认服务正常。";
const url = "http://127.0.0.1:8765/api/health";
function fixture(request = task, config = PluginConfig.fromPluginConfig({ profile: "competition", semantic: { enabled: false } })) {
  config.runtimeIsolation.auditAfterExecution = false;
  const state = createPolicyState();
  updateTaskSpec(state, [{ role: "user", content: request }], config);
  const evaluate = (args: Record<string, unknown> = { url }) => detectToolCall("call_api", args, config, state);
  return { config, state, evaluate };
}

describe("trusted named health services", () => {
  it.each([task, "请检查AgentSentry的健康状态。", "Please check local API health."])("resolves the user-stated operation through trusted config: %s", (request) => {
    const { state, evaluate } = fixture(request);
    const snapshot = structuredClone(state);
    const result = evaluate();
    expect(result.decision).toBe("allow");
    expect(result.policy.task_spec.capabilities.find((capability) => capability.constraints.namedService)?.constraints.namedService).toMatchObject({ endpoint: url, purpose: "health_read" });
    expect(state).toEqual(snapshot);
    expect(state.taskSpec.allowed_targets).not.toContain(url);
  });

  it.each([
    "请查询天气。", "请检查未知服务的健康状态。", "不要调用本地 API 健康检查接口。",
    "解释调用本地 API 健康检查接口的方式。", "如果获批，请调用本地 API 健康检查接口。",
    '总结以下内容："请调用本地 API 健康检查接口确认服务正常。"',
    "Please check EvilAgentSentry health.", "请检查 AgentSentry 的健康状态，地址为 https://other.example/health。",
    "请检查本地 API 健康状态。不要调用任何接口。", "Please check local API health. Do not use any APIs.",
  ])("does not infer a service grant from non-authority or mismatched context: %s", (request) => {
    expect(fixture(request).evaluate().decision).not.toBe("allow");
  });

  it.each([
    { url: "http://127.0.0.1:8766/api/health" }, { url: "http://127.0.0.1:8765/api/admin" },
    { url: `${url}?callback=https://attacker.example/` }, { url: `${url}#different` },
    { url: "http://user:password@127.0.0.1:8765/api/health" }, { url: "http://169.254.169.254/api/health" },
    { url, method: "POST" }, { url, httpMethod: "DELETE" }, { url, method: "GET", verb: "POST" },
    { url, endpoint: "https://attacker.example/health" }, { url, body: "payload" }, { url, headers: { Authorization: "secret" } },
    { url, model: "stability-ai/sdxl" }, { url, code: "print('hidden execution')" }, { url, data: { insert: true } },
    { url, query: "SELECT * FROM users" }, { url, service: { endpoint: "https://attacker.example/" } },
  ])("retains method, destination and schema checks: %j", (args) => {
    expect(fixture().evaluate(args).decision).not.toBe("allow");
  });

  it("does not treat a tool-supplied TaskSpec as user authority", () => {
    const { config } = fixture();
    const state = createPolicyState();
    state.taskSpec = deriveTaskSpecV2(task, [], "tool_result");
    expect(detectToolCall("call_api", { url }, config, state).decision).not.toBe("allow");
  });

  it.each(["read_webpage", "fetch_url", "browser.open"])("keeps implicit read permission inside the service argument contract: %s", (tool) => {
    const { config, state } = fixture();
    expect(detectToolCall(tool, { url }, config, state).decision).toBe("allow");
    expect(detectToolCall(tool, { url, body: "hidden payload" }, config, state).decision).toBe("deny");
    expect(detectToolCall(tool, { url, endpoint: "https://attacker.example/" }, config, state).decision).toBe("deny");
  });

  it("preserves the named operation's schema when the user also states its URL", () => {
    const { evaluate } = fixture(`请调用本地 API 健康检查接口 ${url} 确认服务正常。`);
    expect(evaluate().decision).toBe("allow");
    expect(evaluate({ url, method: "GET", code: "hidden operation" }).decision).toBe("deny");
  });

  it("requires the builtin HTTP adapter contract rather than an administrator replacement", () => {
    const { config, state, evaluate } = fixture();
    registerToolManifest({ ...resolveToolManifest("call_api")!.manifest, sideEffects: ["process_exec"] });
    expect(evaluate().decision).toBe("deny");
    registerToolManifest({ ...resolveToolManifest("read_webpage")!.manifest, sideEffects: ["network_write"] });
    expect(detectToolCall("read_webpage", { url }, config, state).decision).toBe("deny");
  });

  it("follows configured ports and refuses disabled or non-local builtin bindings", () => {
    const { config, evaluate } = fixture();
    config.dashboard.port = 9191;
    expect(evaluate().decision).toBe("deny");
    expect(evaluate({ url: "http://127.0.0.1:9191/api/health" }).decision).toBe("allow");
    config.dashboard.enabled = false;
    expect(evaluate({ url: "http://127.0.0.1:9191/api/health" }).decision).toBe("deny");
    config.dashboard.enabled = true;
    config.dashboard.host = "other.example";
    expect(trustedNamedServices(config)).toEqual([]);
  });

  it("respects an independently configured API host restriction", () => {
    const { config, evaluate } = fixture();
    config.policy.allowlistedApiHosts = ["other.example"];
    expect(evaluate().decision).toBe("deny");
  });

  it("keeps an explicit localhost listener name instead of selecting another address family", () => {
    const { config, evaluate } = fixture();
    config.dashboard.host = "localhost";
    expect(trustedNamedServices(config)[0].endpoint).toBe("http://localhost:8765/api/health");
    expect(evaluate({ url: "http://localhost:8765/api/health" }).decision).toBe("allow");
    expect(evaluate().decision).toBe("deny");
  });

  it("fails closed when the service name matches multiple configured endpoints", () => {
    const { config, evaluate } = fixture();
    config.policy.namedServices = [{ id: "other-service", names: ["本地 API"], endpoint: "http://127.0.0.1:9000/health", purpose: "health_read" }];
    expect(evaluate().decision).not.toBe("allow");
  });

  it("revokes custom service authority without retaining a prior request's grant", () => {
    const { config, state, evaluate } = fixture("Please check Billing health.");
    config.policy.namedServices = [{ id: "billing", names: ["Billing"], endpoint: "http://127.0.0.1:9000/health", purpose: "health_read" }];
    const first = evaluate({ url: config.policy.namedServices[0].endpoint });
    expect(first.decision).toBe("allow");
    updateAfterDecision(state, first.policy, config);
    expect(state.taskSpec.capabilities.some((capability) => capability.constraints.namedService)).toBe(false);
    config.policy.namedServices = [];
    expect(evaluate({ url: "http://127.0.0.1:9000/health" }).decision).toBe("deny");
  });

  it("retains the existing request frequency limit", () => {
    const { state, evaluate } = fixture();
    state.apiCallCounts.set("127.0.0.1", 10);
    expect(evaluate().policy.violations).toContain("api rate exceeds configured limit");
  });

  it("keeps the endpoint/config fixed while asynchronous review is pending", async () => {
    const { state, config } = fixture();
    const service = new SupervisionService();
    const evaluation = await service.evaluate({ state, config, toolName: "call_api", params: { url }, onPreliminary: () => { config.dashboard.port = 9191; } });
    expect(evaluation.result.decision).toBe("allow");
    expect(evaluation.config.dashboard.port).toBe(8765);
    expect(detectToolCall("call_api", { url }, config, state).decision).toBe("deny");
  });
});

describe("named service config validation and persistence", () => {
  const binding = { id: "billing", names: ["Billing"], endpoint: "http://127.0.0.1:9000/health", purpose: "health_read" as const };
  it.each([
    { ...binding, methods: ["POST"] }, { ...binding, purpose: "execute" }, { ...binding, names: [] },
    { ...binding, endpoint: "http://user:password@localhost/health" }, { ...binding, endpoint: "file:///etc/passwd" },
    { ...binding, endpoint: "https://example.com/health?token=secret" },
  ])("rejects an invalid binding without a partial grant: %j", (invalid) => {
    expect(parseNamedServiceBindings([invalid])).toBeUndefined();
    expect(parseNamedServiceBindings([binding, invalid])).toBeUndefined();
  });

  it("preserves valid bindings across runtime reloads and rejects invalid overlays", () => {
    const root = mkdtempSync(join(tmpdir(), "agentsentry-service-config-"));
    roots.push(root);
    const config = PluginConfig.fromPluginConfig({ policy: { namedServices: [binding] }, storage: { stateDir: root } });
    expect(config.policy.namedServices).toEqual([binding]);
    saveRuntimeConfig(config);
    expect(loadRuntimeConfig(PluginConfig.fromPluginConfig({ storage: { stateDir: root } })).policy.namedServices).toEqual([binding]);
    writeFileSync(runtimeConfigPath(config), JSON.stringify({ policy: { namedServices: [{ ...binding, endpoint: "file:///etc/passwd" }] } }));
    expect(loadRuntimeConfig(config).policy.namedServices).toEqual([binding]);
  });
});

describe("actual local HTTP boundary", () => {
  it("executes the permitted health GET and stops a redirect before the next endpoint", async () => {
    let healthCalls = 0, outsideCalls = 0, redirect = false;
    const server = createServer((request, response) => {
      if (request.url === "/health" && request.method === "GET") {
        healthCalls += 1;
        if (redirect) { response.writeHead(302, { location: "/outside" }); response.end(); }
        else { response.writeHead(200, { "content-type": "application/json" }); response.end('{"ok":true}'); }
      } else { outsideCalls += 1; response.end("unexpected"); }
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const endpoint = `http://127.0.0.1:${port}/health`;
    const { config, evaluate } = fixture("Please check Billing health.");
    config.policy.namedServices = [{ id: "billing", names: ["Billing"], endpoint, purpose: "health_read" }];
    const permitted = evaluate({ url: endpoint });
    expect(permitted.decision).toBe("allow");
    const action = { toolName: permitted.policy.action.tool, params: permitted.policy.action.args };
    expect(await executeBusinessTool(action, config)).toMatchObject({ ok: true, status: 200 });
    redirect = true;
    expect(await executeBusinessTool(action, config)).toMatchObject({ ok: false, error: expect.stringContaining("redirect limit") });
    expect(await executeBusinessTool({ ...action, params: { ...action.params, method: "POST" } }, config)).toMatchObject({ ok: false, error: "named_service_method_mismatch" });
    expect(healthCalls).toBe(2);
    expect(outsideCalls).toBe(0);
    expect(evaluate({ url: `http://127.0.0.1:${port}/outside` }).decision).toBe("deny");
  });
});
