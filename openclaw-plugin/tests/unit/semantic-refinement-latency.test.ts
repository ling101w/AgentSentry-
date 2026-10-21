import { afterEach, describe, expect, it, vi } from "vitest";
import { PluginConfig } from "../../config.ts";
import { clearTaskSpecRefinementCache, deriveTaskSpecV2, refineTaskSpecWithLLM } from "../../core/task-spec/index.ts";
import { semanticJudgeToolCall } from "../../core/semantic.ts";

afterEach(() => {
  clearTaskSpecRefinementCache();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

function fixture() {
  vi.stubEnv("AGENTSENTRY_REFINEMENT_LATENCY_TEST_KEY", "fixture");
  const config = PluginConfig.fromPluginConfig({ profile: "balanced", semantic: { mode: "full", timeoutMs: 700, baseUrl: "https://judge.invalid/v1", apiKeyEnv: "AGENTSENTRY_REFINEMENT_LATENCY_TEST_KEY" } });
  const spec = deriveTaskSpecV2("请将总结递送至 ops@example.com。", []);
  return { config, spec };
}

function response() {
  return {
    ok: true,
    text: async () => JSON.stringify({ choices: [{ message: { content: JSON.stringify({
      task_mode: "new_task", task_family: "delivery", confidence: 0.95,
      authorized_capabilities: [{ action: "send", resourceType: "email", effect: "external_side_effect", targets: ["ops@example.com"], confidence: 0.95, evidenceSpan: "递送至 ops@example.com。" }], denied_tools: [], notes: [],
    }) } }] }),
  } as Response;
}

describe("task extraction latency and cache boundaries", () => {
  it("shares concurrent requests and returns independent, revalidated results", async () => {
    const { config, spec } = fixture();
    let release!: (value: Response) => void;
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => { release = resolve; }));
    vi.stubGlobal("fetch", fetchMock);
    const first = refineTaskSpecWithLLM(spec, config);
    const second = refineTaskSpecWithLLM(spec, config);
    expect(fetchMock).toHaveBeenCalledOnce();
    release(response());
    const values = await Promise.all([first, second]);
    expect(values.every((item) => item.applied)).toBe(true);
    values[0].taskSpec.capabilities[0].targets = ["attacker@example.com"];
    expect(values[1].taskSpec.capabilities[0].targets).toEqual(["ops@example.com"]);
    const cached = await refineTaskSpecWithLLM(spec, config);
    expect(cached.taskSpec.capabilities[0].targets).toEqual(["ops@example.com"]);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("does not reuse proposals after provider, credentials, grant or expiry changes", async () => {
    vi.useFakeTimers();
    const { config, spec } = fixture();
    const fetchMock = vi.fn(async () => response());
    vi.stubGlobal("fetch", fetchMock);
    await refineTaskSpecWithLLM(spec, config);
    config.semantic.model = "another-model";
    await refineTaskSpecWithLLM(spec, config);
    vi.stubEnv("AGENTSENTRY_REFINEMENT_LATENCY_TEST_KEY", "rotated-fixture");
    await refineTaskSpecWithLLM(spec, config);
    const denied = structuredClone(spec);
    denied.denied_tools = ["send_email"];
    const deniedResult = await refineTaskSpecWithLLM(denied, config);
    expect(deniedResult.taskSpec.allowed_tools).not.toContain("send_email");
    await vi.advanceTimersByTimeAsync(60_001);
    await refineTaskSpecWithLLM(spec, config);
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  it("honors cacheEnabled=false for successive calls", async () => {
    const { config, spec } = fixture();
    config.semantic.cacheEnabled = false;
    const fetchMock = vi.fn(async () => response());
    vi.stubGlobal("fetch", fetchMock);
    await refineTaskSpecWithLLM(spec, config);
    await refineTaskSpecWithLLM(spec, config);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("reuses a proposal through repeated prompt rebuilds after grant metadata stabilizes", async () => {
    const { config, spec } = fixture();
    const fetchMock = vi.fn(async () => response());
    vi.stubGlobal("fetch", fetchMock);
    let taskSpec = spec;
    for (let step = 0; step < 5; step += 1) taskSpec = (await refineTaskSpecWithLLM(taskSpec, config)).taskSpec;
    // The first response changes the capability set. Later audit text additions
    // do not change the requested authority or require another model call.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(taskSpec.allowed_tools).toContain("send_email");
  });

  it.each(["transport", "body"])("bounds a stalled %s by the total timeout without caching failure", async (stage) => {
    vi.useFakeTimers();
    const { config, spec } = fixture();
    const fetchMock = vi.fn(() => stage === "transport"
      ? new Promise<Response>(() => undefined)
      : Promise.resolve({ ok: true, text: () => new Promise<string>(() => undefined) } as Response));
    vi.stubGlobal("fetch", fetchMock);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const pending = refineTaskSpecWithLLM(spec, config);
      await vi.advanceTimersByTimeAsync(701);
      expect((await pending).applied).toBe(false);
    }
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each([400, 401, 429])("does not retry HTTP %s in the foreground", async (status) => {
    const { config, spec } = fixture();
    const fetchMock = vi.fn(async () => ({ ok: false, status } as Response));
    vi.stubGlobal("fetch", fetchMock);
    expect((await refineTaskSpecWithLLM(spec, config)).applied).toBe(false);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("shares one wall-clock budget across a transient error and retry", async () => {
    vi.useFakeTimers();
    const { config, spec } = fixture();
    const fetchMock = vi.fn()
      .mockImplementationOnce(() => new Promise<Response>((resolve) => setTimeout(() => resolve({ ok: false, status: 503 } as Response), 400)))
      .mockImplementationOnce(() => new Promise<Response>(() => undefined));
    vi.stubGlobal("fetch", fetchMock);
    const started = Date.now();
    const pending = refineTaskSpecWithLLM(spec, config);
    await vi.advanceTimersByTimeAsync(701);
    expect((await pending).applied).toBe(false);
    expect(Date.now() - started).toBe(701);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("sends the provider thinking option only when explicitly configured", async () => {
    const { config, spec } = fixture();
    const bodies: Array<Record<string, unknown>> = [];
    vi.stubGlobal("fetch", vi.fn(async (_url, options: RequestInit) => {
      bodies.push(JSON.parse(String(options.body)));
      return response();
    }));
    await refineTaskSpecWithLLM(spec, config);
    config.semantic.thinking = "disabled";
    await refineTaskSpecWithLLM(spec, config);
    expect(bodies[0]).not.toHaveProperty("thinking");
    expect(bodies[1]).toHaveProperty("thinking", { type: "disabled" });
    expect(PluginConfig.fromPluginConfig({ semantic: { thinking: "invalid" } }).semantic.thinking).toBe("auto");
  });

  it("uses the same provider option for action Judge requests", async () => {
    const { config } = fixture();
    config.semantic.thinking = "disabled";
    const bodies: Array<Record<string, unknown>> = [];
    vi.stubGlobal("fetch", vi.fn(async (_url, options: RequestInit) => {
      bodies.push(JSON.parse(String(options.body)));
      return {
        ok: true,
        text: async () => JSON.stringify({ choices: [{ message: { content: JSON.stringify({ risk: "low", reason: "public data", confidence: 0.95, recommended_action: "allow", evidence: [], categories: [] }) } }] }),
      } as Response;
    }));
    expect(await semanticJudgeToolCall("custom_tool", {}, "review", config)).toHaveLength(1);
    expect(bodies[0]).toHaveProperty("thinking", { type: "disabled" });
  });
});
