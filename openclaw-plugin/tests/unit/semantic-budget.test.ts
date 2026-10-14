import { afterEach, describe, expect, it, vi } from "vitest";
import { PluginConfig } from "../../config.ts";
import { semanticJudgeToolCall, semanticJudgeMemoryWrite, semanticJudgeAmbiguousAction, clearSemanticActionCache } from "../../core/semantic.ts";
import { createPolicyState, decideAction, normalizeAction } from "../../core/policy.ts";

afterEach(() => {
  delete process.env.AGENTSENTRY_BUDGET_TEST_KEY;
  vi.unstubAllGlobals();
  clearSemanticActionCache();
});
function config() {
  const value = new PluginConfig();
  Object.assign(value.semantic, { enabled: true, mode: "full", judgeToolCalls: true, judgeMemoryWrites: true, apiKeyEnv: "AGENTSENTRY_BUDGET_TEST_KEY", timeoutMs: 1000, baseUrl: "https://judge.invalid/v1" });
  process.env.AGENTSENTRY_BUDGET_TEST_KEY = "fixture";
  return value;
}

describe("shared tool semantic time budget", () => {
  it("bounds an unresponsive transport and does not start later routes after expiry", async () => {
    const settings = config();
    let signal: AbortSignal | undefined;
    const fetchMock = vi.fn((_url: string, options: RequestInit) => {
      signal = options.signal as AbortSignal;
      return new Promise<Response>(() => undefined);
    });
    vi.stubGlobal("fetch", fetchMock);
    const started = Date.now();
    const context = { deadlineMs: started + 40 };
    expect(await semanticJudgeToolCall("custom_tool", {}, "review", settings, context)).toEqual([]);
    expect(await semanticJudgeMemoryWrite("remember this", "review", settings, context)).toEqual([]);
    const state = createPolicyState();
    const action = normalizeAction("custom_tool", {});
    const preliminary = { ...decideAction(action, state, settings, []), deterministic_disposition: "ambiguous" as const };
    expect(await semanticJudgeAmbiguousAction({ action, taskSpec: state.taskSpec, policyState: state, preliminary }, settings, context)).toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(signal?.aborted).toBe(true);
    expect(Date.now() - started).toBeLessThan(300);
  });
  it("bounds stalled response bodies and ignores a late high-risk result", async () => {
    const settings = config();
    let resolveBody!: (value: string) => void;
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, text: () => new Promise<string>((resolve) => { resolveBody = resolve; }) })));
    const result = await semanticJudgeToolCall("custom_tool", {}, "review", settings, { deadlineMs: Date.now() + 40 });
    expect(result).toEqual([]);
    resolveBody(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ risk: "high", reason: "late", confidence: 1, recommended_action: "deny", evidence: [], categories: [] }) } }] }));
    await Promise.resolve();
    expect(result).toEqual([]);
  });
});
