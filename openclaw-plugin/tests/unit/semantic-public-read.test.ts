import { afterEach, describe, expect, it, vi } from "vitest";
import { PluginConfig } from "../../config.ts";
import { createPolicyState, updateTaskSpec } from "../../core/policy.ts";
import { semanticGateForToolCall } from "../../core/semantic.ts";
import { SupervisionService } from "../../core/supervision-service.ts";
import { clearCustomToolManifests, registerToolManifest, resolveToolManifest } from "../../core/tool-manifest.ts";

afterEach(() => { vi.unstubAllGlobals(); clearCustomToolManifests(); });

function fixture() {
  const config = PluginConfig.fromPluginConfig({ profile: "balanced", semantic: { enabled: true, mode: "risk-tiered" } });
  const state = createPolicyState();
  updateTaskSpec(state, [{ role: "user", content: "Check https://api.example.com/health." }], config);
  const params = { url: "https://api.example.com/health", method: "GET" };
  return { config, state, params };
}

describe("semantic routing for explicitly scoped public reads", () => {
  it("completes a clean authorized GET without a provider request", async () => {
    const { config, state, params } = fixture();
    const fetchMock = vi.fn(() => { throw new Error("provider must not be called"); });
    vi.stubGlobal("fetch", fetchMock);
    const evaluation = await new SupervisionService().evaluate({ state, config, toolName: "call_api", params, judgeRoutes: "full" });
    expect(evaluation.result.decision).toBe("allow");
    expect(evaluation.routes).toEqual({ toolJudgeRouted: false, memoryJudgeRouted: false, ambiguousJudgeRouted: false });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    { url: "https://api.example.com/other", method: "GET" },
    { url: "https://api.example.com/health", method: "POST" },
    { url: "https://api.example.com/health", method: "GET", headers: { Authorization: "fixture" } },
    { url: "https://api.example.com/health", method: "GET", body: "extra payload" },
    { url: "https://api.example.com/health", method: "GET", http_method: "POST" },
    { url: "https://api.example.com/health", endpoint: "https://api.example.com/other", method: "GET" },
  ])("retains review for an altered scope or payload: %j", (params) => {
    const { config, state } = fixture();
    expect(semanticGateForToolCall("call_api", params, config, { policyState: state }).shouldJudge).toBe(true);
  });

  it.each(["contaminated", "provenance", "risk", "exposure", "private-read", "weak-grant"])("retains review after %s evidence", (kind) => {
    const { config, state, params } = fixture();
    if (kind === "contaminated") state.contaminated = true;
    if (kind === "provenance") state.provenanceBlocked = true;
    if (kind === "risk") state.aggregateRisk.prompt_injection = 20;
    if (kind === "weak-grant") state.taskSpec.capabilities[0].evidence.confidence = 0.7;
    const label = { source: "fixture", integrity: "untrusted" as const, confidentiality: "secret" as const, tainted: true };
    if (kind === "exposure") state.exposures.push({ source: "fixture", text: "private report", label });
    if (kind === "private-read") state.toolResultLabels.set("private", label);
    expect(semanticGateForToolCall("call_api", params, config, { policyState: state }).shouldJudge).toBe(true);
  });

  it("keeps full mode and unscoped requests eligible for review", () => {
    const { config, state, params } = fixture();
    expect(semanticGateForToolCall("call_api", params, config).shouldJudge).toBe(true);
    config.semantic.mode = "full";
    expect(semanticGateForToolCall("call_api", params, config, { policyState: state }).shouldJudge).toBe(true);
  });

  it("retains review for an administrator override of the HTTP tool contract", () => {
    const { config, state, params } = fixture();
    registerToolManifest({ ...resolveToolManifest("call_api")!.manifest, sideEffects: ["network_read"] });
    expect(semanticGateForToolCall("call_api", params, config, { policyState: state }).shouldJudge).toBe(true);
  });
});
