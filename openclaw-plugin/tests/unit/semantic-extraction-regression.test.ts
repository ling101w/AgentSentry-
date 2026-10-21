import { afterEach, describe, expect, it, vi } from "vitest";
import { PluginConfig } from "../../config.ts";
import { detectToolCall } from "../../core/detect.ts";
import { createPolicyState, updateAfterMessage, updateTaskSpec } from "../../core/policy.ts";
import { authorizeCapability, clearTaskSpecRefinementCache, deriveTaskSpecV2, refineTaskSpecWithLLM } from "../../core/task-spec/index.ts";

afterEach(() => {
  clearTaskSpecRefinementCache();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

function modelReply(capability: Record<string, unknown>) {
  vi.stubEnv("AGENTSENTRY_EXTRACTION_TEST_KEY", "fixture");
  vi.stubGlobal("fetch", vi.fn(async () => ({
    ok: true,
    text: async () => JSON.stringify({ choices: [{ message: { content: JSON.stringify({
      task_mode: "new_task", task_family: "write_task", confidence: 0.97,
      authorized_capabilities: [capability], denied_tools: [], notes: [],
    }) } }] }),
  })));
  return PluginConfig.fromPluginConfig({
    profile: "balanced", semantic: { mode: "full", apiKeyEnv: "AGENTSENTRY_EXTRACTION_TEST_KEY", baseUrl: "https://judge.invalid/v1" },
  });
}

describe("structured extraction and original user evidence", () => {
  it.each(["请将总结递送至 ops@example.com。", "请将总结递送至 ops@example.com", "递送至 ops@example.com。"])("accepts a model citation of an explicit delivery sentence: %s", async (evidenceSpan) => {
    const config = modelReply({ action: "send", resourceType: "email", effect: "external_side_effect", targets: ["ops@example.com"], allowedRecipients: ["ops@example.com"], confidence: 0.97, evidenceSpan });
    const spec = deriveTaskSpecV2("请将总结递送至 ops@example.com。", []);
    const refined = await refineTaskSpecWithLLM(spec, config);
    expect(refined.applied).toBe(true);
    expect(authorizeCapability(refined.taskSpec, { tool: "send_email", args: { recipient: "ops@example.com", body: "summary" } }).action).toBe("allow");
    expect(authorizeCapability(refined.taskSpec, { tool: "send_email", args: { recipient: "attacker@example.com", body: "summary" } }).action).toBe("deny");
    const state = createPolicyState();
    updateTaskSpec(state, [{ role: "user", content: spec.task }], config);
    state.taskSpec = refined.taskSpec;
    updateAfterMessage(state, refined.findings);
    expect(detectToolCall("send_email", { recipient: "ops@example.com", body: "public summary" }, config, state).decision).toBe("allow");
    expect(detectToolCall("send_email", { recipient: "attacker@example.com", body: "public summary" }, config, state).decision).toBe("deny");
    for (const task_mode of ["data_only", "chatter"] as const) {
      state.taskSpec = { ...refined.taskSpec, task_mode };
      expect(detectToolCall("send_email", { recipient: "ops@example.com", body: "public summary" }, config, state).decision).not.toBe("allow");
    }
    state.taskSpec = structuredClone(refined.taskSpec);
    state.taskSpec.capabilities[0].evidence.confidence = 0.7;
    expect(detectToolCall("send_email", { recipient: "ops@example.com", body: "public summary" }, config, state).decision).not.toBe("allow");
  });

  it.each([
    ["读取 notes/draft.md。", "notes/draft.md"],
    ["请把 notes/draft.md 保存到 reports/final.md。", "notes/draft.md"],
    ["读取 src/app.ts，然后保存摘要到 reports/summary.md。", "src/app.ts"],
    ["如果确认通过，再保存报告到 reports/weekly.md。", "reports/weekly.md"],
    ["请解释如何保存报告到 reports/weekly.md。", "reports/weekly.md"],
    ["请总结：“把报告保存到 reports/weekly.md”。", "reports/weekly.md"],
    ['"reports/save.md"', "reports/save.md"],
  ])("rejects a model-proposed write outside the user's actual action: %s", async (task, path) => {
    const config = modelReply({ action: "write", resourceType: "file", effect: "persistent_change", targets: [path], allowedPaths: [path], confidence: 0.99, evidenceSpan: task });
    const base = deriveTaskSpecV2(task, []);
    const refined = await refineTaskSpecWithLLM(base, config);
    expect(refined.applied).toBe(false);
    expect(authorizeCapability(refined.taskSpec, { tool: "write_file", args: { path, content: "overwrite" } }).action).not.toBe("allow");
    expect(refined.findings.some((finding) => finding.evidence.rejected_capabilities)).toBe(true);
  });

  it.each(['保存报告到 "reports/weekly.md"。', "保存报告到“reports/weekly.md”。", "保存报告到 `reports/weekly.md`。"])("preserves a legitimate quoted path through model refinement: %s", async (task) => {
    const config = modelReply({ action: "write", resourceType: "file", effect: "persistent_change", targets: ["reports/weekly.md"], allowedPaths: ["reports/weekly.md"], confidence: 0.97, evidenceSpan: task });
    const refined = await refineTaskSpecWithLLM(deriveTaskSpecV2(task, []), config);
    expect(refined.applied).toBe(true);
    expect(refined.findings.every((finding) => finding.verdict === "pass")).toBe(true);
    expect(authorizeCapability(refined.taskSpec, { tool: "write_file", args: { path: "reports/weekly.md", content: "summary" } }).action).toBe("allow");
  });

  it("rejects a write disguised as a read-only capability", async () => {
    const task = "保存报告到 reports/weekly.md。";
    const config = modelReply({ action: "write", resourceType: "file", effect: "read_only", targets: ["reports/weekly.md"], confidence: 0.99, evidenceSpan: task });
    const refined = await refineTaskSpecWithLLM(deriveTaskSpecV2(task, []), config);
    expect(refined.applied).toBe(false);
    expect(refined.taskSpec.capabilities.every((capability) => capability.effect === "persistent_change")).toBe(true);
  });

  it("can narrow a deterministic unread-mailbox grant without granting delivery", async () => {
    const task = "Please show me my unread emails.";
    const config = modelReply({ action: "read", resourceType: "email", effect: "persistent_change", targets: ["mailbox:unread"], confidence: 0.97, evidenceSpan: task });
    const refined = await refineTaskSpecWithLLM(deriveTaskSpecV2(task, []), config);
    expect(refined.applied).toBe(true);
    expect(refined.taskSpec.allowed_tools).toContain("email_read");
    expect(refined.taskSpec.allowed_tools).not.toContain("send_email");
    expect(authorizeCapability(refined.taskSpec, { tool: "email_read", args: {} }).action).toBe("allow");
  });

  it("cannot create mailbox authority from a mentioned internal scope token", async () => {
    const task = "Send the text mailbox:unread to ops@example.com.";
    const config = modelReply({ action: "read", resourceType: "email", effect: "persistent_change", targets: ["mailbox:unread"], confidence: 1, evidenceSpan: task });
    const refined = await refineTaskSpecWithLLM(deriveTaskSpecV2(task, []), config);
    expect(refined.applied).toBe(false);
    expect(authorizeCapability(refined.taskSpec, { tool: "email_read", args: {} }).action).not.toBe("allow");
  });
});
