import fc from "fast-check";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PluginConfig } from "../../config.ts";
import { intersectOptional } from "../../core/task-spec/constraints.ts";
import { authorizeCapability, createAuthorizationState, deriveTaskSpecV2, refineTaskSpecWithLLM, updateAuthorizationState } from "../../core/task-spec/index.ts";
import type { TaskCapability } from "../../core/task-spec/types.ts";
import { clearTaskSpecRefinementCache } from "../../core/task-spec/index.ts";

afterEach(() => {
  clearTaskSpecRefinementCache();
  delete process.env.AGENTSENTRY_CONSTRAINT_TEST_KEY;
  vi.unstubAllGlobals();
});

describe("capability constraint boundaries", () => {
  it("preserves the distinction between absent and unsatisfiable constraints", () => {
    expect(intersectOptional()).toBeUndefined();
    expect(intersectOptional(undefined, ["GET"])).toEqual(["GET"]);
    expect(intersectOptional(["GET"], ["POST"])).toEqual([]);
    expect(intersectOptional([], ["GET"])).toEqual([]);
    expect(intersectOptional(["GET"], [])).toEqual([]);
  });

  it("never authorizes a value outside either intersected grant", () => {
    fc.assert(fc.property(
      fc.option(fc.array(fc.constantFrom("GET", "HEAD", "POST", "DELETE")), { nil: undefined }),
      fc.option(fc.array(fc.constantFrom("GET", "HEAD", "POST", "DELETE")), { nil: undefined }),
      (left, right) => {
        const merged = intersectOptional(left, right);
        for (const method of ["GET", "HEAD", "POST", "DELETE"] as const) {
          const permitted = merged === undefined || merged.includes(method);
          if (permitted) {
            expect(left === undefined || left.includes(method)).toBe(true);
            expect(right === undefined || right.includes(method)).toBe(true);
          }
        }
      },
    ), { numRuns: 250 });
  });

  it.each([
    ["Read https://api.example.com/report.", "Also read https://api.example.com/report.", "allowedMethods", "POST", "call_api", { url: "https://api.example.com/report", method: "GET" }],
    ["Save to notes/report.md.", "Also save to notes/report.md.", "allowedPaths", "notes/other.md", "write_file", { path: "notes/report.md", content: "ok" }],
    ["Send report to alice@example.com.", "Also send report to alice@example.com.", "allowedRecipients", "bob@example.com", "send_email", { recipient: "alice@example.com", body: "ok" }],
  ] as const)("keeps a conflicting cross-turn %s grant closed", (first, second, key, conflicting, tool, args) => {
    let state = updateAuthorizationState(createAuthorizationState([]), first, []).state;
    const capability = state.taskSpec.capabilities.find((item) => item.constraints[key]);
    expect(capability).toBeDefined();
    capability!.constraints[key] = [conflicting];
    state = updateAuthorizationState(state, second, []).state;
    expect(state.taskSpec.capabilities.find((item) => item.capabilityId === capability!.capabilityId)?.constraints[key]).toEqual([]);
    expect(authorizeCapability(state.taskSpec, { tool, args })).toMatchObject({ action: "deny", reason: "capability_constraint_conflict" });
  });

  it.each(["allowedMethods", "allowedPaths", "allowedHosts", "allowedRecipients"] as const)("denies an explicit empty %s set", (key) => {
    const spec = deriveTaskSpecV2("Read https://api.example.com/report.", []);
    spec.capabilities[0].constraints[key] = [];
    expect(authorizeCapability(spec, { tool: "call_api", args: { url: "https://api.example.com/report", method: "GET" } }).action).toBe("deny");
  });

  it.each([{ methods: ["POST"] }, { methods: [] as string[] }])("does not let semantic refinement erase a method restriction: $methods", async ({ methods }) => {
    const spec = deriveTaskSpecV2("Read https://api.example.com/report.", []);
    const capability = spec.capabilities.find((item) => item.resourceType === "api") as TaskCapability;
    const config = new PluginConfig();
    Object.assign(config.semantic, { enabled: true, judgeMessages: true, mode: "full", apiKeyEnv: "AGENTSENTRY_CONSTRAINT_TEST_KEY", baseUrl: "https://judge.invalid/v1", model: "unit-test" });
    process.env.AGENTSENTRY_CONSTRAINT_TEST_KEY = "fixture";
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      text: async () => JSON.stringify({ choices: [{ message: { content: JSON.stringify({
        task_mode: "new_task",
        task_family: "read_only",
        confidence: 0.9,
        authorized_capabilities: [{ action: capability.action, resourceType: capability.resourceType, effect: capability.effect, targets: capability.targets, allowedMethods: methods, confidence: 0.9, evidenceSpan: capability.evidence.explicitSpan }],
        denied_tools: [],
        notes: [],
      }) } }] }),
    })));
    const refined = await refineTaskSpecWithLLM(spec, config);
    expect(refined.applied).toBe(true);
    expect(refined.taskSpec.capabilities[0].constraints.allowedMethods).toEqual([]);
    for (const method of ["GET", "POST", "DELETE"]) {
      expect(authorizeCapability(refined.taskSpec, { tool: "call_api", args: { url: capability.targets[0], method } }).action).toBe("deny");
    }
  });
});
