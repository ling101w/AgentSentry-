import { describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { detectToolCall } from "../../core/detect.ts";
import {
  BEHAVIOR_SAMPLE_TTL_MS,
  BEHAVIOR_WARMUP_SAMPLES,
  BEHAVIOR_WINDOW_SIZE,
  behaviorAnomalyFindingsFor,
  behaviorProfileKey,
  updateBehaviorProfile,
  type BehaviorProfile,
} from "../../core/policy/behavior-baseline.ts";
import type { PolicyActionInput } from "../../core/policy/action-assessment.ts";
import { createPolicyState, updateAfterDecision } from "../../core/policy.ts";
import { deriveTaskSpecV2, type TaskSpec } from "../../core/task-spec/index.ts";

type BehaviorState = {
  behaviorProfiles: Map<string, BehaviorProfile>;
  taskSpec?: TaskSpec;
};

function state(taskSpec?: TaskSpec): BehaviorState {
  return { behaviorProfiles: new Map<string, BehaviorProfile>(), taskSpec };
}

function action(tool: string, args: Record<string, unknown> = {}): PolicyActionInput {
  return { tool, originalTool: tool, args, reason: "" };
}

function learn(target: BehaviorState, item: PolicyActionInput, times = BEHAVIOR_WARMUP_SAMPLES, now = Date.now()): void {
  for (let index = 0; index < times; index += 1) updateBehaviorProfile(target, item, now + index);
}

function profile(target: BehaviorState, tool: string): BehaviorProfile | undefined {
  return target.behaviorProfiles.get(behaviorProfileKey(tool, target.taskSpec));
}

function reasons(target: BehaviorState, item: PolicyActionInput, now = Date.now()): string[] {
  return behaviorAnomalyFindingsFor(item, target, new PluginConfig(), now).map((finding) => finding.reason);
}

describe("behavior baseline warm-up and decision contract", () => {
  it("does not report target novelty before ten allowed observations", () => {
    const target = state();
    const baseline = action("call_api", { url: "https://api.example.test/v1" });
    const novel = action("call_api", { url: "https://other.example.test/v1" });

    learn(target, baseline, BEHAVIOR_WARMUP_SAMPLES - 1);
    expect(reasons(target, novel)).toEqual([]);
    updateBehaviorProfile(target, baseline);
    expect(reasons(target, novel)).toContain("tool target host deviates from the warm sliding behavior window");
  });

  it("learns through the policy caller only when the effective decision is allow", () => {
    const config = new PluginConfig();
    const policyState = createPolicyState();
    const detected = detectToolCall("call_api", { url: "https://api.example.test/v1" }, config, policyState).policy;

    updateAfterDecision(policyState, { ...detected, decision: "ask" });
    updateAfterDecision(policyState, { ...detected, decision: "deny" });
    expect(policyState.behaviorProfiles.size).toBe(0);

    updateAfterDecision(policyState, { ...detected, decision: "allow" });
    expect(policyState.behaviorProfiles.get(behaviorProfileKey("call_api", policyState.taskSpec))?.samples).toHaveLength(1);
  });
});

describe("behavior target normalization and novelty", () => {
  it("normalizes hosts and recipients before comparing them", () => {
    const apiState = state();
    learn(apiState, action("call_api", { url: " ", endpoint: " https://API.Example.test./v1 " }));
    expect(profile(apiState, "call_api")?.samples.every((sample) => sample.host === "api.example.test")).toBe(true);
    expect(reasons(apiState, action("call_api", { url: "https://api.example.test/v2" }))).toEqual([]);
    expect(reasons(apiState, action("call_api", { url: "https://new.example.test/v2" })))
      .toContain("tool target host deviates from the warm sliding behavior window");

    const emailState = state();
    learn(emailState, action("send_email", { recipient: " Teacher@Example.EDU " }));
    expect(profile(emailState, "send_email")?.samples.every((sample) => sample.recipient === "teacher@example.edu")).toBe(true);
    expect(reasons(emailState, action("send_email", { to: "TEACHER@example.edu" }))).toEqual([]);
    expect(reasons(emailState, action("send_email", { to: "other@example.edu" })))
      .toContain("email recipient deviates from the warm sliding behavior window");
  });

  it("uses stable Windows drive, UNC share, POSIX, and workspace roots", () => {
    const cases = [
      { learned: "C:\\Users\\alice\\report.md", same: "c:/Temp/cache.txt", novel: "D:\\archive\\report.md", root: "c:" },
      { learned: "\\\\Server\\Share\\one.txt", same: "//server/share/two.txt", novel: "//server/private/secret.txt", root: "//server/share" },
      { learned: "/var/log/app.log", same: "/var/tmp/result.txt", novel: "/etc/app.conf", root: "/var" },
      { learned: "./reports/one.md", same: "reports/two.md", novel: "other/two.md", root: "reports" },
    ];

    for (const item of cases) {
      const target = state();
      learn(target, action("write_file", { path: item.learned }));
      expect(profile(target, "write_file")?.samples.every((sample) => sample.pathRoot === item.root)).toBe(true);
      expect(reasons(target, action("write_file", { path: item.same }))).toEqual([]);
      expect(reasons(target, action("write_file", { path: item.novel })))
        .toContain("file path root deviates from the warm sliding behavior window");
    }
  });
});

describe("behavior sliding window", () => {
  it("caps samples at forty and expires idle samples", () => {
    const target = state();
    const start = 1_000_000;
    for (let index = 0; index < BEHAVIOR_WINDOW_SIZE + 5; index += 1) {
      updateBehaviorProfile(target, action("call_api", { url: `https://h${index}.example.test/v1` }), start + index);
    }
    expect(profile(target, "call_api")?.samples).toHaveLength(BEHAVIOR_WINDOW_SIZE);
    expect(profile(target, "call_api")?.samples.some((sample) => sample.host === "h0.example.test")).toBe(false);
    expect(reasons(target, action("call_api", { url: "https://novel.example.test" }), start + BEHAVIOR_SAMPLE_TTL_MS + 100)).toEqual([]);
  });

  it("uses a percentile instead of a permanent historical maximum", () => {
    const target = state();
    updateBehaviorProfile(target, action("call_api", { query: "x".repeat(20_000) }), 1);
    learn(target, action("call_api", { query: "ok" }), 19, 2);

    expect(reasons(target, action("call_api", { query: "x".repeat(6_000) }), 100))
      .toContain("tool parameter size is anomalous for the sliding behavior window");
  });

  it("isolates profiles by tool and task capability class", () => {
    const fetchSpec = deriveTaskSpecV2("Fetch https://api.example.test/data.", []);
    const emailSpec = deriveTaskSpecV2("Send report.md to teacher@example.edu.", []);
    const target = state(fetchSpec);
    learn(target, action("call_api", { url: "https://api.example.test/data" }));
    target.taskSpec = emailSpec;
    learn(target, action("call_api", { url: "https://mail.example.test/data" }));

    expect(target.behaviorProfiles.size).toBe(2);
    expect(behaviorProfileKey("call_api", fetchSpec)).not.toBe(behaviorProfileKey("call_api", emailSpec));
  });

  it("bounds profile count and evicts the least recently updated profile", () => {
    const target = state();
    for (let index = 0; index < 64; index += 1) updateBehaviorProfile(target, action(`tool_${index}`));
    updateBehaviorProfile(target, action("tool_0"));
    updateBehaviorProfile(target, action("tool_64"));

    expect(target.behaviorProfiles.size).toBe(64);
    expect(target.behaviorProfiles.has("tool_0::unscoped")).toBe(true);
    expect(target.behaviorProfiles.has("tool_1::unscoped")).toBe(false);
    expect(target.behaviorProfiles.has("tool_64::unscoped")).toBe(true);
  });
});

describe("behavior parameter shape", () => {
  it("detects nested shape spikes and handles cyclic values", () => {
    const target = state();
    learn(target, action("call_api", { query: "ok" }));
    const fields = Object.fromEntries(Array.from({ length: 20 }, (_, index) => [`field_${index}`, index]));
    expect(reasons(target, action("call_api", { payload: [fields] })))
      .toContain("tool parameter shape is anomalous for the sliding behavior window");

    const cyclic: Record<string, unknown> = { value: "ok" };
    cyclic.self = cyclic;
    expect(() => updateBehaviorProfile(target, action("custom_tool", cyclic))).not.toThrow();
    expect(profile(target, "custom_tool")?.samples[0]?.paramKeys).toBe(2);
  });
});
