import { describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { detectToolCall } from "../../core/detect.ts";
import {
  behaviorAnomalyFindingsFor,
  updateBehaviorProfile,
  type BehaviorProfile,
} from "../../core/policy/behavior-baseline.ts";
import type { PolicyActionInput } from "../../core/policy/action-assessment.ts";
import { createPolicyState, updateAfterDecision } from "../../core/policy.ts";

type BehaviorState = { behaviorProfiles: Map<string, BehaviorProfile> };

function state(): BehaviorState {
  return { behaviorProfiles: new Map<string, BehaviorProfile>() };
}

function action(tool: string, args: Record<string, unknown> = {}): PolicyActionInput {
  return { tool, originalTool: tool, args, reason: "" };
}

function learn(target: BehaviorState, item: PolicyActionInput, times = 2): void {
  for (let index = 0; index < times; index += 1) updateBehaviorProfile(target, item);
}

function behavioralReasons(target: BehaviorState, item: PolicyActionInput): string[] {
  return behaviorAnomalyFindingsFor(item, target, new PluginConfig()).map((finding) => finding.reason);
}

describe("behavior baseline cold start and decision contract", () => {
  it("does not report novelty until two allowed observations establish a baseline", () => {
    const target = state();
    const baseline = action("call_api", { url: "https://api.example.test/v1" });
    const novel = action("call_api", { url: "https://other.example.test/v1" });

    expect(behavioralReasons(target, novel)).toEqual([]);
    updateBehaviorProfile(target, baseline);
    expect(behavioralReasons(target, novel)).toEqual([]);
    updateBehaviorProfile(target, baseline);
    expect(behavioralReasons(target, novel)).toContain("tool target host deviates from the statistical session baseline");
  });

  it("learns through the policy caller only when the effective decision is allow", () => {
    const config = new PluginConfig();
    const policyState = createPolicyState();
    const detected = detectToolCall("call_api", { url: "https://api.example.test/v1" }, config, policyState).policy;

    updateAfterDecision(policyState, { ...detected, decision: "ask" });
    updateAfterDecision(policyState, { ...detected, decision: "deny" });
    expect(policyState.behaviorProfiles.size).toBe(0);

    updateAfterDecision(policyState, { ...detected, decision: "allow" });
    expect(policyState.behaviorProfiles.get("call_api")?.calls).toBe(1);
  });
});

describe("behavior target novelty", () => {
  it("normalizes host casing, terminal dots, whitespace, and blank alias fallbacks", () => {
    const target = state();
    learn(target, action("call_api", {
      url: "   ",
      endpoint: "  https://API.Example.test./v1  ",
    }));

    expect(target.behaviorProfiles.get("call_api")?.hosts).toEqual(["api.example.test"]);
    expect(behavioralReasons(target, action("call_api", { url: "https://api.example.test/v2" }))).toEqual([]);
    expect(behavioralReasons(target, action("call_api", { url: "https://new.example.test/v2" })))
      .toContain("tool target host deviates from the statistical session baseline");
  });

  it("normalizes recipient casing and whitespace while detecting a new recipient", () => {
    const target = state();
    updateBehaviorProfile(target, action("send_email", { recipient: " Teacher@Example.EDU " }));
    updateBehaviorProfile(target, action("send_email", { recipient: " ", to: "teacher@example.edu" }));

    expect(target.behaviorProfiles.get("send_email")?.recipients).toEqual(["teacher@example.edu"]);
    expect(behavioralReasons(target, action("send_email", { to: "TEACHER@example.edu" }))).toEqual([]);
    expect(behavioralReasons(target, action("send_email", { to: "other@example.edu" })))
      .toContain("email recipient deviates from the statistical session baseline");
  });

  it("uses stable Windows drive and UNC share roots", () => {
    const driveState = state();
    updateBehaviorProfile(driveState, action("read_file", { path: " C:\\Users\\alice\\report.md " }));
    updateBehaviorProfile(driveState, action("read_file", { path: "c:/Temp/cache.txt" }));
    expect(driveState.behaviorProfiles.get("read_file")?.pathRoots).toEqual(["c:"]);
    expect(behavioralReasons(driveState, action("read_file", { path: "C:\\Windows\\win.ini" }))).toEqual([]);
    expect(behavioralReasons(driveState, action("read_file", { path: "D:\\archive\\report.md" })))
      .toContain("file path root deviates from the statistical session baseline");

    const uncState = state();
    updateBehaviorProfile(uncState, action("read_file", { path: "\\\\Server\\Share\\one.txt" }));
    updateBehaviorProfile(uncState, action("read_file", { path: "//server/share/two.txt" }));
    expect(uncState.behaviorProfiles.get("read_file")?.pathRoots).toEqual(["//server/share"]);
    expect(behavioralReasons(uncState, action("read_file", { path: "\\\\SERVER\\SHARE\\three.txt" }))).toEqual([]);
    expect(behavioralReasons(uncState, action("read_file", { path: "\\\\server\\private\\secret.txt" })))
      .toContain("file path root deviates from the statistical session baseline");
  });

  it("uses stable POSIX and relative workspace roots", () => {
    const posixState = state();
    updateBehaviorProfile(posixState, action("write_file", { path: "/var/log/app.log" }));
    updateBehaviorProfile(posixState, action("write_file", { path: "/var/tmp/result.txt" }));
    expect(posixState.behaviorProfiles.get("write_file")?.pathRoots).toEqual(["/var"]);
    expect(behavioralReasons(posixState, action("write_file", { path: "/var/lib/state.json" }))).toEqual([]);
    expect(behavioralReasons(posixState, action("write_file", { path: "/etc/app.conf" })))
      .toContain("file path root deviates from the statistical session baseline");

    const relativeState = state();
    updateBehaviorProfile(relativeState, action("write_file", { path: "./reports/one.md" }));
    updateBehaviorProfile(relativeState, action("write_file", { path: "reports/two.md" }));
    expect(relativeState.behaviorProfiles.get("write_file")?.pathRoots).toEqual(["reports"]);
    expect(behavioralReasons(relativeState, action("write_file", { path: "./reports/three.md" }))).toEqual([]);
  });
});

describe("behavior parameter anomalies", () => {
  it("measures UTF-8 bytes and detects a size spike", () => {
    const target = state();
    learn(target, action("call_api", { query: "ok" }));
    const oversized = action("call_api", { query: "界".repeat(1500) });

    const finding = behaviorAnomalyFindingsFor(oversized, target, new PluginConfig())
      .find((item) => item.reason === "tool parameter size is anomalous for this session");
    expect(finding).toBeDefined();
    expect(finding?.evidence.param_bytes).toBe(Buffer.byteLength(JSON.stringify(oversized.args, null, 2), "utf8"));
  });

  it("detects a nested parameter-shape spike", () => {
    const target = state();
    learn(target, action("call_api", { query: "ok" }));
    const fields = Object.fromEntries(Array.from({ length: 10 }, (_, index) => [`field_${index}`, index]));

    expect(behavioralReasons(target, action("call_api", { payload: [fields] })))
      .toContain("tool parameter shape is anomalous for this session");
  });

  it("counts cyclic argument objects without recursing indefinitely", () => {
    const target = state();
    const cyclic: Record<string, unknown> = { value: "ok" };
    cyclic.self = cyclic;

    expect(() => updateBehaviorProfile(target, action("custom_tool", cyclic))).not.toThrow();
    expect(target.behaviorProfiles.get("custom_tool")?.maxParamKeys).toBe(2);
  });
});

describe("behavior profile capacity", () => {
  it("keeps unique target values capped and refreshes repeated values as recently used", () => {
    const target = state();
    for (let index = 0; index < 12; index += 1) {
      updateBehaviorProfile(target, action("call_api", { url: `https://h${index}.example.test/v1` }));
    }
    updateBehaviorProfile(target, action("call_api", { url: "https://h0.example.test/v2" }));
    updateBehaviorProfile(target, action("call_api", { url: "https://h12.example.test/v1" }));

    const hosts = target.behaviorProfiles.get("call_api")?.hosts || [];
    expect(hosts).toHaveLength(12);
    expect(hosts).toContain("h0.example.test");
    expect(hosts).not.toContain("h1.example.test");
    expect(hosts.at(-1)).toBe("h12.example.test");
    expect(new Set(hosts).size).toBe(hosts.length);
  });

  it("caps tool profiles at 24 and uses least-recently-updated eviction", () => {
    const target = state();
    updateBehaviorProfile(target, action(""));
    for (let index = 0; index < 23; index += 1) {
      updateBehaviorProfile(target, action(`tool_${index}`));
    }
    updateBehaviorProfile(target, action("tool_0"));
    updateBehaviorProfile(target, action("tool_23"));
    updateBehaviorProfile(target, action("tool_24"));

    expect(target.behaviorProfiles.size).toBe(24);
    expect(target.behaviorProfiles.has("tool_0")).toBe(true);
    expect(target.behaviorProfiles.has("")).toBe(false);
    expect(target.behaviorProfiles.has("tool_1")).toBe(false);
    expect(target.behaviorProfiles.has("tool_24")).toBe(true);
  });
});
