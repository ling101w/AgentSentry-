import { describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import {
  createDynamicSecurityState,
  dynamicSecurityFindingsFor,
  dynamicSecuritySnapshot,
  recordDynamicSecurityEvent,
} from "../../core/dynamic-security.ts";
import { assessAction } from "../../core/policy/action-assessment.ts";

describe("dynamic security risk window", () => {
  it("escalates after high-risk events and recovers after safe actions", () => {
    const config = new PluginConfig();
    config.dynamicSecurity.riskThreshold = 50;
    config.dynamicSecurity.recoverAfterSafeActions = 2;
    const state = createDynamicSecurityState();

    recordDynamicSecurityEvent(state, "deny", 100, [{
      layer: "Tool Boundary",
      finding_type: "deterministic",
      verdict: "block",
      reason: "sensitive exfiltration blocked",
      score: 100,
      evidence: {},
    }], config);

    expect(dynamicSecuritySnapshot(state)).toMatchObject({ degradation_level: 1, high_risk_events: 1 });
    const action = { tool: "send_email", originalTool: "send_email", args: { recipient: "ops@example.com", body: "status" }, reason: "" };
    const findings = dynamicSecurityFindingsFor(action, assessAction(action, config), state, config);
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ verdict: "require_approval", layer: "Runtime Governance" }),
    ]));

    recordDynamicSecurityEvent(state, "allow", 1, [], config);
    recordDynamicSecurityEvent(state, "allow", 1, [], config);
    expect(dynamicSecuritySnapshot(state)).toMatchObject({ degradation_level: 0 });
  });

  it("tightens persistence and execution only after the corresponding degradation level", () => {
    const config = new PluginConfig();
    config.dynamicSecurity.maxDegradationLevel = 4;
    const state = createDynamicSecurityState();
    state.degradationLevel = 4;

    const writeAction = { tool: "write_file", originalTool: "write_file", args: { path: "notes/status.md", content: "ok" }, reason: "" };
    expect(dynamicSecurityFindingsFor(writeAction, assessAction(writeAction, config), state, config))
      .toEqual(expect.arrayContaining([expect.objectContaining({ reason: expect.stringContaining("最高档") })]));

    const execAction = { tool: "shell_exec", originalTool: "exec", args: { command: "rm -rf /" }, reason: "" };
    expect(dynamicSecurityFindingsFor(execAction, assessAction(execAction, config), state, config))
      .toEqual(expect.arrayContaining([expect.objectContaining({ verdict: "block" })]));

    config.dynamicSecurity.enabled = false;
    expect(dynamicSecurityFindingsFor(execAction, assessAction(execAction, config), state, config)).toEqual([]);
  });

  it("requires review when the session action mix drifts into a new side effect", () => {
    const config = new PluginConfig();
    const state = createDynamicSecurityState();
    for (const tool of ["read_file", "read_webpage", "memory_read", "call_api", "write_file"]) {
      recordDynamicSecurityEvent(state, "allow", 5, [], config, tool);
    }
    const action = { tool: "send_email", originalTool: "send_email", args: { recipient: "ops@example.com", body: "ok" }, reason: "" };
    const findings = dynamicSecurityFindingsFor(action, assessAction(action, config), state, config);
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ reason: expect.stringContaining("动作分布") }),
    ]));
    expect(dynamicSecuritySnapshot(state)).toMatchObject({
      entropy_drift: expect.objectContaining({ distinct_tools: 5 }),
    });
  });
});
