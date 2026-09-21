import { describe, expect, it } from "vitest";
import { summarizeLabVerdict } from "../../public/command-lab-verdict.js";

function toolDecision(toolName: string, decision: string, intervention?: Record<string, unknown>) {
  return {
    type: "tool_decision",
    title: `Business tool decision: ${toolName}`,
    summary: `${toolName} ${decision}`,
    payload: {
      toolName,
      normalized_tool: toolName,
      decision,
      scenario: "workspace_injection_12_11",
      ...(intervention ? { intervention, raw_decision: intervention.raw_decision } : {}),
    },
  };
}

describe("command lab verdict summary", () => {
  it("surfaces the denied Gmail sink under risk-based mode", () => {
    const summary = summarizeLabVerdict([
      toolDecision("get_day_calendar_events", "allow"),
      toolDecision("send_email", "deny"),
      toolDecision("create_calendar_event", "allow"),
    ], {
      scenarioDefaults: { workspace_injection_12_11: { label: "提示注入：约 Follow-up meeting" } },
    });
    expect(summary).toMatchObject({
      tool: "send_email",
      rawDecision: "deny",
      verdict: "deny",
      tone: "danger",
    });
  });

  it("keeps the Gmail sink visible when evidence-gated overrides deny to allow", () => {
    const summary = summarizeLabVerdict([
      toolDecision("get_day_calendar_events", "allow"),
      toolDecision("send_email", "allow", {
        mode: "evidence-gated",
        raw_decision: "deny",
        overridden: true,
        evidence_class: "risk_only",
      }),
      toolDecision("create_calendar_event", "allow"),
    ], {
      scenarioDefaults: { workspace_injection_12_11: { label: "提示注入：约 Follow-up meeting" } },
    });
    expect(summary).toMatchObject({
      tool: "send_email",
      rawDecision: "allow",
      verdict: "allow",
      tone: "success",
      interventionMode: "evidence-gated",
      interventionLabel: "证据门控",
      policyDecision: "deny",
      overridden: true,
      gateNote: "证据门控覆盖：风险deny → allow",
    });
  });
});
