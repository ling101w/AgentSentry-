import { describe, expect, it } from "vitest";
import { decisionKind, toolEnforcementAction } from "../../core/enforcement.ts";
import { formatApprovalDescription } from "../../core/operation.ts";

describe("tool enforcement contract", () => {
  it.each(["approval", "block"] as const)("enforces all decision types in %s mode", (mode) => {
    expect(toolEnforcementAction(mode, "deny")).toBe("block");
    expect(toolEnforcementAction(mode, "ask")).toBe("approval");
    expect(toolEnforcementAction(mode, "allow")).toBe("allow");
    expect(decisionKind("deny")).toBe("hard_deny");
    expect(decisionKind("ask")).toBe("approval_required");
  });
  it.each(["deny", "ask", "allow"] as const)("observes %s without enforcing", (decision) => {
    expect(toolEnforcementAction("observe", decision)).toBe("observe");
  });
  it("keeps the exact target before long risk explanations", () => {
    const description = formatApprovalDescription({
      toolName: "send_email", paramPreview: { body: "long payload ".repeat(200), recipient: "alice@example.com", attachment: "reports/status.md" },
      dataSources: ["file:reports/status.md"], sideEffect: "send_email", riskScore: 80, reasons: ["reason ".repeat(100)], violations: [], maxChars: 240,
    });
    expect(description).toContain("alice@example.com");
    expect(description).toContain("reports/status.md");
    expect(description.indexOf("alice@example.com")).toBeLessThan(description.indexOf("long payload"));
  });
});
