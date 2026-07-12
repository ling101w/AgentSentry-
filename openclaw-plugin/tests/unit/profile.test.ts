import { describe, expect, it } from "vitest";
import { applySecurityProfile, PluginConfig } from "../../config.ts";

describe("security profiles", () => {
  it("enables the competition posture without changing the deployment default", () => {
    const defaults = new PluginConfig();
    expect(defaults.profile).toBe("observe");
    expect(defaults.enforcement.mode).toBe("observe");

    applySecurityProfile(defaults, "competition");
    expect(defaults).toMatchObject({
      profile: "competition",
      enforcement: { mode: "approval" },
      semantic: { enabled: true, mode: "risk-tiered", judgeToolCalls: true, judgeMemoryWrites: true, judgeProvenance: true },
      policy: { deterministic: true, taintFeedback: true, restrictWritesToAllowedRoots: true },
      responseCover: { enabled: true },
    });
    expect(defaults.policy.allowedWriteRoots).toEqual(["notes", "reports", "output", "src", "tests"]);
  });

  it("applies an explicit profile before nested overrides", () => {
    const config = PluginConfig.fromPluginConfig({
      profile: "competition",
      semantic: { judgeProvenance: false },
    });
    expect(config.profile).toBe("competition");
    expect(config.semantic.enabled).toBe(true);
    expect(config.semantic.judgeProvenance).toBe(false);
  });

  it("parses and normalizes every public configuration section", () => {
    const config = PluginConfig.fromPluginConfig({
      dashboard: { enabled: false, host: "0.0.0.0", port: 9999 },
      storage: { stateDir: " .state ", maxRecords: 123 },
      capture: { includeMessageText: false, includeToolParams: false, includeSystemPromptPreview: true, previewChars: 321 },
      detection: { enabled: false, askThreshold: 90, denyThreshold: 80 },
      semantic: {
        enabled: true,
        mode: "full",
        judgeToolCalls: false,
        judgeMessages: true,
        judgeProvenance: true,
        judgeMemoryWrites: false,
        baseUrl: " https://judge.example/v1 ",
        model: "judge-model",
        apiKeyEnv: "JUDGE_KEY",
        timeoutMs: 4321,
        maxInputChars: 7654,
      },
      provenanceScan: { enabled: false, scanSkills: false, scanConfig: false, scanSensitiveFiles: false, maxFiles: 12, maxFileBytes: 34, rescanIntervalMs: 56 },
      policy: {
        deterministic: false,
        taintFeedback: false,
        restrictWritesToAllowedRoots: true,
        allowlistedRecipients: ["a@example.com", "a@example.com"],
        allowlistedApiHosts: ["api.example.com"],
        allowedWriteRoots: ["reports"],
        sensitiveAssets: ["vault.txt"],
      },
      runtimeIsolation: { requireKernelObserverForHighRisk: true, unavailableAction: "block", auditAfterExecution: false },
      enforcement: { mode: "block", approvalTimeoutMs: 2222 },
      notifications: { enableProactiveNotifications: true, minSeverity: "warning", maxMessageChars: 444 },
      responseCover: { enabled: true, coverAssistantAfterContamination: false, message: "covered" },
    });

    expect(config.dashboard).toEqual({ enabled: false, host: "0.0.0.0", port: 9999 });
    expect(config.storage).toEqual({ stateDir: ".state", maxRecords: 123 });
    expect(config.detection.askThreshold).toBe(70);
    expect(config.semantic).toMatchObject({ enabled: true, mode: "full", baseUrl: "https://judge.example/v1", judgeMessages: true });
    expect(config.policy.allowlistedRecipients).toEqual(["a@example.com"]);
    expect(config.runtimeIsolation).toEqual({ requireKernelObserverForHighRisk: true, unavailableAction: "block", auditAfterExecution: false });
    expect(config.enforcement.mode).toBe("block");
    expect(config.responseCover.message).toBe("covered");
  });

  it("ignores malformed values and supports all named postures", () => {
    expect(PluginConfig.fromPluginConfig(null)).toBeInstanceOf(PluginConfig);
    const malformed = PluginConfig.fromPluginConfig({
      profile: "not-a-profile",
      dashboard: { port: -1 },
      semantic: { mode: "invalid" },
      enforcement: { mode: "invalid" },
      runtimeIsolation: { unavailableAction: "invalid" },
      notifications: { minSeverity: "invalid" },
      policy: { sensitiveAssets: [] },
    });
    expect(malformed.profile).toBe("observe");
    expect(malformed.dashboard.port).toBe(8765);

    for (const profile of ["observe", "balanced", "competition", "high-security"] as const) {
      applySecurityProfile(malformed, profile);
      expect(malformed.profile).toBe(profile);
    }
    expect(malformed.enforcement.mode).toBe("block");
    expect(malformed.runtimeIsolation.unavailableAction).toBe("block");
  });
});
