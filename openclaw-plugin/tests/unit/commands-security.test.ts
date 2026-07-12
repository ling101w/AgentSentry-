import { describe, expect, it, vi } from "vitest";
import { PluginConfig } from "../../config.ts";
import { formatStatus, handleAgentSentryCommand } from "../../core/commands.ts";

type Runtime = Parameters<typeof handleAgentSentryCommand>[3];

function runtime(): Runtime {
  return {
    dashboardUrl: "http://127.0.0.1:8765",
    recordsPath: "C:/state/records.jsonl",
    runtimeConfigPath: "C:/state/runtime-config.json",
    approvalCachePath: "C:/state/approvals.json",
    sessionCount: 3,
    approvalCacheCount: 2,
    resetRecords: vi.fn(),
    clearProvenanceCache: vi.fn(),
    clearApprovalCache: vi.fn(),
    setConfig: vi.fn(),
    persistConfig: vi.fn(),
    resetRuntimeConfig: vi.fn(),
  };
}

describe("AgentSentry command safety", () => {
  it("reports the active security posture without exposing secret values", () => {
    const config = new PluginConfig();
    config.semantic.enabled = true;
    config.semantic.apiKeyEnv = "PRIVATE_JUDGE_KEY";
    process.env.PRIVATE_JUDGE_KEY = "never-print-this-secret";
    const text = formatStatus(config, runtime());
    delete process.env.PRIVATE_JUDGE_KEY;

    expect(text).toContain("OBSERVE / OBSERVE");
    expect(text).toContain("PRIVATE_JUDGE_KEY");
    expect(text).not.toContain("never-print-this-secret");
    expect(text).toContain("Approval cache: 2 exact operation(s)");
  });

  it("applies and persists a named profile while invalidating provenance state", () => {
    const config = new PluginConfig();
    const hooks = runtime();
    const result = handleAgentSentryCommand({ args: "profile competition" }, config, new PluginConfig(), hooks);

    expect(result.text).toContain("COMPETITION / APPROVAL");
    expect(config).toMatchObject({
      profile: "competition",
      enforcement: { mode: "approval" },
      semantic: { enabled: true },
      policy: { restrictWritesToAllowedRoots: true },
    });
    expect(hooks.setConfig).toHaveBeenCalledWith(config);
    expect(hooks.persistConfig).toHaveBeenCalledWith(config);
    expect(hooks.clearProvenanceCache).toHaveBeenCalledOnce();
  });

  it("rejects unknown profiles and read-only or nonexistent paths without mutating config", () => {
    const config = new PluginConfig();
    const hooks = runtime();
    expect(handleAgentSentryCommand({ args: "profile unrestricted" }, config, new PluginConfig(), hooks).text).toContain("Usage:");
    expect(handleAgentSentryCommand({ args: "config set dashboard.host 0.0.0.0" }, config, new PluginConfig(), hooks).text).toContain("read-only");
    expect(handleAgentSentryCommand({ args: "config set policy.missing true" }, config, new PluginConfig(), hooks).text).toContain("read-only");
    expect(config.dashboard.host).toBe("127.0.0.1");
    expect(hooks.setConfig).not.toHaveBeenCalled();
    expect(hooks.persistConfig).not.toHaveBeenCalled();
  });

  it("validates scalar and array types before persisting writable configuration", () => {
    const config = new PluginConfig();
    const hooks = runtime();

    const enabled = handleAgentSentryCommand({ args: "config set semantic.enabled true" }, config, new PluginConfig(), hooks);
    expect(enabled.text).toContain("semantic.enabled set to true");
    expect(config.semantic.enabled).toBe(true);
    expect(hooks.clearProvenanceCache).toHaveBeenCalledOnce();

    const invalidNumber = handleAgentSentryCommand({ args: "config set detection.denyThreshold NaN" }, config, new PluginConfig(), hooks);
    expect(invalidNumber.text).toContain("Type mismatch");
    expect(config.detection.denyThreshold).toBe(70);

    const invalidArray = handleAgentSentryCommand(
      { args: 'config set policy.allowlistedRecipients ["safe@example.com",42]' },
      config,
      new PluginConfig(),
      hooks,
    );
    expect(invalidArray.text).toContain("Type mismatch");
    expect(config.policy.allowlistedRecipients).toEqual([]);

    const recipients = handleAgentSentryCommand(
      { args: "config set policy.allowlistedRecipients safe@example.com, audit@example.com" },
      config,
      new PluginConfig(),
      hooks,
    );
    expect(recipients.text).toContain('["safe@example.com","audit@example.com"]');
    expect(config.policy.allowlistedRecipients).toEqual(["safe@example.com", "audit@example.com"]);
  });

  it.each([
    ["semantic.mode", "unrestricted", "risk-tiered", "off, risk-tiered, full"],
    ["enforcement.mode", "permissive", "observe", "observe, approval, block"],
    ["runtimeIsolation.unavailableAction", "continue", "require_approval", "require_approval, block"],
    ["notifications.minSeverity", "info", "danger", "warning, danger"],
  ])("rejects invalid enum value for %s without mutating or persisting", (key, invalidValue, originalValue, allowedValues) => {
    const config = new PluginConfig();
    const hooks = runtime();

    const result = handleAgentSentryCommand(
      { args: `config set ${key} ${invalidValue}` },
      config,
      new PluginConfig(),
      hooks,
    );

    expect(result.text).toBe(`Invalid value for ${key}: expected one of ${allowedValues}.`);
    expect(readConfigPath(config, key)).toBe(originalValue);
    expect(hooks.setConfig).not.toHaveBeenCalled();
    expect(hooks.persistConfig).not.toHaveBeenCalled();
    expect(hooks.clearProvenanceCache).not.toHaveBeenCalled();
  });

  it.each([
    ["semantic.mode", "full"],
    ["enforcement.mode", "approval"],
    ["runtimeIsolation.unavailableAction", "block"],
    ["notifications.minSeverity", "warning"],
  ])("accepts allowed enum value for %s", (key, allowedValue) => {
    const config = new PluginConfig();
    const hooks = runtime();

    const result = handleAgentSentryCommand(
      { args: `config set ${key} ${allowedValue}` },
      config,
      new PluginConfig(),
      hooks,
    );

    expect(result.text).toContain(`${key} set to ${JSON.stringify(allowedValue)}`);
    expect(readConfigPath(config, key)).toBe(allowedValue);
    expect(hooks.setConfig).toHaveBeenCalledWith(config);
    expect(hooks.persistConfig).toHaveBeenCalledWith(config);
  });

  it("resets only writable runtime settings to startup values", () => {
    const startup = new PluginConfig();
    startup.capture.previewChars = 777;
    startup.semantic.model = "startup-judge";
    const config = new PluginConfig();
    config.capture.previewChars = 50;
    config.semantic.model = "runtime-judge";
    config.dashboard.port = 9999;
    const hooks = runtime();

    const result = handleAgentSentryCommand({ args: "config reset" }, config, startup, hooks);
    expect(result.text).toContain("reset to startup values");
    expect(config.capture.previewChars).toBe(777);
    expect(config.semantic.model).toBe("startup-judge");
    expect(config.dashboard.port).toBe(9999);
    expect(hooks.setConfig).toHaveBeenCalledWith(config);
    expect(hooks.resetRuntimeConfig).toHaveBeenCalledOnce();
    expect(hooks.clearProvenanceCache).toHaveBeenCalledOnce();
  });

  it("keeps record and approval reset commands narrowly scoped", () => {
    const config = new PluginConfig();
    const hooks = runtime();
    expect(handleAgentSentryCommand({ args: "reset" }, config, new PluginConfig(), hooks).text).toContain("records cleared");
    expect(hooks.resetRecords).toHaveBeenCalledOnce();
    expect(hooks.clearApprovalCache).not.toHaveBeenCalled();

    expect(handleAgentSentryCommand({ args: "approvals status" }, config, new PluginConfig(), hooks).text).toContain("2 exact operation");
    expect(handleAgentSentryCommand({ args: "approvals reset" }, config, new PluginConfig(), hooks).text).toContain("approval cache cleared");
    expect(hooks.clearApprovalCache).toHaveBeenCalledOnce();
    expect(handleAgentSentryCommand({ args: "approvals delete" }, config, new PluginConfig(), hooks).text).toContain("Usage:");
  });

  it("lists writable configuration and handles unknown commands without side effects", () => {
    const config = new PluginConfig();
    const hooks = runtime();
    const listed = handleAgentSentryCommand({ args: "config get" }, config, new PluginConfig(), hooks).text;
    expect(listed).toContain("policy.deterministic");
    expect(listed).not.toContain("dashboard.host");
    expect(handleAgentSentryCommand({ args: "config get missing.path" }, config, new PluginConfig(), hooks).text).toContain("not found");
    expect(handleAgentSentryCommand({ args: "unknown" }, config, new PluginConfig(), hooks).text).toContain("Usage:");
    expect(hooks.persistConfig).not.toHaveBeenCalled();
  });
});

function readConfigPath(config: PluginConfig, path: string): unknown {
  return path.split(".").reduce<unknown>((value, key) => (value as Record<string, unknown>)[key], config);
}
