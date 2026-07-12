import { readFileSync } from "node:fs";

export type EnforcementMode = "observe" | "approval" | "block";
export type NotificationSeverity = "warning" | "danger";
export type SemanticJudgeMode = "off" | "risk-tiered" | "full";
export type RuntimeIsolationUnavailableAction = "require_approval" | "block";
export type SecurityProfileName = "observe" | "balanced" | "competition" | "high-security";

export interface SecurityProfileDefinition {
  profile: SecurityProfileName;
  enforcement: {
    mode: EnforcementMode;
  };
  semantic: {
    enabled: boolean;
    mode: SemanticJudgeMode;
    judgeToolCalls: boolean;
    judgeMessages: boolean;
    judgeProvenance: boolean;
    judgeMemoryWrites: boolean;
  };
  policy: {
    deterministic: boolean;
    taintFeedback: boolean;
    restrictWritesToAllowedRoots: boolean;
    allowedWriteRoots: string[];
  };
  runtimeIsolation: {
    requireKernelObserverForHighRisk: boolean;
    unavailableAction: RuntimeIsolationUnavailableAction;
    auditAfterExecution: boolean;
  };
  responseCover: {
    enabled: boolean;
    coverAssistantAfterContamination: boolean;
  };
  notifications: {
    enableProactiveNotifications: boolean;
    minSeverity: NotificationSeverity;
  };
}

export class PluginConfig {
  profile: SecurityProfileName;
  dashboard: {
    enabled: boolean;
    host: string;
    port: number;
  };
  storage: {
    stateDir: string;
    maxRecords: number;
  };
  capture: {
    includeMessageText: boolean;
    includeToolParams: boolean;
    includeSystemPromptPreview: boolean;
    previewChars: number;
  };
  detection: {
    enabled: boolean;
    askThreshold: number;
    denyThreshold: number;
  };
  semantic: {
    enabled: boolean;
    mode: SemanticJudgeMode;
    judgeToolCalls: boolean;
    judgeMessages: boolean;
    judgeProvenance: boolean;
    judgeMemoryWrites: boolean;
    baseUrl: string;
    model: string;
    apiKeyEnv: string;
    timeoutMs: number;
    maxInputChars: number;
  };
  provenanceScan: {
    enabled: boolean;
    scanSkills: boolean;
    scanConfig: boolean;
    scanSensitiveFiles: boolean;
    maxFiles: number;
    maxFileBytes: number;
    rescanIntervalMs: number;
  };
  policy: {
    deterministic: boolean;
    taintFeedback: boolean;
    restrictWritesToAllowedRoots: boolean;
    allowlistedRecipients: string[];
    allowlistedApiHosts: string[];
    allowedWriteRoots: string[];
    sensitiveAssets: string[];
  };
  runtimeIsolation: {
    requireKernelObserverForHighRisk: boolean;
    unavailableAction: RuntimeIsolationUnavailableAction;
    auditAfterExecution: boolean;
  };
  enforcement: {
    mode: EnforcementMode;
    approvalTimeoutMs: number;
  };
  notifications: {
    enableProactiveNotifications: boolean;
    minSeverity: NotificationSeverity;
    maxMessageChars: number;
  };
  responseCover: {
    enabled: boolean;
    coverAssistantAfterContamination: boolean;
    message: string;
  };

  constructor() {
    this.profile = "observe";
    this.dashboard = {
      enabled: true,
      host: "127.0.0.1",
      port: 8765,
    };
    this.storage = {
      stateDir: "",
      maxRecords: 10000,
    };
    this.capture = {
      includeMessageText: true,
      includeToolParams: true,
      includeSystemPromptPreview: false,
      previewChars: 1200,
    };
    this.detection = {
      enabled: true,
      askThreshold: 40,
      denyThreshold: 70,
    };
    this.semantic = {
      enabled: false,
      mode: "risk-tiered",
      judgeToolCalls: true,
      judgeMessages: false,
      judgeProvenance: false,
      judgeMemoryWrites: true,
      baseUrl: "https://api.openai.com/v1",
      model: "gpt-4o-mini",
      apiKeyEnv: "AGENTSENTRY_API_KEY",
      timeoutMs: 12000,
      maxInputChars: 6000,
    };
    this.provenanceScan = {
      enabled: true,
      scanSkills: true,
      scanConfig: true,
      scanSensitiveFiles: true,
      maxFiles: 800,
      maxFileBytes: 512000,
      rescanIntervalMs: 300000,
    };
    this.policy = {
      deterministic: true,
      taintFeedback: true,
      restrictWritesToAllowedRoots: false,
      allowlistedRecipients: [],
      allowlistedApiHosts: [],
      allowedWriteRoots: [],
      sensitiveAssets: ["secret.txt", "api_key", "token", "password", "system_prompt.txt", ".env", "id_rsa"],
    };
    this.runtimeIsolation = {
      requireKernelObserverForHighRisk: false,
      unavailableAction: "require_approval",
      auditAfterExecution: true,
    };
    this.enforcement = {
      mode: "observe",
      approvalTimeoutMs: 300000,
    };
    this.notifications = {
      enableProactiveNotifications: false,
      minSeverity: "danger",
      maxMessageChars: 1500,
    };
    this.responseCover = {
      enabled: false,
      coverAssistantAfterContamination: true,
      message: "AgentSentry detected contaminated tool output in this turn, so the assistant response was covered. Review the AgentSentry dashboard before trusting or reusing the blocked content.",
    };
    applySecurityProfile(this, "observe");
  }

  static fromPluginConfig(raw: unknown): PluginConfig {
    const config = new PluginConfig();
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return config;
    const obj = raw as Record<string, unknown>;

    const profile = readString(obj.profile, config.profile);
    if (isSecurityProfileName(profile)) applySecurityProfile(config, profile);

    const dashboard = objectAt(obj, "dashboard");
    if (dashboard) {
      config.dashboard.enabled = readBoolean(dashboard.enabled, config.dashboard.enabled);
      config.dashboard.host = readString(dashboard.host, config.dashboard.host);
      config.dashboard.port = readPositiveInt(dashboard.port, config.dashboard.port);
    }

    const storage = objectAt(obj, "storage");
    if (storage) {
      config.storage.stateDir = readString(storage.stateDir, config.storage.stateDir);
      config.storage.maxRecords = readPositiveInt(storage.maxRecords, config.storage.maxRecords);
    }

    const capture = objectAt(obj, "capture");
    if (capture) {
      config.capture.includeMessageText = readBoolean(capture.includeMessageText, config.capture.includeMessageText);
      config.capture.includeToolParams = readBoolean(capture.includeToolParams, config.capture.includeToolParams);
      config.capture.includeSystemPromptPreview = readBoolean(capture.includeSystemPromptPreview, config.capture.includeSystemPromptPreview);
      config.capture.previewChars = readPositiveInt(capture.previewChars, config.capture.previewChars);
    }

    const detection = objectAt(obj, "detection");
    if (detection) {
      config.detection.enabled = readBoolean(detection.enabled, config.detection.enabled);
      config.detection.askThreshold = readPositiveInt(detection.askThreshold, config.detection.askThreshold);
      config.detection.denyThreshold = readPositiveInt(detection.denyThreshold, config.detection.denyThreshold);
      if (config.detection.askThreshold >= config.detection.denyThreshold) {
        config.detection.askThreshold = Math.max(1, config.detection.denyThreshold - 10);
      }
    }

    const semantic = objectAt(obj, "semantic");
    if (semantic) {
      config.semantic.enabled = readBoolean(semantic.enabled, config.semantic.enabled);
      const mode = readString(semantic.mode, config.semantic.mode);
      if (mode === "off" || mode === "risk-tiered" || mode === "full") {
        config.semantic.mode = mode;
      }
      config.semantic.judgeToolCalls = readBoolean(semantic.judgeToolCalls, config.semantic.judgeToolCalls);
      config.semantic.judgeMessages = readBoolean(semantic.judgeMessages, config.semantic.judgeMessages);
      config.semantic.judgeProvenance = readBoolean(semantic.judgeProvenance, config.semantic.judgeProvenance);
      config.semantic.judgeMemoryWrites = readBoolean(semantic.judgeMemoryWrites, config.semantic.judgeMemoryWrites);
      config.semantic.baseUrl = readString(semantic.baseUrl, config.semantic.baseUrl);
      config.semantic.model = readString(semantic.model, config.semantic.model);
      config.semantic.apiKeyEnv = readString(semantic.apiKeyEnv, config.semantic.apiKeyEnv);
      config.semantic.timeoutMs = readPositiveInt(semantic.timeoutMs, config.semantic.timeoutMs);
      config.semantic.maxInputChars = readPositiveInt(semantic.maxInputChars, config.semantic.maxInputChars);
    }

    const provenanceScan = objectAt(obj, "provenanceScan");
    if (provenanceScan) {
      config.provenanceScan.enabled = readBoolean(provenanceScan.enabled, config.provenanceScan.enabled);
      config.provenanceScan.scanSkills = readBoolean(provenanceScan.scanSkills, config.provenanceScan.scanSkills);
      config.provenanceScan.scanConfig = readBoolean(provenanceScan.scanConfig, config.provenanceScan.scanConfig);
      config.provenanceScan.scanSensitiveFiles = readBoolean(provenanceScan.scanSensitiveFiles, config.provenanceScan.scanSensitiveFiles);
      config.provenanceScan.maxFiles = readPositiveInt(provenanceScan.maxFiles, config.provenanceScan.maxFiles);
      config.provenanceScan.maxFileBytes = readPositiveInt(provenanceScan.maxFileBytes, config.provenanceScan.maxFileBytes);
      config.provenanceScan.rescanIntervalMs = readPositiveInt(provenanceScan.rescanIntervalMs, config.provenanceScan.rescanIntervalMs);
    }

    const policy = objectAt(obj, "policy");
    if (policy) {
      config.policy.deterministic = readBoolean(policy.deterministic, config.policy.deterministic);
      config.policy.taintFeedback = readBoolean(policy.taintFeedback, config.policy.taintFeedback);
      config.policy.restrictWritesToAllowedRoots = readBoolean(policy.restrictWritesToAllowedRoots, config.policy.restrictWritesToAllowedRoots);
      config.policy.allowlistedRecipients = readStringArray(policy.allowlistedRecipients, config.policy.allowlistedRecipients);
      config.policy.allowlistedApiHosts = readStringArray(policy.allowlistedApiHosts, config.policy.allowlistedApiHosts);
      config.policy.allowedWriteRoots = readStringArray(policy.allowedWriteRoots, config.policy.allowedWriteRoots);
      config.policy.sensitiveAssets = readStringArray(policy.sensitiveAssets, config.policy.sensitiveAssets);
    }

    const runtimeIsolation = objectAt(obj, "runtimeIsolation");
    if (runtimeIsolation) {
      config.runtimeIsolation.requireKernelObserverForHighRisk = readBoolean(
        runtimeIsolation.requireKernelObserverForHighRisk,
        config.runtimeIsolation.requireKernelObserverForHighRisk,
      );
      const unavailableAction = readString(runtimeIsolation.unavailableAction, config.runtimeIsolation.unavailableAction);
      if (unavailableAction === "require_approval" || unavailableAction === "block") {
        config.runtimeIsolation.unavailableAction = unavailableAction;
      }
      config.runtimeIsolation.auditAfterExecution = readBoolean(
        runtimeIsolation.auditAfterExecution,
        config.runtimeIsolation.auditAfterExecution,
      );
    }

    const enforcement = objectAt(obj, "enforcement");
    if (enforcement) {
      const mode = readString(enforcement.mode, config.enforcement.mode);
      if (mode === "observe" || mode === "approval" || mode === "block") {
        config.enforcement.mode = mode;
      }
      config.enforcement.approvalTimeoutMs = readPositiveInt(enforcement.approvalTimeoutMs, config.enforcement.approvalTimeoutMs);
    }

    const notifications = objectAt(obj, "notifications");
    if (notifications) {
      config.notifications.enableProactiveNotifications = readBoolean(
        notifications.enableProactiveNotifications,
        config.notifications.enableProactiveNotifications,
      );
      const minSeverity = readString(notifications.minSeverity, config.notifications.minSeverity);
      if (minSeverity === "warning" || minSeverity === "danger") {
        config.notifications.minSeverity = minSeverity;
      }
      config.notifications.maxMessageChars = readPositiveInt(notifications.maxMessageChars, config.notifications.maxMessageChars);
    }

    const responseCover = objectAt(obj, "responseCover");
    if (responseCover) {
      config.responseCover.enabled = readBoolean(responseCover.enabled, config.responseCover.enabled);
      config.responseCover.coverAssistantAfterContamination = readBoolean(
        responseCover.coverAssistantAfterContamination,
        config.responseCover.coverAssistantAfterContamination,
      );
      config.responseCover.message = readString(responseCover.message, config.responseCover.message);
    }

    return config;
  }
}

export function applySecurityProfile(config: PluginConfig, profile: SecurityProfileName): PluginConfig {
  const definition = loadSecurityProfileDefinition(profile);

  config.profile = definition.profile;
  config.enforcement.mode = definition.enforcement.mode;
  config.semantic.enabled = definition.semantic.enabled;
  config.semantic.mode = definition.semantic.mode;
  config.semantic.judgeToolCalls = definition.semantic.judgeToolCalls;
  config.semantic.judgeMessages = definition.semantic.judgeMessages;
  config.semantic.judgeProvenance = definition.semantic.judgeProvenance;
  config.semantic.judgeMemoryWrites = definition.semantic.judgeMemoryWrites;
  config.policy.deterministic = definition.policy.deterministic;
  config.policy.taintFeedback = definition.policy.taintFeedback;
  config.policy.restrictWritesToAllowedRoots = definition.policy.restrictWritesToAllowedRoots;
  if (definition.policy.allowedWriteRoots.length && !config.policy.allowedWriteRoots.length) {
    config.policy.allowedWriteRoots = [...definition.policy.allowedWriteRoots];
  }
  config.runtimeIsolation.requireKernelObserverForHighRisk = definition.runtimeIsolation.requireKernelObserverForHighRisk;
  config.runtimeIsolation.unavailableAction = definition.runtimeIsolation.unavailableAction;
  config.runtimeIsolation.auditAfterExecution = definition.runtimeIsolation.auditAfterExecution;
  config.responseCover.enabled = definition.responseCover.enabled;
  config.responseCover.coverAssistantAfterContamination = definition.responseCover.coverAssistantAfterContamination;
  config.notifications.enableProactiveNotifications = definition.notifications.enableProactiveNotifications;
  config.notifications.minSeverity = definition.notifications.minSeverity;
  return config;
}

export function loadSecurityProfileDefinition(
  profile: SecurityProfileName,
  profileDirectory = new URL("./profiles/", import.meta.url),
): SecurityProfileDefinition {
  const profileUrl = new URL(`${profile}.json`, profileDirectory);
  let source: string;
  try {
    source = readFileSync(profileUrl, "utf8");
  } catch (error) {
    throw profileLoadError(profile, profileUrl, "could not be read", error);
  }

  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch (error) {
    throw profileLoadError(profile, profileUrl, "contains invalid JSON", error);
  }

  try {
    return parseSecurityProfileDefinition(value, profile);
  } catch (error) {
    throw profileLoadError(profile, profileUrl, "failed validation", error);
  }
}

function parseSecurityProfileDefinition(value: unknown, expectedProfile: SecurityProfileName): SecurityProfileDefinition {
  const root = requireProfileObject(value, "profile");
  assertOnlyProfileKeys(root, "profile", [
    "profile",
    "enforcement",
    "semantic",
    "policy",
    "runtimeIsolation",
    "responseCover",
    "notifications",
  ]);

  const declaredProfile = requireProfileEnum(root.profile, "profile.profile", ["observe", "balanced", "competition", "high-security"]);
  if (declaredProfile !== expectedProfile) {
    throw new Error(`profile.profile must be "${expectedProfile}", received "${declaredProfile}"`);
  }

  const enforcement = requireProfileObject(root.enforcement, "profile.enforcement");
  assertOnlyProfileKeys(enforcement, "profile.enforcement", ["mode"]);
  const semantic = requireProfileObject(root.semantic, "profile.semantic");
  assertOnlyProfileKeys(semantic, "profile.semantic", [
    "enabled",
    "mode",
    "judgeToolCalls",
    "judgeMessages",
    "judgeProvenance",
    "judgeMemoryWrites",
  ]);
  const policy = requireProfileObject(root.policy, "profile.policy");
  assertOnlyProfileKeys(policy, "profile.policy", [
    "deterministic",
    "taintFeedback",
    "restrictWritesToAllowedRoots",
    "allowedWriteRoots",
  ]);
  const runtimeIsolation = requireProfileObject(root.runtimeIsolation, "profile.runtimeIsolation");
  assertOnlyProfileKeys(runtimeIsolation, "profile.runtimeIsolation", [
    "requireKernelObserverForHighRisk",
    "unavailableAction",
    "auditAfterExecution",
  ]);
  const responseCover = requireProfileObject(root.responseCover, "profile.responseCover");
  assertOnlyProfileKeys(responseCover, "profile.responseCover", ["enabled", "coverAssistantAfterContamination"]);
  const notifications = requireProfileObject(root.notifications, "profile.notifications");
  assertOnlyProfileKeys(notifications, "profile.notifications", ["enableProactiveNotifications", "minSeverity"]);

  return {
    profile: declaredProfile,
    enforcement: {
      mode: requireProfileEnum(enforcement.mode, "profile.enforcement.mode", ["observe", "approval", "block"]),
    },
    semantic: {
      enabled: requireProfileBoolean(semantic.enabled, "profile.semantic.enabled"),
      mode: requireProfileEnum(semantic.mode, "profile.semantic.mode", ["off", "risk-tiered", "full"]),
      judgeToolCalls: requireProfileBoolean(semantic.judgeToolCalls, "profile.semantic.judgeToolCalls"),
      judgeMessages: requireProfileBoolean(semantic.judgeMessages, "profile.semantic.judgeMessages"),
      judgeProvenance: requireProfileBoolean(semantic.judgeProvenance, "profile.semantic.judgeProvenance"),
      judgeMemoryWrites: requireProfileBoolean(semantic.judgeMemoryWrites, "profile.semantic.judgeMemoryWrites"),
    },
    policy: {
      deterministic: requireProfileBoolean(policy.deterministic, "profile.policy.deterministic"),
      taintFeedback: requireProfileBoolean(policy.taintFeedback, "profile.policy.taintFeedback"),
      restrictWritesToAllowedRoots: requireProfileBoolean(
        policy.restrictWritesToAllowedRoots,
        "profile.policy.restrictWritesToAllowedRoots",
      ),
      allowedWriteRoots: requireProfileStringArray(policy.allowedWriteRoots, "profile.policy.allowedWriteRoots"),
    },
    runtimeIsolation: {
      requireKernelObserverForHighRisk: requireProfileBoolean(
        runtimeIsolation.requireKernelObserverForHighRisk,
        "profile.runtimeIsolation.requireKernelObserverForHighRisk",
      ),
      unavailableAction: requireProfileEnum(
        runtimeIsolation.unavailableAction,
        "profile.runtimeIsolation.unavailableAction",
        ["require_approval", "block"],
      ),
      auditAfterExecution: requireProfileBoolean(runtimeIsolation.auditAfterExecution, "profile.runtimeIsolation.auditAfterExecution"),
    },
    responseCover: {
      enabled: requireProfileBoolean(responseCover.enabled, "profile.responseCover.enabled"),
      coverAssistantAfterContamination: requireProfileBoolean(
        responseCover.coverAssistantAfterContamination,
        "profile.responseCover.coverAssistantAfterContamination",
      ),
    },
    notifications: {
      enableProactiveNotifications: requireProfileBoolean(
        notifications.enableProactiveNotifications,
        "profile.notifications.enableProactiveNotifications",
      ),
      minSeverity: requireProfileEnum(notifications.minSeverity, "profile.notifications.minSeverity", ["warning", "danger"]),
    },
  };
}

export function isSecurityProfileName(value: string): value is SecurityProfileName {
  return value === "observe" || value === "balanced" || value === "competition" || value === "high-security";
}

function profileLoadError(profile: SecurityProfileName, profileUrl: URL, reason: string, cause: unknown): Error {
  const detail = cause instanceof Error ? cause.message : String(cause);
  return new Error(`AgentSentry security profile "${profile}" at ${profileUrl.pathname} ${reason}: ${detail}`, { cause });
}

function requireProfileObject(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function assertOnlyProfileKeys(
  value: Record<string, unknown>,
  path: string,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[] = allowedKeys,
): void {
  const allowed = new Set(allowedKeys);
  const unexpected = Object.keys(value).filter((key) => !allowed.has(key));
  if (unexpected.length) throw new Error(`${path} contains unknown field(s): ${unexpected.join(", ")}`);
  const missing = requiredKeys.filter((key) => !(key in value));
  if (missing.length) throw new Error(`${path} is missing required field(s): ${missing.join(", ")}`);
}

function requireProfileBoolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${path} must be a boolean`);
  return value;
}

function requireProfileEnum<const T extends string>(value: unknown, path: string, allowed: readonly T[]): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${path} must be one of: ${allowed.join(", ")}`);
  }
  return value as T;
}

function requireProfileStringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item.trim())) {
    throw new Error(`${path} must be an array of non-empty strings`);
  }
  const normalized = value.map((item) => (item as string).trim());
  if (new Set(normalized).size !== normalized.length) throw new Error(`${path} must not contain duplicate values`);
  return normalized;
}

function objectAt(obj: Record<string, unknown>, key: string): Record<string, unknown> | null {
  const value = obj[key];
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function readBoolean(value: unknown, defaultValue: boolean): boolean {
  return typeof value === "boolean" ? value : defaultValue;
}

function readString(value: unknown, defaultValue: string): string {
  return typeof value === "string" ? value.trim() : defaultValue;
}

function readPositiveInt(value: unknown, defaultValue: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.trunc(value) : defaultValue;
}

function readStringArray(value: unknown, defaultValue: string[]): string[] {
  if (!Array.isArray(value)) return defaultValue;
  const items = value.map((item) => typeof item === "string" ? item.trim() : "").filter(Boolean);
  return items.length ? Array.from(new Set(items)) : defaultValue;
}

export const ConfigSchema = {
  parse(value: unknown): PluginConfig {
    return PluginConfig.fromPluginConfig(value);
  },
};
