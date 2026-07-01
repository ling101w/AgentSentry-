export type EnforcementMode = "observe" | "approval" | "block";
export type NotificationSeverity = "warning" | "danger";

export class PluginConfig {
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
    judgeToolCalls: boolean;
    judgeMessages: boolean;
    judgeFoundation: boolean;
    baseUrl: string;
    model: string;
    apiKeyEnv: string;
    timeoutMs: number;
    maxInputChars: number;
  };
  foundationScan: {
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
      judgeToolCalls: true,
      judgeMessages: false,
      judgeFoundation: false,
      baseUrl: "https://api.openai.com/v1",
      model: "gpt-4o-mini",
      apiKeyEnv: "AGENTSENTRY_API_KEY",
      timeoutMs: 12000,
      maxInputChars: 6000,
    };
    this.foundationScan = {
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
      allowlistedRecipients: ["user@example.com", "security@example.com"],
      allowlistedApiHosts: [],
      allowedWriteRoots: [],
      sensitiveAssets: ["secret.txt", "api_key", "token", "password", "system_prompt.txt", ".env", "id_rsa"],
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
  }

  static fromPluginConfig(raw: unknown): PluginConfig {
    const config = new PluginConfig();
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return config;
    const obj = raw as Record<string, unknown>;

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
      config.semantic.judgeToolCalls = readBoolean(semantic.judgeToolCalls, config.semantic.judgeToolCalls);
      config.semantic.judgeMessages = readBoolean(semantic.judgeMessages, config.semantic.judgeMessages);
      config.semantic.judgeFoundation = readBoolean(semantic.judgeFoundation, config.semantic.judgeFoundation);
      config.semantic.baseUrl = readString(semantic.baseUrl, config.semantic.baseUrl);
      config.semantic.model = readString(semantic.model, config.semantic.model);
      config.semantic.apiKeyEnv = readString(semantic.apiKeyEnv, config.semantic.apiKeyEnv);
      config.semantic.timeoutMs = readPositiveInt(semantic.timeoutMs, config.semantic.timeoutMs);
      config.semantic.maxInputChars = readPositiveInt(semantic.maxInputChars, config.semantic.maxInputChars);
    }

    const foundationScan = objectAt(obj, "foundationScan");
    if (foundationScan) {
      config.foundationScan.enabled = readBoolean(foundationScan.enabled, config.foundationScan.enabled);
      config.foundationScan.scanSkills = readBoolean(foundationScan.scanSkills, config.foundationScan.scanSkills);
      config.foundationScan.scanConfig = readBoolean(foundationScan.scanConfig, config.foundationScan.scanConfig);
      config.foundationScan.scanSensitiveFiles = readBoolean(foundationScan.scanSensitiveFiles, config.foundationScan.scanSensitiveFiles);
      config.foundationScan.maxFiles = readPositiveInt(foundationScan.maxFiles, config.foundationScan.maxFiles);
      config.foundationScan.maxFileBytes = readPositiveInt(foundationScan.maxFileBytes, config.foundationScan.maxFileBytes);
      config.foundationScan.rescanIntervalMs = readPositiveInt(foundationScan.rescanIntervalMs, config.foundationScan.rescanIntervalMs);
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
