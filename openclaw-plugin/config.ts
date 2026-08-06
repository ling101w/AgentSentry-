import { readFileSync } from "node:fs";

export type EnforcementMode = "observe" | "approval" | "block";
export type NotificationSeverity = "warning" | "danger";
export type SemanticJudgeMode = "off" | "risk-tiered" | "full";
export type RuntimeIsolationUnavailableAction = "require_approval" | "block";
export type SecurityProfileName = "observe" | "balanced" | "competition" | "high-security";
export type AgentIdentityLevel = "owner" | "trusted_agent" | "delegated_agent" | "external_agent";

export type AgentIdentityConfig = {
  id: string;
  label: string;
  level: AgentIdentityLevel;
  tenant: string;
  namespace: string;
  mayDelegate: boolean;
  mayAuthorizeSensitiveTools: boolean;
  mayReceiveUntrustedData: boolean;
};

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
    requireNetworkNamespaceForShell: boolean;
  };
  responseCover: {
    enabled: boolean;
    coverAssistantAfterContamination: boolean;
  };
  notifications: {
    enableProactiveNotifications: boolean;
    minSeverity: NotificationSeverity;
  };
  dynamicSecurity?: {
    enabled: boolean;
    windowSize: number;
    riskThreshold: number;
    recoverAfterSafeActions: number;
    maxDegradationLevel: number;
  };
  capabilityTokens?: {
    enabled: boolean;
    ttlMs: number;
    maxInvocations: number;
  };
  rollback?: {
    enabled: boolean;
    maxSnapshots: number;
    protectedPaths: string[];
  };
  initializationDefense?: {
    enabled: boolean;
    scanGlobalOpenClaw: boolean;
    maxComponents: number;
  };
  externalPolicy?: {
    enabled: boolean;
    requireAuth: boolean;
  };
  multiAgentSecurity?: {
    enabled: boolean;
    requireIdentity: boolean;
    requireSignedEnvelope: boolean;
    maxEnvelopeTtlMs: number;
  };
}

export class PluginConfig {
  profile: SecurityProfileName;
  dashboard: {
    enabled: boolean;
    host: string;
    port: number;
    allowRemote: boolean;
    authToken: string;
  };
  storage: {
    stateDir: string;
    maxRecords: number;
    sessionIdleTtlMs: number;
    maxSessions: number;
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
    requireNetworkNamespaceForShell: boolean;
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
  dynamicSecurity: {
    enabled: boolean;
    windowSize: number;
    riskThreshold: number;
    recoverAfterSafeActions: number;
    maxDegradationLevel: number;
  };
  capabilityTokens: {
    enabled: boolean;
    ttlMs: number;
    maxInvocations: number;
  };
  rollback: {
    enabled: boolean;
    maxSnapshots: number;
    protectedPaths: string[];
  };
  initializationDefense: {
    enabled: boolean;
    scanGlobalOpenClaw: boolean;
    maxComponents: number;
  };
  externalPolicy: {
    enabled: boolean;
    requireAuth: boolean;
  };
  multiAgentSecurity: {
    enabled: boolean;
    requireIdentity: boolean;
    requireSignedEnvelope: boolean;
    maxEnvelopeTtlMs: number;
    agents: AgentIdentityConfig[];
  };

  constructor() {
    this.profile = "observe";
    this.dashboard = {
      enabled: true,
      host: "127.0.0.1",
      port: 8765,
      allowRemote: false,
      authToken: "",
    };
    this.storage = {
      stateDir: "",
      maxRecords: 10000,
      sessionIdleTtlMs: 30 * 60 * 1000,
      maxSessions: 256,
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
      timeoutMs: 1500,
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
      requireNetworkNamespaceForShell: false,
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
    this.dynamicSecurity = {
      enabled: true,
      windowSize: 12,
      riskThreshold: 65,
      recoverAfterSafeActions: 6,
      maxDegradationLevel: 3,
    };
    this.capabilityTokens = {
      enabled: true,
      ttlMs: 10 * 60 * 1000,
      maxInvocations: 5,
    };
    this.rollback = {
      enabled: true,
      maxSnapshots: 80,
      protectedPaths: ["MEMORY.md", "User.md", "Soul.md", "openclaw.json", ".openclaw/openclaw.json"],
    };
    this.initializationDefense = {
      enabled: true,
      scanGlobalOpenClaw: true,
      maxComponents: 200,
    };
    this.externalPolicy = {
      enabled: true,
      requireAuth: true,
    };
    this.multiAgentSecurity = {
      enabled: true,
      requireIdentity: true,
      requireSignedEnvelope: true,
      maxEnvelopeTtlMs: 10 * 60 * 1000,
      agents: defaultAgentIdentities(),
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
      config.dashboard.port = readNonNegativeInt(dashboard.port, config.dashboard.port);
      config.dashboard.allowRemote = readBoolean(dashboard.allowRemote, config.dashboard.allowRemote);
      config.dashboard.authToken = readString(dashboard.authToken, config.dashboard.authToken);
    }

    const storage = objectAt(obj, "storage");
    if (storage) {
      config.storage.stateDir = readString(storage.stateDir, config.storage.stateDir);
      config.storage.maxRecords = readPositiveInt(storage.maxRecords, config.storage.maxRecords);
      config.storage.sessionIdleTtlMs = readPositiveInt(storage.sessionIdleTtlMs, config.storage.sessionIdleTtlMs);
      config.storage.maxSessions = readPositiveInt(storage.maxSessions, config.storage.maxSessions);
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
      config.runtimeIsolation.requireNetworkNamespaceForShell = readBoolean(
        runtimeIsolation.requireNetworkNamespaceForShell,
        config.runtimeIsolation.requireNetworkNamespaceForShell,
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

    const dynamicSecurity = objectAt(obj, "dynamicSecurity");
    if (dynamicSecurity) {
      config.dynamicSecurity.enabled = readBoolean(dynamicSecurity.enabled, config.dynamicSecurity.enabled);
      config.dynamicSecurity.windowSize = clampInt(readPositiveInt(dynamicSecurity.windowSize, config.dynamicSecurity.windowSize), 4, 80);
      config.dynamicSecurity.riskThreshold = clampInt(readPositiveInt(dynamicSecurity.riskThreshold, config.dynamicSecurity.riskThreshold), 1, 150);
      config.dynamicSecurity.recoverAfterSafeActions = clampInt(
        readPositiveInt(dynamicSecurity.recoverAfterSafeActions, config.dynamicSecurity.recoverAfterSafeActions),
        2,
        50,
      );
      config.dynamicSecurity.maxDegradationLevel = clampInt(
        readNonNegativeInt(dynamicSecurity.maxDegradationLevel, config.dynamicSecurity.maxDegradationLevel),
        0,
        4,
      );
    }

    const capabilityTokens = objectAt(obj, "capabilityTokens");
    if (capabilityTokens) {
      config.capabilityTokens.enabled = readBoolean(capabilityTokens.enabled, config.capabilityTokens.enabled);
      config.capabilityTokens.ttlMs = clampInt(readPositiveInt(capabilityTokens.ttlMs, config.capabilityTokens.ttlMs), 30_000, 24 * 60 * 60 * 1000);
      config.capabilityTokens.maxInvocations = clampInt(
        readPositiveInt(capabilityTokens.maxInvocations, config.capabilityTokens.maxInvocations),
        1,
        100,
      );
    }

    const rollback = objectAt(obj, "rollback");
    if (rollback) {
      config.rollback.enabled = readBoolean(rollback.enabled, config.rollback.enabled);
      config.rollback.maxSnapshots = clampInt(readPositiveInt(rollback.maxSnapshots, config.rollback.maxSnapshots), 5, 1000);
      config.rollback.protectedPaths = readStringArray(rollback.protectedPaths, config.rollback.protectedPaths);
    }

    const initializationDefense = objectAt(obj, "initializationDefense");
    if (initializationDefense) {
      config.initializationDefense.enabled = readBoolean(initializationDefense.enabled, config.initializationDefense.enabled);
      config.initializationDefense.scanGlobalOpenClaw = readBoolean(initializationDefense.scanGlobalOpenClaw, config.initializationDefense.scanGlobalOpenClaw);
      config.initializationDefense.maxComponents = clampInt(
        readPositiveInt(initializationDefense.maxComponents, config.initializationDefense.maxComponents),
        10,
        2000,
      );
    }

    const externalPolicy = objectAt(obj, "externalPolicy");
    if (externalPolicy) {
      config.externalPolicy.enabled = readBoolean(externalPolicy.enabled, config.externalPolicy.enabled);
      config.externalPolicy.requireAuth = readBoolean(externalPolicy.requireAuth, config.externalPolicy.requireAuth);
    }

    const multiAgentSecurity = objectAt(obj, "multiAgentSecurity");
    if (multiAgentSecurity) {
      config.multiAgentSecurity.enabled = readBoolean(multiAgentSecurity.enabled, config.multiAgentSecurity.enabled);
      config.multiAgentSecurity.requireIdentity = readBoolean(multiAgentSecurity.requireIdentity, config.multiAgentSecurity.requireIdentity);
      config.multiAgentSecurity.requireSignedEnvelope = readBoolean(
        multiAgentSecurity.requireSignedEnvelope,
        config.multiAgentSecurity.requireSignedEnvelope,
      );
      config.multiAgentSecurity.maxEnvelopeTtlMs = clampInt(
        readPositiveInt(multiAgentSecurity.maxEnvelopeTtlMs, config.multiAgentSecurity.maxEnvelopeTtlMs),
        30_000,
        24 * 60 * 60 * 1000,
      );
      config.multiAgentSecurity.agents = readAgentIdentityArray(multiAgentSecurity.agents, config.multiAgentSecurity.agents);
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
  config.runtimeIsolation.requireNetworkNamespaceForShell = definition.runtimeIsolation.requireNetworkNamespaceForShell;
  config.responseCover.enabled = definition.responseCover.enabled;
  config.responseCover.coverAssistantAfterContamination = definition.responseCover.coverAssistantAfterContamination;
  config.notifications.enableProactiveNotifications = definition.notifications.enableProactiveNotifications;
  config.notifications.minSeverity = definition.notifications.minSeverity;
  if (definition.dynamicSecurity) {
    config.dynamicSecurity = { ...definition.dynamicSecurity };
  }
  if (definition.capabilityTokens) {
    config.capabilityTokens = { ...definition.capabilityTokens };
  }
  if (definition.rollback) {
    config.rollback = { ...definition.rollback, protectedPaths: [...definition.rollback.protectedPaths] };
  }
  if (definition.initializationDefense) {
    config.initializationDefense = { ...definition.initializationDefense };
  }
  if (definition.externalPolicy) {
    config.externalPolicy = { ...definition.externalPolicy };
  }
  if (definition.multiAgentSecurity) {
    config.multiAgentSecurity = { ...config.multiAgentSecurity, ...definition.multiAgentSecurity };
  }
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
    "dynamicSecurity",
    "capabilityTokens",
    "rollback",
    "initializationDefense",
    "externalPolicy",
    "multiAgentSecurity",
  ], [
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
    "requireNetworkNamespaceForShell",
  ]);
  const responseCover = requireProfileObject(root.responseCover, "profile.responseCover");
  assertOnlyProfileKeys(responseCover, "profile.responseCover", ["enabled", "coverAssistantAfterContamination"]);
  const notifications = requireProfileObject(root.notifications, "profile.notifications");
  assertOnlyProfileKeys(notifications, "profile.notifications", ["enableProactiveNotifications", "minSeverity"]);
  const dynamicSecurity = objectAt(root, "dynamicSecurity");
  if (dynamicSecurity) {
    assertOnlyProfileKeys(dynamicSecurity, "profile.dynamicSecurity", [
      "enabled",
      "windowSize",
      "riskThreshold",
      "recoverAfterSafeActions",
      "maxDegradationLevel",
    ]);
  }
  const capabilityTokens = objectAt(root, "capabilityTokens");
  if (capabilityTokens) {
    assertOnlyProfileKeys(capabilityTokens, "profile.capabilityTokens", ["enabled", "ttlMs", "maxInvocations"]);
  }
  const rollback = objectAt(root, "rollback");
  if (rollback) {
    assertOnlyProfileKeys(rollback, "profile.rollback", ["enabled", "maxSnapshots", "protectedPaths"]);
  }
  const initializationDefense = objectAt(root, "initializationDefense");
  if (initializationDefense) {
    assertOnlyProfileKeys(initializationDefense, "profile.initializationDefense", ["enabled", "scanGlobalOpenClaw", "maxComponents"]);
  }
  const externalPolicy = objectAt(root, "externalPolicy");
  if (externalPolicy) {
    assertOnlyProfileKeys(externalPolicy, "profile.externalPolicy", ["enabled", "requireAuth"]);
  }
  const multiAgentSecurity = objectAt(root, "multiAgentSecurity");
  if (multiAgentSecurity) {
    assertOnlyProfileKeys(multiAgentSecurity, "profile.multiAgentSecurity", ["enabled", "requireIdentity", "requireSignedEnvelope", "maxEnvelopeTtlMs"]);
  }

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
      requireNetworkNamespaceForShell: requireProfileBoolean(
        runtimeIsolation.requireNetworkNamespaceForShell,
        "profile.runtimeIsolation.requireNetworkNamespaceForShell",
      ),
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
    dynamicSecurity: dynamicSecurity
      ? {
        enabled: requireProfileBoolean(dynamicSecurity.enabled, "profile.dynamicSecurity.enabled"),
        windowSize: requireProfileInt(dynamicSecurity.windowSize, "profile.dynamicSecurity.windowSize", 4, 80),
        riskThreshold: requireProfileInt(dynamicSecurity.riskThreshold, "profile.dynamicSecurity.riskThreshold", 1, 150),
        recoverAfterSafeActions: requireProfileInt(dynamicSecurity.recoverAfterSafeActions, "profile.dynamicSecurity.recoverAfterSafeActions", 2, 50),
        maxDegradationLevel: requireProfileInt(dynamicSecurity.maxDegradationLevel, "profile.dynamicSecurity.maxDegradationLevel", 0, 4),
      }
      : undefined,
    capabilityTokens: capabilityTokens
      ? {
        enabled: requireProfileBoolean(capabilityTokens.enabled, "profile.capabilityTokens.enabled"),
        ttlMs: requireProfileInt(capabilityTokens.ttlMs, "profile.capabilityTokens.ttlMs", 30_000, 24 * 60 * 60 * 1000),
        maxInvocations: requireProfileInt(capabilityTokens.maxInvocations, "profile.capabilityTokens.maxInvocations", 1, 100),
      }
      : undefined,
    rollback: rollback
      ? {
        enabled: requireProfileBoolean(rollback.enabled, "profile.rollback.enabled"),
        maxSnapshots: requireProfileInt(rollback.maxSnapshots, "profile.rollback.maxSnapshots", 5, 1000),
        protectedPaths: requireProfileStringArray(rollback.protectedPaths, "profile.rollback.protectedPaths"),
      }
      : undefined,
    initializationDefense: initializationDefense
      ? {
        enabled: requireProfileBoolean(initializationDefense.enabled, "profile.initializationDefense.enabled"),
        scanGlobalOpenClaw: requireProfileBoolean(initializationDefense.scanGlobalOpenClaw, "profile.initializationDefense.scanGlobalOpenClaw"),
        maxComponents: requireProfileInt(initializationDefense.maxComponents, "profile.initializationDefense.maxComponents", 10, 2000),
      }
      : undefined,
    externalPolicy: externalPolicy
      ? {
        enabled: requireProfileBoolean(externalPolicy.enabled, "profile.externalPolicy.enabled"),
        requireAuth: requireProfileBoolean(externalPolicy.requireAuth, "profile.externalPolicy.requireAuth"),
      }
      : undefined,
    multiAgentSecurity: multiAgentSecurity
      ? {
        enabled: requireProfileBoolean(multiAgentSecurity.enabled, "profile.multiAgentSecurity.enabled"),
        requireIdentity: requireProfileBoolean(multiAgentSecurity.requireIdentity, "profile.multiAgentSecurity.requireIdentity"),
        requireSignedEnvelope: requireProfileBoolean(multiAgentSecurity.requireSignedEnvelope, "profile.multiAgentSecurity.requireSignedEnvelope"),
        maxEnvelopeTtlMs: requireProfileInt(multiAgentSecurity.maxEnvelopeTtlMs, "profile.multiAgentSecurity.maxEnvelopeTtlMs", 30_000, 24 * 60 * 60 * 1000),
      }
      : undefined,
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

function requireProfileInt(value: unknown, path: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) || Math.trunc(value) !== value || value < min || value > max) {
    throw new Error(`${path} must be an integer between ${min} and ${max}`);
  }
  return value;
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

function readNonNegativeInt(value: unknown, defaultValue: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.trunc(value) : defaultValue;
}

function clampInt(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.trunc(value)));
}

function readStringArray(value: unknown, defaultValue: string[]): string[] {
  if (!Array.isArray(value)) return defaultValue;
  const items = value.map((item) => typeof item === "string" ? item.trim() : "").filter(Boolean);
  return items.length ? Array.from(new Set(items)) : defaultValue;
}

function defaultAgentIdentities(): AgentIdentityConfig[] {
  return [
    {
      id: "agent:main",
      label: "主 Agent / 用户会话",
      level: "owner",
      tenant: "default",
      namespace: "primary",
      mayDelegate: true,
      mayAuthorizeSensitiveTools: true,
      mayReceiveUntrustedData: false,
    },
    {
      id: "agent:research_child",
      label: "研究子 Agent",
      level: "delegated_agent",
      tenant: "default",
      namespace: "research",
      mayDelegate: false,
      mayAuthorizeSensitiveTools: false,
      mayReceiveUntrustedData: true,
    },
    {
      id: "agent:tool_worker",
      label: "工具执行子 Agent",
      level: "trusted_agent",
      tenant: "default",
      namespace: "tools",
      mayDelegate: true,
      mayAuthorizeSensitiveTools: false,
      mayReceiveUntrustedData: false,
    },
  ];
}

function readAgentIdentityArray(value: unknown, defaultValue: AgentIdentityConfig[]): AgentIdentityConfig[] {
  if (!Array.isArray(value)) return defaultValue;
  const seen = new Set<string>();
  const output: AgentIdentityConfig[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return defaultValue;
    const record = item as Record<string, unknown>;
    const id = typeof record.id === "string" ? record.id.trim() : "";
    const label = typeof record.label === "string" ? record.label.trim() : "";
    const level = record.level;
    const tenant = typeof record.tenant === "string" ? record.tenant.trim() : "";
    const namespace = typeof record.namespace === "string" ? record.namespace.trim() : "";
    if (!id || !label || !tenant || !namespace || seen.has(id)
      || !["owner", "trusted_agent", "delegated_agent", "external_agent"].includes(String(level))
      || typeof record.mayDelegate !== "boolean"
      || typeof record.mayAuthorizeSensitiveTools !== "boolean"
      || typeof record.mayReceiveUntrustedData !== "boolean") return defaultValue;
    seen.add(id);
    output.push({
      id,
      label,
      level: level as AgentIdentityLevel,
      tenant,
      namespace,
      mayDelegate: record.mayDelegate,
      mayAuthorizeSensitiveTools: record.mayAuthorizeSensitiveTools,
      mayReceiveUntrustedData: record.mayReceiveUntrustedData,
    });
  }
  return output.length ? output : defaultValue;
}

export const ConfigSchema = {
  parse(value: unknown): PluginConfig {
    return PluginConfig.fromPluginConfig(value);
  },
};
