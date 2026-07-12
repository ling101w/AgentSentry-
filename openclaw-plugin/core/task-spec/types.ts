export type CapabilityAction = "read" | "write" | "send" | "execute" | "request" | "persist";

export type CapabilityResource = "file" | "email" | "api" | "shell" | "memory" | "skill";

export type CapabilityEffect = "read_only" | "external_side_effect" | "persistent_change";

export type CapabilitySource = "user" | "memory" | "tool_result" | "system";

export interface TaskCapability {
  action: CapabilityAction;
  resourceType: CapabilityResource;
  targets: string[];
  effect: CapabilityEffect;
  constraints: {
    allowedMethods?: string[];
    allowedPaths?: string[];
    allowedHosts?: string[];
    allowedRecipients?: string[];
    maxBytes?: number;
  };
  evidence: {
    sourceMessageHash: string;
    source: CapabilitySource;
    explicitSpan: string;
    explicitAuthorization: boolean;
    insideQuotation: boolean;
    negated: boolean;
    targetIsConcrete: boolean;
    confidence: number;
  };
  expiresAfterTurn: number;
}

export interface TaskSpec {
  version: 2;
  task: string;
  capabilities: TaskCapability[];
  denied_tools: string[];
  allowed_tools: string[];
  forbidden_tools: string[];
  allowed_targets: string[];
  sensitive_assets: string[];
  output_policy: string;
}

export interface CapabilityActionRequest {
  tool: string;
  originalTool?: string;
  args: Record<string, unknown>;
}

export type CapabilityAuthorization = {
  action: "allow" | "ask" | "deny";
  authorized: boolean;
  reason: string;
  capability?: TaskCapability;
  expectedTarget?: string;
  actualTarget?: string;
};
