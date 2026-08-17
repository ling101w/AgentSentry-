export type CapabilityAction = "read" | "write" | "send" | "execute" | "request" | "persist";

export type CapabilityResource = "file" | "email" | "api" | "shell" | "memory" | "skill" | "calendar" | "cloud_file";

export type CapabilityEffect = "read_only" | "external_side_effect" | "persistent_change";

export type CapabilitySource = "user" | "memory" | "tool_result" | "delegated_tool_result" | "system";

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
    allowedOperations?: string[];
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
    delegationVerified?: boolean;
    delegation?: {
      sourceType: "email";
      sender: string;
      subject: string;
    };
  };
  expiresAfterTurn: number;
}

export interface TaskSpec {
  version: 2;
  task: string;
  task_mode?: "new_task" | "task_continuation" | "preference" | "confirmation" | "data_only" | "chatter";
  task_family?: "analysis" | "read_only" | "write_task" | "delivery" | "memory" | "shell" | "mixed" | "unknown";
  task_confidence?: number;
  capabilities: TaskCapability[];
  denied_tools: string[];
  allowed_tools: string[];
  forbidden_tools: string[];
  allowed_targets: string[];
  sensitive_assets: string[];
  output_policy: string;
  delegations?: Array<{
    sourceType: "email";
    sender: string;
    subject: string;
  }>;
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
