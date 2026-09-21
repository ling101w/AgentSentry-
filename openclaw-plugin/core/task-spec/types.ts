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
    maxCalls?: number;
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
  /**
   * (P0-1) Stable identity of this capability: (action, resourceType, effect,
   * clause-scoped bound argument tuple). Two capabilities with different
   * bindings must never merge; merging by bare (action, resource, effect)
   * turns "send A to Alice; send B to Bob" into {A,B} -> {Alice,Bob}.
   */
  capabilityId?: string;
  /**
   * (P0-1) Clause-local parameter binding extracted verbatim from the user's
   * request. Enforces that the arguments of an authorized call come from the
   * same clause that granted the capability.
   */
  bound?: {
    recipients?: string[];
    paths?: string[];
    urls?: string[];
    commands?: string[];
  };
  /** (P1) Per-capability usage accounting for approval-free reuse. */
  usage?: {
    calls: number;
    bytesWritten: number;
    expiresAfterTurn: number;
  };
  expiresAfterTurn: number;
}

/** Capability proposal that requires explicit user approval before use. */
export interface PendingCapabilityRequest {
  action: CapabilityAction;
  resourceType: CapabilityResource;
  effect: CapabilityEffect;
  targets: string[];
  reason: string;
  evidenceSpan: string;
  confidence: number;
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
  /** (P0-3) Keyword-inferred sensitive targets requiring user approval. */
  pending_capability_requests?: PendingCapabilityRequest[];
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
