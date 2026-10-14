import type { SemanticGraph } from "../action-semantics.ts";
import type { DetectionFinding } from "../detect.ts";
import type { DynamicSecurityState } from "../dynamic-security.ts";
import type { PersistentMemoryLabel } from "../memory-ifc.ts";
import type { InterventionGateResult } from "./intervention-gate.ts";
import type { DataFlowTaintFlow } from "./abac.ts";
import type { BehaviorProfile } from "./behavior-baseline.ts";
import type { SemanticActionGraphState, SemanticProvenanceLink } from "../semantic-action-graph.ts";
import type { DataProvenance, SemanticClaim } from "../taint/provenance-graph.ts";
import type { AuthorizationState, TaskSpec } from "../task-spec/index.ts";
import type { ContentIndex } from "../taint/content-index.ts";
import type { RiskVector, TaintProfile, TrustLabel } from "../trust.ts";
export type AgentSentryAction = {
  tool: string;
  originalTool: string;
  args: Record<string, unknown>;
  reason: string;
};

export type { TaskSpec } from "../task-spec/index.ts";
export type Label = {
  source: string;
  integrity: "trusted" | "untrusted";
  confidentiality: "public" | "internal" | "secret";
  tainted: boolean;
  provenance_untrusted?: boolean;
  influence?: "none" | "matched" | "payload_default";
  trust_label?: TrustLabel;
  risk_vector?: RiskVector;
  tags?: string[];
  /** Opaque, session-local correlation values for the data subject. */
  subject_scopes?: string[];
  taint_profile?: TaintProfile;
  provenance_ids?: string[];
};

export type RuntimeFeedbackProfile = {
  tool: string;
  runtime_alerts: number;
  risk_score: number;
  last_seen: string;
  reasons: string[];
  events: string[];
};

export type IFCBranch = {
  id: string;
  source: string;
  status: "isolated" | "merged";
  integrity: "system-trusted" | "user-trusted" | "untrusted-external";
  confidentiality: "public" | "internal" | "user-private" | "tenant-secret";
  purpose: string;
  summary: string;
  lifetime: "turn" | "session" | "memory" | "expired";
  createdAt: string;
  provenanceIds: string[];
  subjectScopes?: string[];
  risk: number;
  confidence: number;
};

export type PolicyState = {
  sessionRevision: number;
  currentTask: string;
  taskSpec: TaskSpec;
  authorizationState: AuthorizationState;
  contaminated: boolean;
  provenanceBlocked: boolean;
  provenanceFindings: DetectionFinding[];
  history: Array<{
    tool: string;
    originalTool?: string;
    frequencyKey?: string;
    decision: "allow" | "ask" | "deny";
    risk_score: number;
  }>;
  toolResultLabels: Map<string, Label>;
  exposures: Array<{
    source: string;
    text: string;
    label: Label;
    provenanceId?: string;
    semanticClaims?: SemanticClaim[];
    contentIndex?: ContentIndex;
  }>;
  apiCallCounts: Map<string, number>;
  behaviorProfiles: Map<string, BehaviorProfile>;
  runtimeProfiles: Map<string, RuntimeFeedbackProfile>;
  trustLabels: TrustLabel[];
  aggregateRisk: RiskVector;
  taintedSources: string[];
  taintFlows: DataFlowTaintFlow[];
  dataProvenance: DataProvenance[];
  ifcBranches: IFCBranch[];
  persistentMemoryLabels: PersistentMemoryLabel[];
  semanticActionGraph: SemanticActionGraphState;
  dynamicSecurity: DynamicSecurityState;
};

export type PolicyDecision = {
  decision: "allow" | "ask" | "deny";
  risk_score: number;
  reasons: string[];
  violations: string[];
  deterministic_block: boolean;
  sentry_score: number;
  risk_vector: RiskVector;
  trust_labels: TrustLabel[];
  action: AgentSentryAction;
  task_spec: TaskSpec;
  findings: DetectionFinding[];
  action_graph_node_id: string;
  deterministic_disposition: "allow" | "deny" | "ambiguous";
  intervention?: InterventionGateResult;
  effects?: PolicyEffects;
};

export type PolicyEffects = {
  baseRevision: number;
  semanticActionGraph: SemanticActionGraphState;
  apiCallCounts: Map<string, number>;
  dataProvenance: DataProvenance[];
  taintFlows: PolicyState["taintFlows"];
};

export type PolicyEvaluation = { decision: PolicyDecision; effects: PolicyEffects };
export type PolicyStateCheckpoint = {
  version: 1;
  created_at: string;
  currentTask: string;
  taskSpec: TaskSpec;
  authorizationState: AuthorizationState;
  contaminated: boolean;
  provenanceBlocked: boolean;
  provenanceFindings: DetectionFinding[];
  history: PolicyState["history"];
  toolResultLabels: Array<[string, Label]>;
  exposures: PolicyState["exposures"];
  apiCallCounts: Array<[string, number]>;
  behaviorProfiles: Array<[string, BehaviorProfile]>;
  runtimeProfiles: Array<[string, RuntimeFeedbackProfile]>;
  trustLabels: TrustLabel[];
  aggregateRisk: RiskVector;
  taintedSources: string[];
  taintFlows: PolicyState["taintFlows"];
  dataProvenance: DataProvenance[];
  ifcBranches: IFCBranch[];
  persistentMemoryLabels: PersistentMemoryLabel[];
  semanticActionGraph: SemanticActionGraphState;
  dynamicSecurity: DynamicSecurityState;
};

export type PolicyDecisionContext = {
  toolCallId?: string;
  workspaceDir?: string;
  semanticGraph?: SemanticGraph;
  provenanceLinks?: SemanticProvenanceLink[];
  provenanceAdditions?: DataProvenance[];
  onPerformance?: (stage: "semantic_action_graph", durationMs: number) => void;
};
