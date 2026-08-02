import type { DetectionFinding } from "../detect.ts";
import type { RiskVector, TaintProfile, TaintSink, TrustLabel } from "../trust.ts";

export type Capability =
  | { kind: "fs.read"; roots: string[] }
  | { kind: "fs.write"; roots: string[] }
  | { kind: "network.fetch"; origins: string[] }
  | { kind: "email.send"; recipients?: string[] }
  | { kind: "memory.read"; namespace: string }
  | { kind: "memory.write"; namespace: string }
  | { kind: "execution.shell" };

export type AuthorizationNode = {
  id: string;
  kind: "task" | "capability" | "scope";
  value: string;
  capability_kind?: Capability["kind"];
};

export type AuthorizationEdge = {
  from: string;
  to: string;
  relation: "grants" | "scopes";
};

export type AuthorizationGraph = {
  root: string;
  nodes: AuthorizationNode[];
  edges: AuthorizationEdge[];
};

export type AgentSentryAction = {
  tool: string;
  originalTool: string;
  args: Record<string, unknown>;
  reason: string;
};

export type TaskSpec = {
  task: string;
  capabilities: Capability[];
  authorization_graph: AuthorizationGraph;
  allowed_tools: string[];
  forbidden_tools: string[];
  allowed_targets: string[];
  sensitive_assets: string[];
  output_policy: string;
};

export type Label = {
  source: string;
  integrity: "trusted" | "untrusted";
  confidentiality: "public" | "internal" | "secret";
  tainted: boolean;
  provenance_untrusted?: boolean;
  influence?: "none" | "matched" | "explicit";
  trust_label?: TrustLabel;
  risk_vector?: RiskVector;
  tags?: string[];
  taint_profile?: TaintProfile;
};

export type BehaviorProfile = {
  tool: string;
  taskClass: string;
  samples: Array<{
    observedAt: number;
    host: string;
    recipient: string;
    pathRoot: string;
    paramBytes: number;
    paramKeys: number;
  }>;
};

export type ProvenanceNode = {
  id: string;
  kind: "tool_result" | "tool_arg" | "sink";
  label_id?: string;
  source?: string;
  tool?: string;
  arg?: string;
};

export type ProvenanceEdge = {
  from: string;
  to: string;
  relation: "tainted" | "used_in" | "reaches";
};

export type ProvenanceGraph = {
  nodes: Map<string, ProvenanceNode>;
  edges: ProvenanceEdge[];
};

export type TaintFlow = {
  label_id: string;
  source: string;
  sink: TaintSink;
  blocked: boolean;
  confidence: number;
  reason: string;
  tags: string[];
  path: string[];
};

export type PolicyState = {
  currentTask: string;
  taskSpec: TaskSpec;
  contaminated: boolean;
  provenanceBlocked: boolean;
  provenanceFindings: DetectionFinding[];
  history: Array<{ tool: string; decision: "allow" | "ask" | "deny"; risk_score: number }>;
  toolResultLabels: Map<string, Label>;
  exposures: Array<{ source: string; text: string; label: Label; node_id: string }>;
  apiCallCounts: Map<string, number>;
  behaviorProfiles: Map<string, BehaviorProfile>;
  trustLabels: TrustLabel[];
  aggregateRisk: RiskVector;
  taintedSources: string[];
  taintFlows: TaintFlow[];
  provenanceGraph: ProvenanceGraph;
  nextActionId: number;
};

export type PolicySnapshot = Readonly<PolicyState>;

export type PolicyEffect =
  | { type: "history.append"; value: PolicyState["history"][number] }
  | { type: "api.increment"; host: string }
  | { type: "behavior.observe"; action: AgentSentryAction }
  | { type: "risk.merge"; value: RiskVector }
  | { type: "trust.remember"; label: TrustLabel }
  | { type: "state.contaminate" }
  | { type: "taint.flow"; flow: TaintFlow }
  | { type: "graph.node"; node: ProvenanceNode }
  | { type: "graph.edge"; edge: ProvenanceEdge }
  | { type: "tool_result.remember"; toolCallId: string; label: Label }
  | { type: "exposure.remember"; exposure: PolicyState["exposures"][number] }
  | { type: "action.advance" };

export type PolicyDecision = {
  decision: "allow" | "ask" | "deny";
  risk_score: number;
  reasons: string[];
  violations: string[];
  deterministic_block: boolean;
  deterministic_disposition: "allow" | "deny" | "ambiguous";
  sentry_score: number;
  risk_vector: RiskVector;
  trust_labels: TrustLabel[];
  action: AgentSentryAction;
  task_spec: TaskSpec;
  findings: DetectionFinding[];
  effects: PolicyEffect[];
};

export type PolicyEvaluation = {
  decision: PolicyDecision;
  effects: PolicyEffect[];
};

export type ActionClass = "read" | "write" | "external_sink" | "execution" | "memory" | "network" | "unknown";

export type ActionAssessment = {
  class: ActionClass;
  highRisk: boolean;
  externalSink: boolean;
  sensitive: boolean;
  persistence: boolean;
  systemMutation: boolean;
  dangerousCommand: boolean;
  reasons: string[];
};
