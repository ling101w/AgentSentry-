import { createHash } from "node:crypto";
import type { SemanticGraph } from "./action-semantics.ts";
import type { DataProvenance } from "./taint/provenance-graph.ts";
import type { CapabilityAuthorization, TaskCapability, TaskSpec } from "./task-spec/index.ts";
import type { TaintSink } from "./trust.ts";

export type SemanticActionNodeKind = "intent" | "capability" | "action" | "data" | "sink";

export type SemanticActionStatus =
  | "proposed"
  | "awaiting_approval"
  | "blocked"
  | "executing"
  | "succeeded"
  | "failed"
  | "observed";

export type SemanticActionEdgeKind =
  | "declares"
  | "governs"
  | "authorizes"
  | "constrains"
  | "requests"
  | "consumes"
  | "produces"
  | "derives"
  | "targets";

export type SemanticEvidenceBasis = "observed" | "decoded" | "conservative";

export type SemanticActionSinkEffect = "external" | "persistent" | "execution" | "sensitive_read" | "write" | "unknown";

export interface SemanticActionNode {
  id: string;
  kind: SemanticActionNodeKind;
  sequence: number;
  label: string;
  fingerprint?: string;
  capabilityKey?: string;
  callIdHash?: string;
  tool?: string;
  originalTool?: string;
  decision?: "allow" | "ask" | "deny";
  status?: SemanticActionStatus;
  authorized?: boolean;
  authorizationReason?: string;
  sink?: string;
  effect?: SemanticActionSinkEffect;
  provenanceId?: string;
  source?: string;
  path?: string;
  confidentiality?: DataProvenance["confidentiality"];
  integrity?: DataProvenance["integrity"];
  transformations?: string[];
  synthetic?: boolean;
}

export interface SemanticActionEdge {
  id: string;
  from: string;
  to: string;
  kind: SemanticActionEdgeKind;
  sequence: number;
  basis: SemanticEvidenceBasis;
  confidence: number;
  argPath?: string;
  match?: string;
}

export interface SemanticAttackPath {
  id: string;
  risk:
    | "secret_to_external_sink"
    | "tainted_to_external_sink"
    | "secret_to_persistent_state"
    | "tainted_to_persistent_state"
    | "secret_to_execution"
    | "tainted_to_execution"
    | "unauthorized_side_effect"
    | "target_scope_mismatch";
  verdict: "block" | "review";
  reason: string;
  certainty: "observed" | "conservative";
  confidence: number;
  sourceNodeId: string;
  actionNodeId: string;
  sinkNodeId: string;
  nodeIds: string[];
  edgeIds: string[];
  steps: string[];
  sequence: number;
}

export interface SemanticActionGraphLimits {
  maxNodes: number;
  maxEdges: number;
  maxPaths: number;
}

export interface SemanticActionGraphState {
  version: 2;
  nextSequence: number;
  activeIntentId: string | null;
  activeCapabilityIds: string[];
  nodes: SemanticActionNode[];
  edges: SemanticActionEdge[];
  paths: SemanticAttackPath[];
  limits: SemanticActionGraphLimits;
  pendingCalls: Map<string, string[]>;
  settledCalls: Map<string, string>;
  lifecycleAnomalies: Array<{
    actionNodeId: string;
    from: SemanticActionStatus;
    to: SemanticActionStatus;
    sequence: number;
  }>;
}

export interface SemanticActionEffects {
  external: boolean;
  persistence: boolean;
  execution: boolean;
  sensitive: boolean;
  sideEffect?: boolean;
}

export interface SemanticProvenanceLink {
  provenanceId: string;
  argPath?: string;
  match?: string;
  basis?: SemanticEvidenceBasis;
  confidence?: number;
}

export interface SemanticGraphViolation {
  reason: string;
  path: SemanticAttackPath;
}

export interface SemanticActionAttempt {
  actionNodeId: string;
  violations: SemanticGraphViolation[];
}

const DEFAULT_LIMITS: SemanticActionGraphLimits = {
  maxNodes: 320,
  maxEdges: 640,
  maxPaths: 64,
};

const DEFAULT_JUDGE_PROJECTION_BYTES = 2400;

const TARGET_SCOPE_MISMATCH_REASONS = new Set([
  "recipient_outside_authorization",
  "attachment_outside_authorization",
  "path_outside_authorization",
  "target_outside_authorization",
  "host_outside_authorization",
  "method_outside_authorization",
  "command_outside_authorization",
  "capability_constraints_not_satisfied",
]);

export function createSemanticActionGraph(
  limits: Partial<SemanticActionGraphLimits> = {},
): SemanticActionGraphState {
  return {
    version: 2,
    nextSequence: 1,
    activeIntentId: null,
    activeCapabilityIds: [],
    nodes: [],
    edges: [],
    paths: [],
    limits: {
      maxNodes: boundedLimit(limits.maxNodes, DEFAULT_LIMITS.maxNodes, 8),
      maxEdges: boundedLimit(limits.maxEdges, DEFAULT_LIMITS.maxEdges, 16),
      maxPaths: boundedLimit(limits.maxPaths, DEFAULT_LIMITS.maxPaths, 4),
    },
    pendingCalls: new Map(),
    settledCalls: new Map(),
    lifecycleAnomalies: [],
  };
}

export function activateSemanticIntent(graph: SemanticActionGraphState, taskSpec: TaskSpec): string {
  retireSupersededLegacyProposals(graph);
  const sequence = nextSequence(graph);
  const fingerprint = sha256(taskSpec.task || "<empty-task>");
  const intent = addNode(graph, {
    id: nodeId("intent", `${fingerprint}:${sequence}`),
    kind: "intent",
    sequence,
    label: taskSpec.task.trim() ? "user_task" : "empty_task",
    fingerprint,
  });
  graph.activeIntentId = intent.id;
  graph.activeCapabilityIds = [];

  for (const capability of taskSpec.capabilities) {
    const capabilityKey = keyForCapability(capability);
    const node = addNode(graph, {
      id: nodeId("cap", `${intent.id}:${capabilityKey}`),
      kind: "capability",
      sequence: nextSequence(graph),
      label: `${capability.action}:${capability.resourceType}:${capability.effect}`,
      capabilityKey,
      source: capability.evidence.source,
      authorized: authoritativeCapability(capability),
      authorizationReason: authoritativeCapability(capability)
        ? "explicit_user_capability"
        : "non_authoritative_capability",
    });
    graph.activeCapabilityIds.push(node.id);
    addEdge(graph, intent.id, node.id, "declares");
  }

  trimGraph(graph);
  return intent.id;
}

function retireSupersededLegacyProposals(graph: SemanticActionGraphState): void {
  const explicitCallActionIds = new Set(
    [...graph.pendingCalls]
      .filter(([key]) => key.startsWith("id:"))
      .flatMap(([, ids]) => ids),
  );
  const legacyActionIds = new Set(
    [...graph.pendingCalls]
      .filter(([key]) => key.startsWith("tool:"))
      .flatMap(([, ids]) => ids),
  );
  for (const actionNodeId of legacyActionIds) {
    if (explicitCallActionIds.has(actionNodeId)) continue;
    const action = graph.nodes.find((node) => node.id === actionNodeId && node.kind === "action");
    if (!action || action.status !== "proposed") continue;
    transitionSemanticActionStatus(graph, action, "failed");
    unregisterAction(graph, actionNodeId);
  }
}

export function beginSemanticAction(
  graph: SemanticActionGraphState,
  input: {
    toolCallId?: string;
    tool: string;
    originalTool: string;
    authorization: CapabilityAuthorization;
    sink: TaintSink | null;
    effects: SemanticActionEffects;
    semantic?: SemanticGraph;
    provenance: DataProvenance[];
    consumes?: SemanticProvenanceLink[];
  },
): SemanticActionAttempt {
  assertPendingCallAvailable(graph, input.toolCallId, input.tool, input.originalTool);
  const sequence = nextSequence(graph);
  const callIdHash = sha256(input.toolCallId?.trim() || `${input.tool}:${sequence}`).slice(0, 24);
  const action = addNode(graph, {
    id: nodeId("action", `${callIdHash}:${sequence}`),
    kind: "action",
    sequence,
    label: safeLabel(input.tool || "unknown_tool"),
    callIdHash,
    tool: safeLabel(input.tool || "unknown_tool"),
    originalTool: safeLabel(input.originalTool || input.tool || "unknown_tool"),
    status: "proposed",
    authorized: input.authorization.authorized,
    authorizationReason: safeLabel(input.authorization.reason || "unknown_authorization"),
  });

  registerPendingCall(graph, input.toolCallId, input.tool, input.originalTool, action.id);
  const authorizationSourceNodeId = connectIntentAndCapability(graph, action.id, input.authorization);

  const provenanceById = new Map(input.provenance.map((item) => [item.id, item]));
  const consumed = uniqueLinks(input.consumes || []);
  for (const link of consumed) {
    const dataNode = upsertProvenanceClosure(graph, link.provenanceId, provenanceById, new Set());
    if (!dataNode) continue;
    addEdge(graph, dataNode.id, action.id, "consumes", {
      argPath: safePath(link.argPath),
      match: safeLabel(link.match),
      basis: link.basis || evidenceBasisForMatch(link.match),
      confidence: link.confidence ?? evidenceConfidenceForMatch(link.match),
    });
  }

  addSemanticReferenceNodes(graph, action.id, input.semantic);
  const authorizationRisk = authorizationRiskFor(
    input.authorization,
    input.tool,
    input.effects,
  );
  const sink = effectiveSink(input.sink, input.effects, input.semantic)
    || (authorizationRisk ? authorizationBoundarySink(authorizationRisk, input.tool, input.effects) : null);
  let sinkNode: SemanticActionNode | null = null;
  if (sink) {
    sinkNode = addNode(graph, {
      id: nodeId("sink", `${action.id}:${sink.name}`),
      kind: "sink",
      sequence: nextSequence(graph),
      label: safeLabel(sink.name),
      sink: safeLabel(sink.name),
      effect: sink.effect,
      synthetic: sink.basis === "conservative",
    });
    addEdge(graph, action.id, sinkNode.id, "targets", {
      basis: sink.basis,
      confidence: sink.confidence,
    });
  }

  const dataPaths = sinkNode ? detectAttackPaths(graph, action.id, sinkNode) : [];
  const authorizationPath = sinkNode && authorizationRisk
    ? authorizationViolationPath(
      graph,
      authorizationSourceNodeId || action.id,
      action.id,
      sinkNode,
      authorizationRisk,
      input.authorization,
    )
    : null;
  const paths = [...(authorizationPath ? [authorizationPath] : []), ...dataPaths];
  for (const path of paths) rememberPath(graph, path);
  trimGraph(graph);
  return {
    actionNodeId: action.id,
    violations: paths.map((path) => ({ reason: path.reason, path })),
  };
}

export function setSemanticActionDecision(
  graph: SemanticActionGraphState,
  actionNodeId: string,
  decision: "allow" | "ask" | "deny",
): void {
  const node = graph.nodes.find((item) => item.id === actionNodeId && item.kind === "action");
  if (node) node.decision = decision;
}

export function markSemanticActionEnforcement(
  graph: SemanticActionGraphState,
  actionNodeId: string,
  input: {
    decision: "allow" | "ask" | "deny";
    status: Extract<SemanticActionStatus, "awaiting_approval" | "blocked" | "executing">;
  },
): void {
  const node = graph.nodes.find((item) => item.id === actionNodeId && item.kind === "action");
  if (!node) return;
  if (!transitionSemanticActionStatus(graph, node, input.status)) return;
  node.decision = input.decision;
  if (input.status === "blocked") unregisterAction(graph, actionNodeId, true);
}

export function semanticActionResultContext(
  graph: SemanticActionGraphState,
  input: { toolCallId?: string; tool: string },
): { actionNodeId: string; consumedProvenanceIds: string[] } | null {
  const actionNodeId = pendingActionId(graph, input.toolCallId, input.tool)
    || settledActionId(graph, input.toolCallId);
  if (!actionNodeId) return null;
  const consumedProvenanceIds = graph.edges
    .filter((edge) => edge.to === actionNodeId && edge.kind === "consumes")
    .map((edge) => graph.nodes.find((node) => node.id === edge.from)?.provenanceId || "")
    .filter(Boolean);
  return { actionNodeId, consumedProvenanceIds: Array.from(new Set(consumedProvenanceIds)) };
}

export function completeSemanticAction(
  graph: SemanticActionGraphState,
  input: {
    toolCallId?: string;
    tool: string;
    status: "succeeded" | "failed";
    produced?: DataProvenance[];
    provenance?: DataProvenance[];
  },
): string {
  let actionNodeId = pendingActionId(graph, input.toolCallId, input.tool);
  const settledActionNodeId = settledActionId(graph, input.toolCallId);
  if (!actionNodeId && settledActionNodeId) {
    const settled = graph.nodes.find((node) => node.id === settledActionNodeId);
    const blockedExecutionObserved = settled?.status === "blocked" && input.status === "succeeded";
    if (settled) transitionSemanticActionStatus(graph, settled, input.status);
    if (!blockedExecutionObserved) return settledActionNodeId;

    const observed = createObservedSemanticAction(graph, input.toolCallId, input.tool, "post_block_execution");
    for (const edge of graph.edges.filter((candidate) =>
      candidate.to === settledActionNodeId && candidate.kind === "consumes"
    )) {
      addEdge(graph, edge.from, observed.id, "consumes", {
        argPath: edge.argPath,
        match: edge.match,
        basis: edge.basis,
        confidence: edge.confidence,
      });
    }
    for (const edge of graph.edges.filter((candidate) =>
      candidate.from === settledActionNodeId && candidate.kind === "targets"
    )) {
      addEdge(graph, observed.id, edge.to, "targets", {
        basis: edge.basis,
        confidence: edge.confidence,
      });
    }
    attachProducedProvenance(graph, observed.id, input);
    const settledKey = input.toolCallId?.trim();
    if (settledKey) rememberSettledCall(graph, `id:${settledKey}`, observed.id);
    trimGraph(graph);
    return observed.id;
  }
  let syntheticAction = false;
  if (!actionNodeId) {
    const synthetic = createObservedSemanticAction(graph, input.toolCallId, input.tool, "result_without_before_hook");
    actionNodeId = synthetic.id;
    syntheticAction = true;
  }

  const action = graph.nodes.find((item) => item.id === actionNodeId);
  const acceptedStatus = syntheticAction || !action || transitionSemanticActionStatus(graph, action, input.status);
  if (!acceptedStatus) return actionNodeId;
  if (input.status === "succeeded") attachProducedProvenance(graph, actionNodeId, input);
  unregisterAction(graph, actionNodeId, true);
  trimGraph(graph);
  return actionNodeId;
}

function createObservedSemanticAction(
  graph: SemanticActionGraphState,
  toolCallId: string | undefined,
  tool: string,
  reason: string,
): SemanticActionNode {
  const sequence = nextSequence(graph);
  const callIdHash = sha256(toolCallId?.trim() || `${tool}:${sequence}`).slice(0, 24);
  const synthetic = addNode(graph, {
    id: nodeId("action", `observed:${reason}:${callIdHash}:${sequence}`),
    kind: "action",
    sequence,
    label: safeLabel(tool || "unknown_tool"),
    callIdHash,
    tool: safeLabel(tool || "unknown_tool"),
    originalTool: safeLabel(tool || "unknown_tool"),
    status: "observed",
    authorizationReason: reason,
    synthetic: true,
  });
  if (graph.activeIntentId) addEdge(graph, graph.activeIntentId, synthetic.id, "governs");
  return synthetic;
}

function attachProducedProvenance(
  graph: SemanticActionGraphState,
  actionNodeId: string,
  input: {
    produced?: DataProvenance[];
    provenance?: DataProvenance[];
  },
): void {
  const all = input.provenance || input.produced || [];
  const provenanceById = new Map(all.map((item) => [item.id, item]));
  const consumedNodeIds = new Set(
    graph.edges
      .filter((edge) => edge.to === actionNodeId && edge.kind === "consumes")
      .map((edge) => edge.from),
  );
  const consumedProvenanceIds = new Set(
    [...consumedNodeIds]
      .map((id) => graph.nodes.find((node) => node.id === id)?.provenanceId || "")
      .filter(Boolean),
  );
  for (const item of input.produced || []) {
    const dataNode = upsertProvenanceClosure(graph, item.id, provenanceById, new Set());
    if (!dataNode) continue;
    graph.edges = graph.edges.filter((edge) =>
      !(edge.kind === "derives" && edge.to === dataNode.id && consumedNodeIds.has(edge.from))
    );
    const inheritedThroughOpaqueTool = item.parentIds.some((id) => consumedProvenanceIds.has(id));
    addEdge(graph, actionNodeId, dataNode.id, "produces", inheritedThroughOpaqueTool
      ? { basis: "conservative", confidence: consumedProvenanceIds.size === 1 ? 0.75 : 0.6 }
      : { basis: "observed", confidence: 1 });
  }
}

export function semanticActionGraphSnapshot(graph: SemanticActionGraphState): Record<string, unknown> {
  const maxNodes = 36;
  const maxEdges = 40;
  const maxPaths = 6;
  const referencedNodeIds = new Set<string>();
  const referencedEdgeIds = new Set<string>();
  const selectedPaths: SemanticAttackPath[] = [];
  const addNode = (id: string | null): void => {
    if (!id || referencedNodeIds.size >= maxNodes) return;
    if (graph.nodes.some((node) => node.id === id)) referencedNodeIds.add(id);
  };
  addNode(graph.activeIntentId);
  graph.activeCapabilityIds.slice(-8).forEach(addNode);
  Array.from(new Set([...graph.pendingCalls.values()].flat())).slice(-8).forEach(addNode);
  for (const path of [...graph.paths].reverse()) {
    if (selectedPaths.length >= maxPaths) break;
    const nextNodes = path.nodeIds.filter((id) => !referencedNodeIds.has(id));
    const nextEdges = path.edgeIds.filter((id) => !referencedEdgeIds.has(id));
    if (referencedNodeIds.size + nextNodes.length > maxNodes) continue;
    if (referencedEdgeIds.size + nextEdges.length > maxEdges) continue;
    selectedPaths.push(path);
    nextNodes.forEach((id) => referencedNodeIds.add(id));
    nextEdges.forEach((id) => referencedEdgeIds.add(id));
  }
  selectedPaths.reverse();

  for (const node of [...graph.nodes].reverse()) addNode(node.id);

  const nodes = graph.nodes.filter((node) => referencedNodeIds.has(node.id));
  const nodeIds = new Set(nodes.map((node) => node.id));
  const pathEdges = graph.edges.filter((edge) => referencedEdgeIds.has(edge.id));
  const supportingBudget = Math.max(0, maxEdges - pathEdges.length);
  const supportingCandidates = graph.edges
    .filter((edge) => !referencedEdgeIds.has(edge.id) && nodeIds.has(edge.from) && nodeIds.has(edge.to));
  const authorizationNodeIds = new Set([
    ...(graph.activeIntentId ? [graph.activeIntentId] : []),
    ...graph.activeCapabilityIds,
    ...[...graph.pendingCalls.values()].flat(),
  ]);
  const authorizationKinds = new Set<SemanticActionEdgeKind>(["declares", "governs", "authorizes", "constrains", "requests"]);
  const authorizationCandidates = supportingCandidates
    .filter((edge) => authorizationKinds.has(edge.kind) && (authorizationNodeIds.has(edge.from) || authorizationNodeIds.has(edge.to)));
  const authorizationEdges = supportingBudget > 0 ? authorizationCandidates.slice(-supportingBudget) : [];
  const authorizationEdgeIds = new Set(authorizationEdges.map((edge) => edge.id));
  const recentSupportingBudget = Math.max(0, supportingBudget - authorizationEdges.length);
  const recentSupportingCandidates = supportingCandidates.filter((edge) => !authorizationEdgeIds.has(edge.id));
  const recentSupportingEdges = recentSupportingBudget > 0
    ? recentSupportingCandidates.slice(-recentSupportingBudget)
    : [];
  const supportingEdges = [...authorizationEdges, ...recentSupportingEdges];
  const edges = [...pathEdges, ...supportingEdges]
    .sort((left, right) => left.sequence - right.sequence)
    .slice(-maxEdges);
  const edgeIds = new Set(edges.map((edge) => edge.id));
  const recentPaths = selectedPaths.filter((path) =>
    path.nodeIds.every((id) => nodeIds.has(id)) && path.edgeIds.every((id) => edgeIds.has(id))
  );
  const snapshot: Record<string, unknown> = {
    version: graph.version,
    node_count: graph.nodes.length,
    edge_count: graph.edges.length,
    path_count: graph.paths.length,
    snapshot_truncated: graph.nodes.length > nodes.length || graph.edges.length > edges.length || graph.paths.length > recentPaths.length,
    active_intent_id: graph.activeIntentId && nodeIds.has(graph.activeIntentId) ? graph.activeIntentId : null,
    nodes: nodes.map(publicNode),
    edges: edges.map(publicEdge),
    attack_paths: recentPaths.map(publicAttackPath),
    lifecycle_anomalies: graph.lifecycleAnomalies.slice(-8).map((item) => ({ ...item })),
  };
  const maxSerializedBytes = 64 * 1024;
  const attackPaths = snapshot.attack_paths as Array<Record<string, unknown>>;
  while (attackPaths.length > 1 && snapshotBytes(snapshot) > maxSerializedBytes) {
    attackPaths.shift();
    snapshot.snapshot_truncated = true;
  }
  if (snapshotBytes(snapshot) > maxSerializedBytes) {
    snapshot.attack_paths = [];
    snapshot.snapshot_truncated = true;
  }
  if (snapshotBytes(snapshot) > maxSerializedBytes) {
    return {
      version: graph.version,
      node_count: graph.nodes.length,
      edge_count: graph.edges.length,
      path_count: graph.paths.length,
      snapshot_truncated: true,
      active_intent_id: null,
      nodes: [],
      edges: [],
      attack_paths: [],
      lifecycle_anomalies: [],
    };
  }
  return snapshot;
}

export function semanticActionGraphJudgeProjection(
  graph: SemanticActionGraphState,
  maxSerializedBytes = DEFAULT_JUDGE_PROJECTION_BYTES,
): Record<string, unknown> {
  const byteLimit = boundedLimit(maxSerializedBytes, DEFAULT_JUDGE_PROJECTION_BYTES, 512);
  const variants = [
    judgeProjection(graph, { maxPaths: 2, maxPathNodes: 10, maxCapabilities: 4, maxActions: 3, maxAnomalies: 3 }),
    judgeProjection(graph, { maxPaths: 1, maxPathNodes: 8, maxCapabilities: 3, maxActions: 2, maxAnomalies: 2 }),
    judgeProjection(graph, { maxPaths: 1, maxPathNodes: 6, maxCapabilities: 1, maxActions: 1, maxAnomalies: 1 }),
  ];
  for (const projection of variants) {
    if (snapshotBytes(projection) <= byteLimit) return projection;
  }

  const latestPath = [...graph.paths].sort((left, right) => right.sequence - left.sequence)[0];
  const latestAction = [...graph.nodes].reverse().find((node) => node.kind === "action");
  const minimal: Record<string, unknown> = {
    version: graph.version,
    graph_counts: judgeGraphCounts(graph),
    projection_truncated: true,
    latest_action: latestAction ? judgeNode(latestAction, 48) : null,
    latest_path: latestPath ? {
      risk: snapshotText(latestPath.risk, 64),
      verdict: latestPath.verdict,
      certainty: latestPath.certainty,
      confidence: latestPath.confidence,
      source: snapshotText(latestPath.steps[0] || "unknown", 72),
      sink: snapshotText(latestPath.steps.at(-1) || "unknown", 72),
    } : null,
    lifecycle_anomaly_count: graph.lifecycleAnomalies.length,
  };
  if (snapshotBytes(minimal) <= byteLimit) return minimal;
  return {
    version: graph.version,
    graph_counts: judgeGraphCounts(graph),
    projection_truncated: true,
  };
}

export function findSemanticActionPath(
  graph: SemanticActionGraphState,
  from: string,
  to: string,
): { nodeIds: string[]; edgeIds: string[] } | null {
  return directedPath(graph, from, to);
}

export function validateSemanticActionGraph(graph: SemanticActionGraphState): void {
  const nodeIds = new Set<string>();
  for (const node of graph.nodes) {
    if (nodeIds.has(node.id)) throw new Error(`duplicate semantic action node ${node.id}`);
    nodeIds.add(node.id);
  }
  const edgeIds = new Set<string>();
  for (const edge of graph.edges) {
    if (edgeIds.has(edge.id)) throw new Error(`duplicate semantic action edge ${edge.id}`);
    edgeIds.add(edge.id);
    if (!nodeIds.has(edge.from) || !nodeIds.has(edge.to)) {
      throw new Error(`dangling semantic action edge ${edge.id}`);
    }
    if (edge.from === edge.to) throw new Error(`self-referencing semantic action edge ${edge.id}`);
    if (!["observed", "decoded", "conservative"].includes(edge.basis) || edge.confidence < 0 || edge.confidence > 1) {
      throw new Error(`invalid semantic action edge evidence ${edge.id}`);
    }
  }
  if (containsCycle(graph)) throw new Error("semantic action graph contains a directed cycle");
  for (const path of graph.paths) {
    if (path.nodeIds.some((id) => !nodeIds.has(id)) || path.edgeIds.some((id) => !edgeIds.has(id))) {
      throw new Error(`dangling semantic attack path ${path.id}`);
    }
  }
}

function connectIntentAndCapability(
  graph: SemanticActionGraphState,
  actionNodeId: string,
  authorization: CapabilityAuthorization,
): string | null {
  if (graph.activeIntentId) addEdge(graph, graph.activeIntentId, actionNodeId, "governs");
  const capabilityKey = authorization.capability ? keyForCapability(authorization.capability) : "";
  const capabilityNode = graph.activeCapabilityIds
    .map((id) => graph.nodes.find((node) => node.id === id))
    .find((node) => node?.capabilityKey === capabilityKey);
  if (authorization.authorized && capabilityNode) {
    addEdge(graph, capabilityNode.id, actionNodeId, "authorizes");
    return capabilityNode.id;
  }
  if (capabilityNode) addEdge(graph, capabilityNode.id, actionNodeId, "constrains");
  if (graph.activeIntentId) addEdge(graph, graph.activeIntentId, actionNodeId, "requests");
  return capabilityNode?.id || graph.activeIntentId;
}

function addSemanticReferenceNodes(
  graph: SemanticActionGraphState,
  actionNodeId: string,
  semantic?: SemanticGraph,
): void {
  if (!semantic) return;
  for (const [index, source] of semantic.sensitiveSources.slice(0, 6).entries()) {
    const path = factPath(source);
    const node = addNode(graph, {
      id: nodeId("data", `${actionNodeId}:semantic:${index}:${source}`),
      kind: "data",
      sequence: nextSequence(graph),
      label: "sensitive_reference",
      provenanceId: `semantic_${sha256(`${actionNodeId}:${source}`).slice(0, 24)}`,
      source: "tool_args",
      path,
      confidentiality: "secret",
      integrity: "untrusted",
      transformations: semantic.encodings.length ? ["decoded_semantic_reference"] : [],
      synthetic: true,
    });
    addEdge(graph, node.id, actionNodeId, "consumes", {
      argPath: path,
      match: semantic.encodings.length ? "decoded" : "semantic",
      basis: "conservative",
      confidence: semantic.encodings.length ? 0.82 : 0.72,
    });
  }
}

function effectiveSink(
  sink: TaintSink | null,
  effects: SemanticActionEffects,
  semantic?: SemanticGraph,
): {
  name: string;
  effect: SemanticActionSinkEffect;
  basis: SemanticEvidenceBasis;
  confidence: number;
} | null {
  if (sink) return { name: sink, effect: sinkEffect(sink, effects), basis: "observed", confidence: 1 };
  if (effects.external) {
    return { name: "external_network", effect: "external", basis: "observed", confidence: 1 };
  }
  if (semantic?.externalSinks.length && semantic.networkWrites.length) {
    return { name: "external_network", effect: "external", basis: "conservative", confidence: 0.72 };
  }
  if (effects.persistence) {
    return { name: "persistent_state", effect: "persistent", basis: "observed", confidence: 1 };
  }
  if (semantic?.persistenceTargets.length) {
    return { name: "persistent_state", effect: "persistent", basis: "conservative", confidence: 0.72 };
  }
  if (effects.execution) {
    return { name: "process_execution", effect: "execution", basis: "observed", confidence: 1 };
  }
  if (semantic?.privilegedEffects.length) {
    return { name: "process_execution", effect: "execution", basis: "conservative", confidence: 0.72 };
  }
  return null;
}

function authorizationRiskFor(
  authorization: CapabilityAuthorization,
  tool: string,
  effects: SemanticActionEffects,
): Extract<SemanticAttackPath["risk"], "unauthorized_side_effect" | "target_scope_mismatch"> | null {
  if (authorization.authorized) return null;
  if (authorization.capability && TARGET_SCOPE_MISMATCH_REASONS.has(authorization.reason)) {
    return "target_scope_mismatch";
  }
  const sideEffect = effects.sideEffect ?? defaultSideEffectForTool(tool, effects);
  return sideEffect ? "unauthorized_side_effect" : null;
}

function defaultSideEffectForTool(tool: string, effects: SemanticActionEffects): boolean {
  if (["write_file", "send_email", "shell_exec", "memory_write"].includes(tool)) return true;
  return tool === "call_api" && (effects.external || effects.persistence || effects.execution);
}

function authorizationBoundarySink(
  risk: Extract<SemanticAttackPath["risk"], "unauthorized_side_effect" | "target_scope_mismatch">,
  tool: string,
  effects: SemanticActionEffects,
): {
  name: string;
  effect: SemanticActionSinkEffect;
  basis: SemanticEvidenceBasis;
  confidence: number;
} {
  let effect: SemanticActionSinkEffect = "unknown";
  if (effects.external) effect = "external";
  else if (effects.persistence) effect = "persistent";
  else if (effects.execution || tool === "shell_exec") effect = "execution";
  else if (tool === "write_file") effect = "write";
  return {
    name: risk === "target_scope_mismatch" ? "authorization_scope" : "side_effect_boundary",
    effect,
    basis: "observed",
    confidence: 1,
  };
}

function authorizationViolationPath(
  graph: SemanticActionGraphState,
  sourceNodeId: string,
  actionNodeId: string,
  sinkNode: SemanticActionNode,
  risk: Extract<SemanticAttackPath["risk"], "unauthorized_side_effect" | "target_scope_mismatch">,
  authorization: CapabilityAuthorization,
): SemanticAttackPath | null {
  const path = directedPath(graph, sourceNodeId, sinkNode.id);
  if (!path) return null;
  const pathEdges = path.edgeIds
    .map((id) => graph.edges.find((edge) => edge.id === id))
    .filter((edge): edge is SemanticActionEdge => Boolean(edge));
  const confidence = pathEdges.length
    ? Math.min(...pathEdges.map((edge) => edge.confidence))
    : 1;
  const certainty = pathEdges.every((edge) => edge.basis !== "conservative")
    ? "observed"
    : "conservative";
  const sequence = nextSequence(graph);
  return {
    id: `sag_path_${sha256(`${risk}:${sourceNodeId}:${actionNodeId}:${sinkNode.id}`).slice(0, 24)}`,
    risk,
    verdict: authorization.action === "deny" ? "block" : "review",
    reason: reasonForRisk(risk, certainty),
    certainty,
    confidence,
    sourceNodeId,
    actionNodeId,
    sinkNodeId: sinkNode.id,
    nodeIds: path.nodeIds,
    edgeIds: path.edgeIds,
    steps: path.nodeIds.map((id) => graph.nodes.find((node) => node.id === id)).filter(Boolean).map(pathStep),
    sequence,
  };
}

function sinkEffect(sink: TaintSink, effects: SemanticActionEffects): SemanticActionSinkEffect {
  if (sink === "send_email" || sink === "call_api" || effects.external) return "external";
  if (sink === "memory_write" || sink === "config_write" || sink === "skill_install" || effects.persistence) return "persistent";
  if (sink === "shell_exec" || effects.execution) return "execution";
  if (sink === "sensitive_read") return "sensitive_read";
  if (sink === "write_file") return "write";
  return "unknown";
}

function detectAttackPaths(
  graph: SemanticActionGraphState,
  actionNodeId: string,
  sinkNode: SemanticActionNode,
): SemanticAttackPath[] {
  const reachable = reverseReachableNodeIds(graph, sinkNode.id);
  const riskyNodes = graph.nodes.filter((node) => reachable.has(node.id) && isRiskyDataNode(node));
  const roots = riskyNodes.filter((node) => !hasRiskyLineageParent(graph, node));
  const candidates = (roots.length ? roots : riskyNodes)
    .map((source) => ({ source, path: directedPath(graph, source.id, sinkNode.id) }))
    .filter((item): item is { source: SemanticActionNode; path: { nodeIds: string[]; edgeIds: string[] } } =>
      Boolean(item.path?.nodeIds.includes(actionNodeId))
    )
    .sort((left, right) => {
      const confidentiality = Number(right.source.confidentiality === "secret") - Number(left.source.confidentiality === "secret");
      if (confidentiality) return confidentiality;
      const length = right.path.nodeIds.length - left.path.nodeIds.length;
      return length || right.source.sequence - left.source.sequence;
    });
  const paths: SemanticAttackPath[] = [];
  for (const { source, path } of candidates) {
    const risk = pathRisk(source, sinkNode.effect || "unknown");
    if (!risk) continue;
    const producer = graph.edges.find((edge) => edge.to === source.id && edge.kind === "produces");
    const nodeIds = producer ? [producer.from, ...path.nodeIds] : path.nodeIds;
    const edgeIds = producer ? [producer.id, ...path.edgeIds] : path.edgeIds;
    const pathEdges = edgeIds
      .map((id) => graph.edges.find((edge) => edge.id === id))
      .filter((edge): edge is SemanticActionEdge => Boolean(edge));
    const confidence = pathEdges.length
      ? Math.min(...pathEdges.map((edge) => edge.confidence))
      : 0;
    const certainty = pathEdges.every((edge) => edge.basis !== "conservative" && edge.confidence >= 0.95)
      ? "observed"
      : "conservative";
    const sequence = nextSequence(graph);
    paths.push({
      id: `sag_path_${sha256(`${risk}:${source.id}:${actionNodeId}:${sinkNode.id}`).slice(0, 24)}`,
      risk,
      verdict: certainty === "observed" ? "block" : "review",
      reason: reasonForRisk(risk, certainty),
      certainty,
      confidence,
      sourceNodeId: source.id,
      actionNodeId,
      sinkNodeId: sinkNode.id,
      nodeIds,
      edgeIds,
      steps: nodeIds.map((id) => graph.nodes.find((node) => node.id === id)).filter(Boolean).map(pathStep),
      sequence,
    });
  }
  return paths.sort((left, right) => {
    const certainty = Number(right.certainty === "observed") - Number(left.certainty === "observed");
    if (certainty) return certainty;
    return right.confidence - left.confidence || right.nodeIds.length - left.nodeIds.length;
  }).slice(0, 6);
}

function isRiskyDataNode(node: SemanticActionNode | undefined): boolean {
  return Boolean(node?.kind === "data" && (node.confidentiality === "secret" || node.integrity === "tainted"));
}

function hasRiskyLineageParent(graph: SemanticActionGraphState, node: SemanticActionNode): boolean {
  for (const edge of graph.edges) {
    if (edge.to !== node.id) continue;
    if (edge.kind === "derives") {
      if (isRiskyDataNode(graph.nodes.find((candidate) => candidate.id === edge.from))) return true;
      continue;
    }
    if (edge.kind !== "produces") continue;
    const producerId = edge.from;
    if (graph.edges.some((input) =>
      input.to === producerId
      && input.kind === "consumes"
      && isRiskyDataNode(graph.nodes.find((candidate) => candidate.id === input.from))
    )) return true;
  }
  return false;
}

function reverseReachableNodeIds(graph: SemanticActionGraphState, from: string): Set<string> {
  const reachable = new Set([from]);
  const pending = [from];
  const incoming = new Map<string, string[]>();
  for (const edge of graph.edges) incoming.set(edge.to, [...(incoming.get(edge.to) || []), edge.from]);
  while (pending.length) {
    const current = pending.pop()!;
    for (const previous of incoming.get(current) || []) {
      if (reachable.has(previous)) continue;
      reachable.add(previous);
      pending.push(previous);
    }
  }
  return reachable;
}

function pathRisk(
  source: SemanticActionNode,
  effect: SemanticActionSinkEffect,
): SemanticAttackPath["risk"] | null {
  const secret = source.confidentiality === "secret";
  const tainted = source.integrity === "tainted";
  if (effect === "external") {
    if (secret) return "secret_to_external_sink";
    if (tainted) return "tainted_to_external_sink";
  }
  if (effect === "persistent") {
    if (secret) return "secret_to_persistent_state";
    if (tainted) return "tainted_to_persistent_state";
  }
  if (effect === "execution") {
    if (secret) return "secret_to_execution";
    if (tainted) return "tainted_to_execution";
  }
  return null;
}

function reasonForRisk(
  risk: SemanticAttackPath["risk"],
  certainty: SemanticAttackPath["certainty"],
): string {
  const observed: Record<SemanticAttackPath["risk"], string> = {
    secret_to_external_sink: "semantic action graph traced secret data to an external sink",
    tainted_to_external_sink: "semantic action graph traced tainted instructions to an external sink",
    secret_to_persistent_state: "semantic action graph traced secret data to persistent state",
    tainted_to_persistent_state: "semantic action graph traced tainted instructions to persistent state",
    secret_to_execution: "semantic action graph traced secret data into process execution",
    tainted_to_execution: "semantic action graph traced tainted instructions into process execution",
    unauthorized_side_effect: "semantic action graph found a side effect without explicit capability authorization",
    target_scope_mismatch: "semantic action graph found an action target outside the authorized capability scope",
  };
  if (certainty === "observed") return observed[risk];
  return observed[risk]
    .replace("traced", "conservatively inferred")
    .replace("to an external sink", "may reach an external sink")
    .replace("to persistent state", "may reach persistent state")
    .replace("into process execution", "may influence process execution");
}

function upsertProvenanceClosure(
  graph: SemanticActionGraphState,
  provenanceId: string,
  provenanceById: Map<string, DataProvenance>,
  active: Set<string>,
): SemanticActionNode | null {
  const existing = graph.nodes.find((node) => node.kind === "data" && node.provenanceId === provenanceId);
  const provenance = provenanceById.get(provenanceId);
  if (!provenance) return existing || null;
  if (active.has(provenanceId)) return existing || null;
  active.add(provenanceId);
  const node = existing || addNode(graph, {
    id: nodeId("data", provenance.id),
    kind: "data",
    sequence: nextSequence(graph),
    label: "data_field",
    provenanceId: provenance.id,
    source: safeLabel(provenance.source),
    path: safePath(provenance.path),
    confidentiality: provenance.confidentiality,
    integrity: provenance.integrity,
    transformations: provenance.transformations.slice(-12).map(safeLabel),
    fingerprint: safeLabel(provenance.contentFingerprint),
  });
  for (const parentId of provenance.parentIds) {
    const parent = upsertProvenanceClosure(graph, parentId, provenanceById, active);
    if (!parent) continue;
    const mediatedByProducer = graph.edges.some((produces) =>
      produces.kind === "produces"
      && produces.to === node.id
      && graph.edges.some((consumes) =>
        consumes.kind === "consumes" && consumes.from === parent.id && consumes.to === produces.from
      )
    );
    if (!mediatedByProducer) {
      const evidence = evidenceForTransformations(provenance.transformations);
      addEdge(graph, parent.id, node.id, "derives", evidence);
    }
  }
  active.delete(provenanceId);
  return node;
}

function directedPath(
  graph: SemanticActionGraphState,
  from: string,
  to: string,
): { nodeIds: string[]; edgeIds: string[] } | null {
  if (from === to) return { nodeIds: [from], edgeIds: [] };
  const graphNodeIds = new Set(graph.nodes.map((node) => node.id));
  if (!graphNodeIds.has(from) || !graphNodeIds.has(to)) return null;
  const hasStrongPath = hasDirectedPath(graph, from, to, (edge) => edge.basis !== "conservative");
  const eligible = (edge: SemanticActionEdge): boolean => !hasStrongPath || edge.basis !== "conservative";
  const bottleneck = widestPathConfidence(graph, from, to, eligible);
  if (bottleneck === null) return null;

  const outgoing = new Map<string, SemanticActionEdge[]>();
  for (const edge of graph.edges) {
    if (!eligible(edge) || edge.confidence + 1e-12 < bottleneck) continue;
    outgoing.set(edge.from, [...(outgoing.get(edge.from) || []), edge]);
  }
  for (const edges of outgoing.values()) edges.sort(compareEdgesDeterministically);

  const queue: Array<{ nodeId: string; nodeIds: string[]; edgeIds: string[] }> = [{
    nodeId: from,
    nodeIds: [from],
    edgeIds: [],
  }];
  const visited = new Set([from]);
  while (queue.length) {
    const current = queue.shift()!;
    for (const edge of outgoing.get(current.nodeId) || []) {
      if (visited.has(edge.to)) continue;
      const nodeIds = [...current.nodeIds, edge.to];
      const edgeIds = [...current.edgeIds, edge.id];
      if (edge.to === to) return { nodeIds, edgeIds };
      visited.add(edge.to);
      queue.push({ nodeId: edge.to, nodeIds, edgeIds });
    }
  }
  return null;
}

function hasDirectedPath(
  graph: SemanticActionGraphState,
  from: string,
  to: string,
  eligible: (edge: SemanticActionEdge) => boolean,
): boolean {
  const pending = [from];
  const visited = new Set([from]);
  while (pending.length) {
    const current = pending.pop()!;
    for (const edge of graph.edges) {
      if (edge.from !== current || !eligible(edge)) continue;
      if (edge.to === to) return true;
      if (visited.has(edge.to)) continue;
      visited.add(edge.to);
      pending.push(edge.to);
    }
  }
  return false;
}

function widestPathConfidence(
  graph: SemanticActionGraphState,
  from: string,
  to: string,
  eligible: (edge: SemanticActionEdge) => boolean,
): number | null {
  const confidence = new Map<string, number>([[from, 1]]);
  const settled = new Set<string>();
  while (true) {
    const candidates = [...confidence]
      .filter(([id]) => !settled.has(id))
      .sort((left, right) => right[1] - left[1] || compareText(left[0], right[0]));
    const current = candidates[0];
    if (!current) return null;
    const [currentId, currentConfidence] = current;
    if (currentId === to) return currentConfidence;
    settled.add(currentId);
    for (const edge of graph.edges) {
      if (edge.from !== currentId || !eligible(edge) || settled.has(edge.to)) continue;
      const candidateConfidence = Math.min(currentConfidence, edge.confidence);
      if (candidateConfidence > (confidence.get(edge.to) ?? -1)) {
        confidence.set(edge.to, candidateConfidence);
      }
    }
  }
}

function compareEdgesDeterministically(left: SemanticActionEdge, right: SemanticActionEdge): number {
  return compareText(left.id, right.id)
    || compareText(left.to, right.to)
    || compareText(left.kind, right.kind);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function addNode(graph: SemanticActionGraphState, node: SemanticActionNode): SemanticActionNode {
  const existing = graph.nodes.find((item) => item.id === node.id);
  if (existing) return existing;
  graph.nodes.push(node);
  return node;
}

function addEdge(
  graph: SemanticActionGraphState,
  from: string,
  to: string,
  kind: SemanticActionEdgeKind,
  details: {
    argPath?: string;
    match?: string;
    basis?: SemanticEvidenceBasis;
    confidence?: number;
  } = {},
): SemanticActionEdge | null {
  if (from === to) return null;
  if (!graph.nodes.some((node) => node.id === from) || !graph.nodes.some((node) => node.id === to)) return null;
  const id = `sag_edge_${sha256(`${from}:${kind}:${to}:${details.argPath || ""}:${details.match || ""}`).slice(0, 24)}`;
  const existing = graph.edges.find((edge) => edge.id === id);
  const basis = details.basis || "observed";
  const confidence = boundedConfidence(details.confidence, basis === "observed" ? 1 : basis === "decoded" ? 0.98 : 0.7);
  if (existing) {
    if (basis === "conservative" || (basis === "decoded" && existing.basis === "observed")) existing.basis = basis;
    existing.confidence = Math.min(existing.confidence, confidence);
    return existing;
  }
  if (directedPath(graph, to, from)) return null;
  const edge: SemanticActionEdge = {
    id,
    from,
    to,
    kind,
    sequence: nextSequence(graph),
    basis,
    confidence,
    ...(details.argPath ? { argPath: safePath(details.argPath) } : {}),
    ...(details.match ? { match: safeLabel(details.match) } : {}),
  };
  graph.edges.push(edge);
  return edge;
}

function evidenceBasisForMatch(match: string | undefined): SemanticEvidenceBasis {
  if (match === "exact") return "observed";
  if (match === "encoded_exact") return "decoded";
  return "conservative";
}

function evidenceConfidenceForMatch(match: string | undefined): number {
  if (match === "exact") return 1;
  if (match === "encoded_exact") return 0.98;
  if (match === "substring") return 0.9;
  if (match === "encoded_substring") return 0.86;
  if (match === "fuzzy") return 0.82;
  if (match === "encoded_fuzzy") return 0.78;
  return 0.7;
}

function evidenceForTransformations(transformations: string[]): {
  basis: SemanticEvidenceBasis;
  confidence: number;
} {
  const match = [...transformations].reverse().find((item) =>
    ["exact", "encoded_exact", "substring", "encoded_substring", "fuzzy", "encoded_fuzzy"].includes(item)
  );
  return {
    basis: evidenceBasisForMatch(match),
    confidence: evidenceConfidenceForMatch(match),
  };
}

function boundedConfidence(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.max(0, Math.min(1, value))
    : fallback;
}

function rememberPath(graph: SemanticActionGraphState, path: SemanticAttackPath): void {
  const existing = graph.paths.findIndex((item) => item.id === path.id);
  if (existing >= 0) graph.paths.splice(existing, 1);
  graph.paths.push(path);
  if (graph.paths.length > graph.limits.maxPaths) graph.paths = graph.paths.slice(-graph.limits.maxPaths);
}

function trimGraph(graph: SemanticActionGraphState): void {
  const pendingActionIds = new Set([...graph.pendingCalls.values()].flat());
  const settledActionIds = new Set(Array.from(new Set(graph.settledCalls.values())).slice(-32));
  const blockedSettledActionIds = new Set([...settledActionIds].filter((id) =>
    graph.nodes.find((node) => node.id === id)?.status === "blocked"
  ));
  const protectedCallActionIds = new Set([...pendingActionIds, ...blockedSettledActionIds]);
  if (graph.nodes.length > graph.limits.maxNodes) {
    const priority: string[] = [];
    const prioritize = (id: string | null): void => {
      if (id && !priority.includes(id)) priority.push(id);
    };
    const prioritizeIncidentNodes = (actionIds: Set<string>): void => {
      graph.edges.forEach((edge) => {
        if (actionIds.has(edge.from)) prioritize(edge.to);
        if (actionIds.has(edge.to)) prioritize(edge.from);
      });
    };
    prioritize(graph.activeIntentId);
    pendingActionIds.forEach(prioritize);
    prioritizeIncidentNodes(pendingActionIds);
    graph.activeCapabilityIds.forEach(prioritize);
    blockedSettledActionIds.forEach(prioritize);
    prioritizeIncidentNodes(blockedSettledActionIds);
    settledActionIds.forEach(prioritize);
    [...graph.paths].reverse().forEach((path) => path.nodeIds.forEach(prioritize));
    [...graph.nodes]
      .reverse()
      .filter(isRiskyDataNode)
      .forEach((node) => prioritize(node.id));
    [...graph.nodes].reverse().forEach((node) => prioritize(node.id));
    const keep = new Set(priority.slice(0, graph.limits.maxNodes));
    graph.nodes = graph.nodes.filter((node) => keep.has(node.id));
  }

  const nodeIds = new Set(graph.nodes.map((node) => node.id));
  const eligibleEdges = graph.edges.filter((edge) => nodeIds.has(edge.from) && nodeIds.has(edge.to));
  const protectedEdgeIds = new Set<string>();
  for (const edge of eligibleEdges) {
    if (protectedEdgeIds.size >= graph.limits.maxEdges) break;
    if (protectedCallActionIds.has(edge.from) || protectedCallActionIds.has(edge.to)) protectedEdgeIds.add(edge.id);
  }
  for (const path of [...graph.paths].reverse()) {
    if (!path.nodeIds.every((id) => nodeIds.has(id))) continue;
    const additional = path.edgeIds.filter((id) => !protectedEdgeIds.has(id));
    if (protectedEdgeIds.size + additional.length > graph.limits.maxEdges) continue;
    additional.forEach((id) => protectedEdgeIds.add(id));
  }
  const protectedEdges = eligibleEdges.filter((edge) => protectedEdgeIds.has(edge.id));
  const recentEdgeBudget = Math.max(0, graph.limits.maxEdges - protectedEdges.length);
  const recentEdgeCandidates = eligibleEdges.filter((edge) => !protectedEdgeIds.has(edge.id));
  const recentEdges = recentEdgeBudget > 0 ? recentEdgeCandidates.slice(-recentEdgeBudget) : [];
  graph.edges = [...protectedEdges, ...recentEdges].sort((left, right) => left.sequence - right.sequence);
  const edgeIds = new Set(graph.edges.map((edge) => edge.id));
  graph.paths = graph.paths.filter((path) =>
    path.nodeIds.every((id) => nodeIds.has(id)) && path.edgeIds.every((id) => edgeIds.has(id))
  ).slice(-graph.limits.maxPaths);
  graph.activeCapabilityIds = graph.activeCapabilityIds.filter((id) => nodeIds.has(id));
  if (graph.activeIntentId && !nodeIds.has(graph.activeIntentId)) graph.activeIntentId = null;
  for (const [key, ids] of graph.pendingCalls) {
    const kept = ids.filter((id) => nodeIds.has(id));
    if (kept.length) graph.pendingCalls.set(key, kept);
    else graph.pendingCalls.delete(key);
  }
  for (const [key, actionNodeId] of graph.settledCalls) {
    if (!nodeIds.has(actionNodeId)) graph.settledCalls.delete(key);
  }
  graph.lifecycleAnomalies = graph.lifecycleAnomalies
    .filter((item) => nodeIds.has(item.actionNodeId))
    .slice(-24);
}

function assertPendingCallAvailable(
  graph: SemanticActionGraphState,
  toolCallId: string | undefined,
  tool: string,
  originalTool: string,
): void {
  const keys = pendingKeys(toolCallId, tool, originalTool);
  const pendingIds = Array.from(new Set(keys.flatMap((key) => graph.pendingCalls.get(key) || [])));
  const explicitId = Boolean(toolCallId?.trim());
  if (!explicitId && pendingIds.length && pendingIds.every((id) =>
    graph.nodes.find((node) => node.id === id)?.status === "proposed"
  )) {
    for (const id of pendingIds) {
      const node = graph.nodes.find((candidate) => candidate.id === id);
      if (node) transitionSemanticActionStatus(graph, node, "failed");
      unregisterAction(graph, id);
    }
    return;
  }
  for (const key of keys) {
    if ((graph.pendingCalls.get(key) || []).length || (key.startsWith("id:") && graph.settledCalls.has(key))) {
      throw new Error("ambiguous or duplicate semantic action call identity");
    }
  }
}

function registerPendingCall(
  graph: SemanticActionGraphState,
  toolCallId: string | undefined,
  tool: string,
  originalTool: string,
  actionNodeId: string,
): void {
  for (const key of pendingKeys(toolCallId, tool, originalTool)) graph.pendingCalls.set(key, [actionNodeId]);
}

function pendingActionId(graph: SemanticActionGraphState, toolCallId: string | undefined, tool: string): string | null {
  const ids = pendingKeys(toolCallId, tool, tool)
    .flatMap((key) => graph.pendingCalls.get(key) || []);
  const uniqueIds = Array.from(new Set(ids.filter((id) => graph.nodes.some((node) => node.id === id))));
  return uniqueIds.length === 1 ? uniqueIds[0] : null;
}

function settledActionId(graph: SemanticActionGraphState, toolCallId: string | undefined): string | null {
  const id = toolCallId?.trim();
  if (!id) return null;
  const actionNodeId = graph.settledCalls.get(`id:${id}`) || "";
  return graph.nodes.some((node) => node.id === actionNodeId) ? actionNodeId : null;
}

function unregisterAction(graph: SemanticActionGraphState, actionNodeId: string, settle = false): void {
  for (const [key, ids] of graph.pendingCalls) {
    if (settle && key.startsWith("id:") && ids.includes(actionNodeId)) rememberSettledCall(graph, key, actionNodeId);
    const kept = ids.filter((id) => id !== actionNodeId);
    if (kept.length) graph.pendingCalls.set(key, kept);
    else graph.pendingCalls.delete(key);
  }
}

function pendingKeys(toolCallId: string | undefined, tool: string, originalTool: string): string[] {
  const id = toolCallId?.trim();
  if (id) return [`id:${id}`];
  return Array.from(new Set([tool, originalTool]
    .map((value) => safeLabel(value || "unknown_tool"))
    .filter(Boolean)
    .map((value) => `tool:${value}`)));
}

function rememberSettledCall(graph: SemanticActionGraphState, key: string, actionNodeId: string): void {
  graph.settledCalls.delete(key);
  graph.settledCalls.set(key, actionNodeId);
  while (graph.settledCalls.size > 128) {
    const oldest = graph.settledCalls.keys().next().value as string | undefined;
    if (!oldest) break;
    graph.settledCalls.delete(oldest);
  }
}

function transitionSemanticActionStatus(
  graph: SemanticActionGraphState,
  node: SemanticActionNode,
  next: SemanticActionStatus,
): boolean {
  const current = node.status || "proposed";
  if (current === next) return true;
  const allowed: Record<SemanticActionStatus, SemanticActionStatus[]> = {
    proposed: ["awaiting_approval", "blocked", "executing", "succeeded", "failed"],
    awaiting_approval: ["blocked", "executing", "succeeded", "failed"],
    executing: ["blocked", "succeeded", "failed"],
    blocked: [],
    succeeded: [],
    failed: [],
    observed: [],
  };
  if (!allowed[current].includes(next)) {
    graph.lifecycleAnomalies.push({
      actionNodeId: node.id,
      from: current,
      to: next,
      sequence: nextSequence(graph),
    });
    if (graph.lifecycleAnomalies.length > 24) graph.lifecycleAnomalies = graph.lifecycleAnomalies.slice(-24);
    return false;
  }
  node.status = next;
  return true;
}

function keyForCapability(capability: TaskCapability): string {
  return sha256(JSON.stringify({
    action: capability.action,
    resourceType: capability.resourceType,
    effect: capability.effect,
    targets: [...capability.targets].sort(),
    constraints: capability.constraints,
    evidence: {
      source: capability.evidence.source,
      sourceMessageHash: capability.evidence.sourceMessageHash,
      explicitAuthorization: capability.evidence.explicitAuthorization,
      insideQuotation: capability.evidence.insideQuotation,
      negated: capability.evidence.negated,
      targetIsConcrete: capability.evidence.targetIsConcrete,
    },
  }));
}

function authoritativeCapability(capability: TaskCapability): boolean {
  return capability.evidence.source === "user"
    && capability.evidence.explicitAuthorization
    && !capability.evidence.insideQuotation
    && !capability.evidence.negated
    && capability.evidence.targetIsConcrete;
}

function factPath(fact: string): string {
  const index = fact.indexOf(":");
  return safePath(index >= 0 ? fact.slice(0, index) : fact);
}

function publicNode(node: SemanticActionNode): SemanticActionNode {
  const result: SemanticActionNode = {
    id: node.id,
    kind: node.kind,
    sequence: node.sequence,
    label: snapshotText(node.label, 80),
  };
  if (node.callIdHash) result.callIdHash = snapshotText(node.callIdHash, 32);
  if (node.tool) result.tool = snapshotText(node.tool, 80);
  if (node.originalTool && node.originalTool !== node.tool) result.originalTool = snapshotText(node.originalTool, 80);
  if (node.decision) result.decision = node.decision;
  if (node.status) result.status = node.status;
  if (typeof node.authorized === "boolean") result.authorized = node.authorized;
  if (node.authorizationReason) result.authorizationReason = snapshotText(node.authorizationReason, 80);
  if (node.sink) result.sink = snapshotText(node.sink, 80);
  if (node.effect) result.effect = node.effect;
  if (node.provenanceId) result.provenanceId = snapshotText(node.provenanceId, 96);
  if (node.source) result.source = snapshotText(node.source, 96);
  if (node.path) result.path = snapshotText(node.path, 120);
  if (node.confidentiality) result.confidentiality = node.confidentiality;
  if (node.integrity) result.integrity = node.integrity;
  if (node.transformations?.length) {
    result.transformations = node.transformations.slice(-4).map((item) => snapshotText(item, 80));
  }
  if (node.synthetic) result.synthetic = true;
  return result;
}

function publicEdge(edge: SemanticActionEdge): SemanticActionEdge {
  return {
    id: edge.id,
    from: edge.from,
    to: edge.to,
    kind: edge.kind,
    sequence: edge.sequence,
    basis: edge.basis,
    confidence: edge.confidence,
    ...(edge.argPath ? { argPath: snapshotText(edge.argPath, 120) } : {}),
    ...(edge.match ? { match: snapshotText(edge.match, 64) } : {}),
  };
}

function publicAttackPath(path: SemanticAttackPath): Record<string, unknown> {
  return {
    id: path.id,
    risk: path.risk,
    verdict: path.verdict,
    reason: snapshotText(path.reason, 180),
    certainty: path.certainty,
    confidence: path.confidence,
    sourceNodeId: path.sourceNodeId,
    actionNodeId: path.actionNodeId,
    sinkNodeId: path.sinkNodeId,
    nodeIds: [...path.nodeIds],
    edgeIds: [...path.edgeIds],
    steps: compactSnapshotList(path.steps, 18).map((item) => snapshotText(item, 120)),
    sequence: path.sequence,
  };
}

type JudgeProjectionLimits = {
  maxPaths: number;
  maxPathNodes: number;
  maxCapabilities: number;
  maxActions: number;
  maxAnomalies: number;
};

function judgeProjection(
  graph: SemanticActionGraphState,
  limits: JudgeProjectionLimits,
): Record<string, unknown> {
  const activeCapabilities = graph.activeCapabilityIds
    .map((id) => graph.nodes.find((node) => node.id === id && node.kind === "capability"))
    .filter((node): node is SemanticActionNode => Boolean(node))
    .slice(-limits.maxCapabilities)
    .map((node) => judgeNode(node));
  const recentActions = graph.nodes
    .filter((node) => node.kind === "action")
    .slice(-limits.maxActions)
    .map((node) => judgeNode(node));
  const paths = [...graph.paths]
    .sort((left, right) => right.sequence - left.sequence
      || Number(right.verdict === "block") - Number(left.verdict === "block"))
    .slice(0, limits.maxPaths)
    .map((path) => judgePath(graph, path, limits.maxPathNodes));
  const includedPathNodeCount = paths.reduce((total, path) =>
    total + Number((path as { directed_nodes?: unknown[] }).directed_nodes?.length || 0), 0);
  return {
    version: graph.version,
    graph_counts: judgeGraphCounts(graph),
    projection_truncated: graph.paths.length > paths.length
      || paths.some((path) => Number(path.omitted_node_count || 0) > 0)
      || graph.activeCapabilityIds.length > activeCapabilities.length
      || graph.nodes.filter((node) => node.kind === "action").length > recentActions.length
      || includedPathNodeCount < paths.reduce((total, path) => total + Number(path.original_node_count || 0), 0),
    authorization_context: {
      active_intent_present: Boolean(graph.activeIntentId),
      active_capabilities: activeCapabilities,
    },
    recent_actions: recentActions,
    causal_paths: paths,
    lifecycle_anomalies: graph.lifecycleAnomalies.slice(-limits.maxAnomalies).map((item) => ({
      from: item.from,
      to: item.to,
      sequence: item.sequence,
    })),
  };
}

function judgeGraphCounts(graph: SemanticActionGraphState): Record<string, number> {
  return {
    nodes: graph.nodes.length,
    edges: graph.edges.length,
    paths: graph.paths.length,
    pending_calls: new Set([...graph.pendingCalls.values()].flat()).size,
    lifecycle_anomalies: graph.lifecycleAnomalies.length,
  };
}

function judgePath(
  graph: SemanticActionGraphState,
  path: SemanticAttackPath,
  maxPathNodes: number,
): Record<string, unknown> {
  const nodes = path.nodeIds
    .map((id) => graph.nodes.find((node) => node.id === id))
    .filter((node): node is SemanticActionNode => Boolean(node));
  const directedNodes = compactSnapshotList(nodes.map((node) => node.id), maxPathNodes)
    .map((id) => graph.nodes.find((node) => node.id === id))
    .filter((node): node is SemanticActionNode => Boolean(node))
    .map((node) => judgeNode(node));
  const edgeEvidence = { observed: 0, decoded: 0, conservative: 0, minimum_confidence: 1 };
  let observedEdges = 0;
  for (const edgeId of path.edgeIds) {
    const edge = graph.edges.find((candidate) => candidate.id === edgeId);
    if (!edge) continue;
    edgeEvidence[edge.basis] += 1;
    edgeEvidence.minimum_confidence = Math.min(edgeEvidence.minimum_confidence, edge.confidence);
    observedEdges += 1;
  }
  if (!observedEdges) edgeEvidence.minimum_confidence = 0;
  return {
    path_id: snapshotText(path.id, 64),
    direction: "source_to_sink",
    risk: path.risk,
    verdict: path.verdict,
    certainty: path.certainty,
    confidence: path.confidence,
    original_node_count: nodes.length,
    omitted_node_count: Math.max(0, nodes.length - directedNodes.length),
    directed_nodes: directedNodes,
    edge_evidence: edgeEvidence,
  };
}

function judgeNode(node: SemanticActionNode, labelLimit = 80): Record<string, unknown> {
  const label = node.kind === "action"
    ? node.tool || node.label
    : node.kind === "data"
      ? node.path || node.label
      : node.kind === "sink"
        ? node.sink || node.label
        : node.label;
  const result: Record<string, unknown> = {
    kind: node.kind,
    label: snapshotText(label, labelLimit),
  };
  if (node.status) result.status = node.status;
  if (node.decision) result.decision = node.decision;
  if (typeof node.authorized === "boolean") result.authorized = node.authorized;
  if (node.authorizationReason) result.authorization_reason = snapshotText(node.authorizationReason, 64);
  if (node.effect) result.effect = node.effect;
  if (node.confidentiality) result.confidentiality = node.confidentiality;
  if (node.integrity) result.integrity = node.integrity;
  if (node.synthetic) result.synthetic = true;
  return result;
}

function compactSnapshotList(values: string[], limit: number): string[] {
  if (values.length <= limit) return [...values];
  const head = Math.ceil(limit / 2);
  const tail = Math.floor(limit / 2);
  return [...values.slice(0, head), ...values.slice(-tail)];
}

function snapshotText(value: string, limit: number): string {
  return safeLabel(value).slice(0, limit);
}

function snapshotBytes(value: Record<string, unknown>): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

function pathStep(node: SemanticActionNode | undefined): string {
  if (!node) return "unknown";
  if (node.kind === "action") return `action:${node.tool || node.label}`;
  if (node.kind === "data") return `data:${node.path || node.label}`;
  if (node.kind === "sink") return `sink:${node.sink || node.label}`;
  return `${node.kind}:${node.label}`;
}

function containsCycle(graph: SemanticActionGraphState): boolean {
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const outgoing = new Map<string, string[]>();
  for (const edge of graph.edges) outgoing.set(edge.from, [...(outgoing.get(edge.from) || []), edge.to]);
  const visit = (id: string): boolean => {
    if (visiting.has(id)) return true;
    if (visited.has(id)) return false;
    visiting.add(id);
    for (const next of outgoing.get(id) || []) {
      if (visit(next)) return true;
    }
    visiting.delete(id);
    visited.add(id);
    return false;
  };
  return graph.nodes.some((node) => visit(node.id));
}

function uniqueLinks(links: SemanticProvenanceLink[]): SemanticProvenanceLink[] {
  const seen = new Set<string>();
  return links.filter((link) => {
    const key = `${link.provenanceId}:${link.argPath || ""}:${link.match || ""}`;
    if (!link.provenanceId || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function nextSequence(graph: SemanticActionGraphState): number {
  const value = graph.nextSequence;
  graph.nextSequence += 1;
  return value;
}

function nodeId(kind: string, value: string): string {
  return `sag_${kind}_${sha256(value).slice(0, 24)}`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeLabel(value: unknown): string {
  return String(value || "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 160);
}

function safePath(value: unknown): string {
  return safeLabel(value).replace(/[^a-zA-Z0-9_$.[\]"'-]/g, "_").slice(0, 180);
}

function boundedLimit(value: number | undefined, fallback: number, minimum: number): number {
  return Number.isInteger(value) ? Math.max(minimum, Math.min(Number(value), 10_000)) : fallback;
}
