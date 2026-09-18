import { createHash } from "node:crypto";
import type { SemanticActionEdge, SemanticActionGraphState, SemanticActionNode } from "../semantic-action-graph.ts";
import type { TaskSpec } from "../task-spec/index.ts";

export const PRODUCTION_GRAPH_SCHEMA_VERSION = "production-graph-v1" as const;
export const GRAPH_TRAINING_ENVELOPE_VERSION = "graph-training-envelope-v1" as const;

const NODE_KINDS = ["intent", "capability", "action", "data", "sink"] as const;
const EDGE_KINDS = ["declares", "governs", "authorizes", "constrains", "requests", "consumes", "produces", "derives", "targets"] as const;
const EDGE_BASES = ["observed", "decoded", "conservative"] as const;
const SINK_EFFECTS = ["external", "persistent", "execution", "sensitive_read", "write", "unknown", "none"] as const;
const TOOL_FAMILIES = ["read", "write", "network", "delivery", "execution", "memory", "agent", "other", "none"] as const;
const SOURCE_CLASSES = ["user", "system", "workspace", "tool_result", "external", "memory", "webhook", "agent", "unknown", "none"] as const;
const MATCH_KINDS = ["exact", "encoded_exact", "substring", "encoded_substring", "fuzzy", "encoded_fuzzy", "semantic", "none", "other"] as const;
const AUTH_STATES = ["authorized", "unauthorized", "unknown"] as const;
const CONFIDENTIALITY_CLASSES = ["public", "internal", "secret", "none"] as const;
const INTEGRITY_CLASSES = ["trusted", "untrusted", "tainted", "none"] as const;
const TASK_MODES = ["new_task", "task_continuation", "preference", "confirmation", "data_only", "chatter", "unknown"] as const;
const TASK_FAMILIES = ["analysis", "read_only", "write_task", "delivery", "memory", "shell", "mixed", "unknown"] as const;
const FORBIDDEN_INPUT_KEYS = new Set([
  "decision",
  "status",
  "verdict",
  "risk",
  "risk_score",
  "sentry_score",
  "score",
  "label",
  "findings",
  "violations",
  "judge",
  "judge_output",
  "recommended_action",
  "attack_paths",
  "path_verdict",
]);

export type ProductionGraphNode = {
  id: string;
  kind: (typeof NODE_KINDS)[number];
  sequence_offset: number;
  in_degree: number;
  out_degree: number;
  current_action: boolean;
  active_intent: boolean;
  active_capability: boolean;
  tool_family: (typeof TOOL_FAMILIES)[number];
  tool_bucket: number;
  auth_state: (typeof AUTH_STATES)[number];
  sink_effect: (typeof SINK_EFFECTS)[number];
  source_class: (typeof SOURCE_CLASSES)[number];
  confidentiality: (typeof CONFIDENTIALITY_CLASSES)[number];
  integrity: (typeof INTEGRITY_CLASSES)[number];
  transformation_count: number;
  opaque_transform: boolean;
  capability_action: string;
  capability_resource: string;
  capability_effect: string;
};

export type ProductionGraphEdge = {
  source: string;
  target: string;
  kind: (typeof EDGE_KINDS)[number];
  basis: (typeof EDGE_BASES)[number];
  confidence: number;
  sequence_offset: number;
  argument_binding: boolean;
  match_kind: (typeof MATCH_KINDS)[number];
};

export type ProductionGraphInput = {
  schema_version: typeof PRODUCTION_GRAPH_SCHEMA_VERSION;
  current_action: string;
  context: {
    task_mode: (typeof TASK_MODES)[number];
    task_family: (typeof TASK_FAMILIES)[number];
    active_capability_count: number;
  };
  graph: {
    directed: true;
    original_node_count: number;
    original_edge_count: number;
    projection_truncated: boolean;
    nodes: ProductionGraphNode[];
    edges: ProductionGraphEdge[];
  };
};

export type GraphTrainingEnvelope = {
  schema_version: typeof GRAPH_TRAINING_ENVELOPE_VERSION;
  sample_id: string;
  captured_at: string;
  input: ProductionGraphInput;
};

export type ProductionGraphProjectionOptions = {
  maxNodes?: number;
  maxEdges?: number;
  maxHops?: number;
};

type ProjectionCandidate = { id: string; priority: number; sequence: number };

export function buildProductionGraphInput(input: {
  graph: SemanticActionGraphState;
  currentActionNodeId: string;
  taskMode?: TaskSpec["task_mode"];
  taskFamily?: TaskSpec["task_family"];
  limits?: ProductionGraphProjectionOptions;
}): ProductionGraphInput {
  const maxNodes = boundedInteger(input.limits?.maxNodes, 4, 40, 40);
  const maxEdges = boundedInteger(input.limits?.maxEdges, 4, 40, 40);
  const maxHops = boundedInteger(input.limits?.maxHops, 1, 6, 3);
  const graph = input.graph;
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const current = nodeById.get(input.currentActionNodeId);
  if (!current || current.kind !== "action") throw new Error("production graph projection requires a current action node");

  const distances = graphDistances(graph, current.id, maxHops);
  const directNeighbors = new Set([...distances].filter(([, distance]) => distance === 1).map(([id]) => id));
  const candidates = graph.nodes.map((node): ProjectionCandidate => ({
    id: node.id,
    priority: projectionPriority(node, current.id, directNeighbors, distances, graph),
    sequence: node.sequence,
  }));
  candidates.sort((left, right) => left.priority - right.priority || right.sequence - left.sequence || left.id.localeCompare(right.id));
  const selectedIds = new Set(candidates.slice(0, maxNodes).map((candidate) => candidate.id));
  selectedIds.add(current.id);

  const selectedNodes = graph.nodes
    .filter((node) => selectedIds.has(node.id))
    .sort((left, right) => left.sequence - right.sequence || left.id.localeCompare(right.id))
    .slice(-maxNodes);
  const finalNodeIds = new Set(selectedNodes.map((node) => node.id));
  const eligibleEdges = graph.edges.filter((edge) => finalNodeIds.has(edge.from) && finalNodeIds.has(edge.to));
  const selectedEdges = [...eligibleEdges]
    .sort((left, right) => edgePriority(left, current.id) - edgePriority(right, current.id)
      || right.sequence - left.sequence
      || left.id.localeCompare(right.id))
    .slice(0, maxEdges)
    .sort((left, right) => left.sequence - right.sequence || left.id.localeCompare(right.id));
  const publicIdByInternalId = new Map(selectedNodes.map((node, index) => [node.id, `n${index}`]));
  const degrees = projectedDegrees(selectedNodes, eligibleEdges);

  const projection: ProductionGraphInput = {
    schema_version: PRODUCTION_GRAPH_SCHEMA_VERSION,
    current_action: publicIdByInternalId.get(current.id) || "",
    context: {
      task_mode: enumValue(input.taskMode, TASK_MODES, "unknown"),
      task_family: enumValue(input.taskFamily, TASK_FAMILIES, "unknown"),
      active_capability_count: Math.min(graph.activeCapabilityIds.length, 10_000),
    },
    graph: {
      directed: true,
      original_node_count: graph.nodes.length,
      original_edge_count: graph.edges.length,
      projection_truncated: selectedNodes.length < graph.nodes.length || selectedEdges.length < eligibleEdges.length,
      nodes: selectedNodes.map((node) => projectNode(node, current, graph, publicIdByInternalId.get(node.id) || "", degrees.get(node.id))),
      edges: selectedEdges.map((edge) => projectEdge(edge, current, publicIdByInternalId)),
    },
  };
  assertProductionGraphInput(projection);
  return projection;
}

export function createGraphTrainingEnvelope(input: {
  sampleId: string;
  capturedAt?: string;
  graphInput: ProductionGraphInput;
}): GraphTrainingEnvelope {
  assertProductionGraphInput(input.graphInput);
  const sampleId = safeIdentifier(input.sampleId);
  if (!sampleId) throw new Error("graph training sample id is required");
  const capturedAtValue = input.capturedAt || "";
  const capturedAt = Number.isFinite(Date.parse(capturedAtValue))
    ? new Date(capturedAtValue).toISOString()
    : new Date().toISOString();
  return {
    schema_version: GRAPH_TRAINING_ENVELOPE_VERSION,
    sample_id: sampleId,
    captured_at: capturedAt,
    input: structuredClone(input.graphInput),
  };
}

export function assertProductionGraphInput(value: unknown): asserts value is ProductionGraphInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("production graph input must be an object");
  assertNoForbiddenInputKeys(value);
  const input = value as Partial<ProductionGraphInput>;
  if (input.schema_version !== PRODUCTION_GRAPH_SCHEMA_VERSION) throw new Error("unsupported production graph schema version");
  if (!input.graph || input.graph.directed !== true || !Array.isArray(input.graph.nodes) || !Array.isArray(input.graph.edges)) {
    throw new Error("production graph input has an invalid graph envelope");
  }
  if (input.graph.nodes.length > 40 || input.graph.edges.length > 40) throw new Error("production graph projection exceeds storage limits");
  if (!input.context
    || !TASK_MODES.includes(input.context.task_mode)
    || !TASK_FAMILIES.includes(input.context.task_family)
    || !boundedNumber(input.context.active_capability_count, 0, 10_000, true)) {
    throw new Error("production graph input has invalid task context");
  }
  if (!boundedNumber(input.graph.original_node_count, 1, 10_000, true)
    || !boundedNumber(input.graph.original_edge_count, 0, 20_000, true)
    || typeof input.graph.projection_truncated !== "boolean"
    || input.graph.original_node_count < input.graph.nodes.length
    || input.graph.original_edge_count < input.graph.edges.length) {
    throw new Error("production graph input has invalid graph counts");
  }
  const ids = new Set<string>();
  for (const node of input.graph.nodes) {
    if (!node || typeof node.id !== "string" || !/^n\d+$/.test(node.id) || ids.has(node.id)) throw new Error("production graph contains an invalid node id");
    if (!NODE_KINDS.includes(node.kind)) throw new Error("production graph contains an invalid node kind");
    if (!TOOL_FAMILIES.includes(node.tool_family) || !SOURCE_CLASSES.includes(node.source_class) || !SINK_EFFECTS.includes(node.sink_effect)) {
      throw new Error("production graph contains invalid categorical node features");
    }
    if (!AUTH_STATES.includes(node.auth_state)
      || !CONFIDENTIALITY_CLASSES.includes(node.confidentiality)
      || !INTEGRITY_CLASSES.includes(node.integrity)
      || !boundedNumber(node.sequence_offset, -10_000, 10_000, true)
      || !boundedNumber(node.in_degree, 0, 10_000, true)
      || !boundedNumber(node.out_degree, 0, 10_000, true)
      || !boundedNumber(node.tool_bucket, 0, 255, true)
      || !boundedNumber(node.transformation_count, 0, 32, true)
      || typeof node.current_action !== "boolean"
      || typeof node.active_intent !== "boolean"
      || typeof node.active_capability !== "boolean"
      || typeof node.opaque_transform !== "boolean"
      || !validCategoryToken(node.capability_action)
      || !validCategoryToken(node.capability_resource)
      || !validCategoryToken(node.capability_effect)) {
      throw new Error("production graph contains invalid node features");
    }
    ids.add(node.id);
  }
  if (typeof input.current_action !== "string" || !ids.has(input.current_action)) throw new Error("production graph current action is missing");
  const currentNodes = input.graph.nodes.filter((node) => node.current_action);
  if (currentNodes.length !== 1 || currentNodes[0].id !== input.current_action || currentNodes[0].kind !== "action") {
    throw new Error("production graph current action marker is invalid");
  }
  for (const edge of input.graph.edges) {
    if (!edge || !ids.has(edge.source) || !ids.has(edge.target)) throw new Error("production graph contains a dangling edge");
    if (!EDGE_KINDS.includes(edge.kind) || !EDGE_BASES.includes(edge.basis)) throw new Error("production graph contains invalid edge evidence");
    if (!Number.isFinite(edge.confidence) || edge.confidence < 0 || edge.confidence > 1) throw new Error("production graph contains invalid edge confidence");
    if (!MATCH_KINDS.includes(edge.match_kind)
      || !boundedNumber(edge.sequence_offset, -10_000, 10_000, true)
      || typeof edge.argument_binding !== "boolean") {
      throw new Error("production graph contains invalid edge features");
    }
  }
}

export function isProductionGraphInput(value: unknown): value is ProductionGraphInput {
  try {
    assertProductionGraphInput(value);
    return true;
  } catch {
    return false;
  }
}

function graphDistances(graph: SemanticActionGraphState, start: string, maxHops: number): Map<string, number> {
  const adjacency = new Map<string, Set<string>>();
  for (const edge of graph.edges) {
    adjacency.set(edge.from, (adjacency.get(edge.from) || new Set()).add(edge.to));
    adjacency.set(edge.to, (adjacency.get(edge.to) || new Set()).add(edge.from));
  }
  const distances = new Map([[start, 0]]);
  const queue = [start];
  while (queue.length) {
    const id = queue.shift() || "";
    const distance = distances.get(id) || 0;
    if (distance >= maxHops) continue;
    for (const neighbor of [...(adjacency.get(id) || [])].sort()) {
      if (distances.has(neighbor)) continue;
      distances.set(neighbor, distance + 1);
      queue.push(neighbor);
    }
  }
  return distances;
}

function projectionPriority(
  node: SemanticActionNode,
  currentId: string,
  directNeighbors: Set<string>,
  distances: Map<string, number>,
  graph: SemanticActionGraphState,
): number {
  if (node.id === currentId) return 0;
  if (directNeighbors.has(node.id)) return 100;
  if (node.id === graph.activeIntentId) return 200;
  if (graph.activeCapabilityIds.includes(node.id)) return 300;
  const distance = distances.get(node.id);
  if (distance !== undefined) return 400 + distance * 100;
  if (node.kind === "data" && (node.confidentiality === "secret" || node.integrity === "tainted")) return 1200;
  return 2000;
}

function edgePriority(edge: SemanticActionEdge, currentId: string): number {
  if (edge.from === currentId || edge.to === currentId) return 0;
  if (edge.kind === "authorizes" || edge.kind === "constrains" || edge.kind === "consumes" || edge.kind === "targets") return 100;
  if (edge.basis === "observed" || edge.basis === "decoded") return 200;
  return 300;
}

function projectedDegrees(nodes: SemanticActionNode[], edges: SemanticActionEdge[]): Map<string, { incoming: number; outgoing: number }> {
  const result = new Map(nodes.map((node) => [node.id, { incoming: 0, outgoing: 0 }]));
  for (const edge of edges) {
    const source = result.get(edge.from);
    const target = result.get(edge.to);
    if (source) source.outgoing += 1;
    if (target) target.incoming += 1;
  }
  return result;
}

function projectNode(
  node: SemanticActionNode,
  current: SemanticActionNode,
  graph: SemanticActionGraphState,
  publicId: string,
  degree: { incoming: number; outgoing: number } | undefined,
): ProductionGraphNode {
  const capability = node.kind === "capability" ? capabilityParts(node.label) : ["none", "none", "none"];
  return {
    id: publicId,
    kind: node.kind,
    sequence_offset: boundedInteger(node.sequence - current.sequence, -10_000, 10_000, 0),
    in_degree: Math.min(degree?.incoming || 0, 10_000),
    out_degree: Math.min(degree?.outgoing || 0, 10_000),
    current_action: node.id === current.id,
    active_intent: node.id === graph.activeIntentId,
    active_capability: graph.activeCapabilityIds.includes(node.id),
    tool_family: toolFamily(node.kind === "action" ? node.tool : ""),
    tool_bucket: node.kind === "action" ? hashBucket(node.tool || node.label, 256) : 0,
    auth_state: node.authorized === true ? "authorized" : node.authorized === false ? "unauthorized" : "unknown",
    sink_effect: enumValue(node.effect, SINK_EFFECTS, node.kind === "sink" ? "unknown" : "none"),
    source_class: sourceClass(node.source),
    confidentiality: enumValue(node.confidentiality, CONFIDENTIALITY_CLASSES, "none"),
    integrity: enumValue(node.integrity, INTEGRITY_CLASSES, "none"),
    transformation_count: Math.min(node.transformations?.length || 0, 32),
    opaque_transform: Boolean(node.transformations?.some((value) => /opaque|summary|transform|derived/i.test(value))),
    capability_action: capability[0],
    capability_resource: capability[1],
    capability_effect: capability[2],
  };
}

function projectEdge(
  edge: SemanticActionEdge,
  current: SemanticActionNode,
  publicIdByInternalId: Map<string, string>,
): ProductionGraphEdge {
  return {
    source: publicIdByInternalId.get(edge.from) || "",
    target: publicIdByInternalId.get(edge.to) || "",
    kind: edge.kind,
    basis: edge.basis,
    confidence: Math.round(Math.max(0, Math.min(1, edge.confidence)) * 10_000) / 10_000,
    sequence_offset: boundedInteger(edge.sequence - current.sequence, -10_000, 10_000, 0),
    argument_binding: Boolean(edge.argPath),
    match_kind: matchKind(edge.match),
  };
}

function capabilityParts(label: string): [string, string, string] {
  const parts = String(label || "").split(":");
  return [categoryToken(parts[0]), categoryToken(parts[1]), categoryToken(parts[2])];
}

function toolFamily(value: string | undefined): (typeof TOOL_FAMILIES)[number] {
  const tool = String(value || "").toLowerCase();
  if (!tool) return "none";
  if (tool === "read_file" || tool === "read_webpage") return "read";
  if (tool === "write_file") return "write";
  if (tool === "call_api") return "network";
  if (tool === "send_email") return "delivery";
  if (tool === "shell_exec") return "execution";
  if (tool === "memory_read" || tool === "memory_write") return "memory";
  if (tool === "sessions_send") return "agent";
  return "other";
}

function sourceClass(value: string | undefined): (typeof SOURCE_CLASSES)[number] {
  const source = String(value || "").toLowerCase();
  if (!source) return "none";
  if (/user/.test(source)) return "user";
  if (/system/.test(source)) return "system";
  if (/workspace|file/.test(source)) return "workspace";
  if (/tool/.test(source)) return "tool_result";
  if (/external|web|email|api/.test(source)) return "external";
  if (/memory/.test(source)) return "memory";
  if (/webhook|wake/.test(source)) return "webhook";
  if (/agent|session/.test(source)) return "agent";
  return "unknown";
}

function matchKind(value: string | undefined): (typeof MATCH_KINDS)[number] {
  const normalized = String(value || "").toLowerCase();
  if (!normalized) return "none";
  return enumValue(normalized, MATCH_KINDS, normalized.includes("semantic") ? "semantic" : "other");
}

function categoryToken(value: string | undefined): string {
  const normalized = String(value || "").trim().toLowerCase();
  return /^[a-z][a-z0-9_-]{0,31}$/.test(normalized) ? normalized : "other";
}

function hashBucket(value: string, buckets: number): number {
  const digest = createHash("sha256").update(value || "unknown", "utf8").digest();
  return digest.readUInt32BE(0) % buckets;
}

function safeIdentifier(value: string): string {
  return String(value || "").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 96);
}

function enumValue<const T extends readonly string[]>(value: unknown, allowed: T, fallback: T[number]): T[number] {
  return typeof value === "string" && allowed.includes(value) ? value as T[number] : fallback;
}

function boundedInteger(value: number | undefined, minimum: number, maximum: number, fallback: number): number {
  return Number.isInteger(value) ? Math.max(minimum, Math.min(maximum, Number(value))) : fallback;
}

function boundedNumber(value: unknown, minimum: number, maximum: number, integer = false): value is number {
  return typeof value === "number"
    && Number.isFinite(value)
    && value >= minimum
    && value <= maximum
    && (!integer || Number.isInteger(value));
}

function validCategoryToken(value: unknown): value is string {
  return typeof value === "string" && /^[a-z][a-z0-9_-]{0,31}$/.test(value);
}

function assertNoForbiddenInputKeys(value: unknown, path = "input"): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoForbiddenInputKeys(item, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_INPUT_KEYS.has(key.toLowerCase())) throw new Error(`label leakage field is forbidden at ${path}.${key}`);
    assertNoForbiddenInputKeys(item, `${path}.${key}`);
  }
}
