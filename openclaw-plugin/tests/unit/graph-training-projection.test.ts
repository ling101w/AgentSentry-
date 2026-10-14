import { describe, expect, it } from "vitest";
import type { AgentSentryRecord } from "../../core/records.ts";
import type { SemanticActionGraphState } from "../../core/semantic-action-graph.ts";
import {
  PRODUCTION_GRAPH_SCHEMA_VERSION,
  assertProductionGraphInput,
  buildProductionGraphInput,
  createGraphTrainingEnvelope,
  isProductionGraphInput,
} from "../../core/graph-learning/production-graph.ts";
import { graphTrainingRowFromRecord } from "../../core/graph-learning/training-export.ts";

function semanticGraph(extraNodes = 0): SemanticActionGraphState {
  const nodes: SemanticActionGraphState["nodes"] = [
    { id: "intent-1", kind: "intent", sequence: 1, label: "user_task", fingerprint: "raw-task-fingerprint" },
    { id: "cap-1", kind: "capability", sequence: 2, label: "send:email:external", authorized: true, authorizationReason: "explicit_user_capability" },
    {
      id: "data-1",
      kind: "data",
      sequence: 3,
      label: "TOP_SECRET_VALUE",
      path: "$.credentials.api_key",
      source: "external_web:attacker.example",
      confidentiality: "secret",
      integrity: "tainted",
      transformations: ["opaque_summary"],
      provenanceId: "prov-sensitive",
    },
    {
      id: "action-1",
      kind: "action",
      sequence: 4,
      label: "send_email",
      tool: "send_email",
      originalTool: "mail_send_TOP_SECRET_VALUE",
      authorized: false,
      authorizationReason: "recipient_outside_authorization",
      callIdHash: "raw-call-id-hash",
      decision: "deny",
      status: "blocked",
    },
    { id: "sink-1", kind: "sink", sequence: 5, label: "attacker@example.test", sink: "send_email", effect: "external" },
  ];
  for (let index = 0; index < extraNodes; index += 1) {
    nodes.push({ id: `old-${index}`, kind: "action", sequence: 6 + index, label: `unrelated-${index}`, tool: `custom_${index}`, status: "succeeded", decision: "allow" });
  }
  return {
    version: 2,
    nextSequence: nodes.length + 1,
    activeIntentId: "intent-1",
    activeCapabilityIds: ["cap-1"],
    nodes,
    edges: [
      { id: "e1", from: "intent-1", to: "cap-1", kind: "declares", sequence: 2, basis: "observed", confidence: 1 },
      { id: "e2", from: "cap-1", to: "action-1", kind: "authorizes", sequence: 4, basis: "observed", confidence: 1 },
      { id: "e3", from: "data-1", to: "action-1", kind: "consumes", sequence: 4, basis: "decoded", confidence: 0.98, argPath: "$.body", match: "encoded_exact" },
      { id: "e4", from: "action-1", to: "sink-1", kind: "targets", sequence: 5, basis: "conservative", confidence: 0.75 },
    ],
    paths: [{
      id: "attack-path",
      risk: "secret_to_external_sink",
      verdict: "block",
      reason: "TOP_SECRET_VALUE reached attacker@example.test",
      certainty: "observed",
      confidence: 0.98,
      sourceNodeId: "data-1",
      actionNodeId: "action-1",
      sinkNodeId: "sink-1",
      nodeIds: ["data-1", "action-1", "sink-1"],
      edgeIds: ["e3", "e4"],
      steps: ["TOP_SECRET_VALUE", "send_email", "attacker@example.test"],
      sequence: 6,
    }],
    limits: { maxNodes: 320, maxEdges: 640, maxPaths: 64 },
    pendingCalls: new Map([["id:call-1", ["action-1"]]]),
    settledCalls: new Map(),
    lifecycleAnomalies: [{ actionNodeId: "action-1", from: "proposed", to: "succeeded", sequence: 7 }],
  };
}

describe("production graph training projection", () => {
  it("exports bounded structural features without outcome or raw-content leakage", () => {
    const projection = buildProductionGraphInput({
      graph: semanticGraph(50),
      currentActionNodeId: "action-1",
      taskMode: "new_task",
      taskFamily: "delivery",
    });

    expect(projection.schema_version).toBe(PRODUCTION_GRAPH_SCHEMA_VERSION);
    expect(projection.graph.nodes.length).toBeLessThanOrEqual(40);
    expect(projection.graph.edges.length).toBeLessThanOrEqual(40);
    expect(projection.graph.projection_truncated).toBe(true);
    expect(projection.graph.nodes.find((node) => node.id === projection.current_action)).toMatchObject({
      kind: "action",
      tool_family: "delivery",
      auth_state: "unauthorized",
      current_action: true,
    });
    expect(projection.graph.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "consumes", basis: "decoded", argument_binding: true, match_kind: "encoded_exact" }),
      expect.objectContaining({ kind: "targets", basis: "conservative" }),
    ]));

    const serialized = JSON.stringify(projection);
    for (const forbidden of ["TOP_SECRET_VALUE", "attacker@example.test", "$.credentials", "raw-call-id-hash", "\"decision\"", "\"status\"", "\"verdict\"", "\"label\""]) {
      expect(serialized).not.toContain(forbidden);
    }
    expect(() => assertProductionGraphInput(projection)).not.toThrow();
    expect(isProductionGraphInput(projection)).toBe(true);
  });

  it("rejects missing actions, label fields, dangling edges, and invalid sample ids", () => {
    expect(() => buildProductionGraphInput({ graph: semanticGraph(), currentActionNodeId: "missing" })).toThrow(/current action/);
    const projection = buildProductionGraphInput({ graph: semanticGraph(), currentActionNodeId: "action-1" });
    expect(isProductionGraphInput({ ...projection, decision: "deny" })).toBe(false);
    expect(isProductionGraphInput({
      ...projection,
      graph: { ...projection.graph, edges: [{ ...projection.graph.edges[0], target: "n999" }] },
    })).toBe(false);
    expect(isProductionGraphInput({
      ...projection,
      context: { ...projection.context, task_mode: "injected-task-mode" },
    })).toBe(false);
    expect(isProductionGraphInput({
      ...projection,
      graph: {
        ...projection.graph,
        nodes: projection.graph.nodes.map((node) => ({ ...node, current_action: false })),
      },
    })).toBe(false);
    expect(() => createGraphTrainingEnvelope({ sampleId: "***", graphInput: projection })).toThrow(/sample id/);
  });

  it("keeps the pre-decision input separate from policy weak labels", () => {
    const input = buildProductionGraphInput({ graph: semanticGraph(), currentActionNodeId: "action-1" });
    const envelope = createGraphTrainingEnvelope({
      sampleId: "graph_sample_123",
      capturedAt: "2026-09-15T01:02:03.000Z",
      graphInput: input,
    });
    const record: AgentSentryRecord = {
      id: "record-1",
      run_id: "run-1",
      session_key: "session-hash",
      type: "tool_decision",
      layer: "Tool Boundary",
      severity: "danger",
      title: "decision",
      summary: "decision",
      payload: { decision: "deny", deterministic_block: true, graph_learning: envelope },
      created_at: "2026-09-15T01:02:04.000Z",
    };
    const row = graphTrainingRowFromRecord(record);
    expect(row).toMatchObject({
      input: { schema_version: "production-graph-v1" },
      label: { source: "policy_weak_label", policy_outcome: "block", deterministic_block: true },
      metadata: { sample_id: "graph_sample_123", record_id: "record-1" },
    });
    expect(JSON.stringify(row?.input)).not.toContain("policy_outcome");
    expect(graphTrainingRowFromRecord({ ...record, type: "alert" })).toBeNull();
    expect(graphTrainingRowFromRecord({ ...record, payload: {} })).toBeNull();
  });
});
