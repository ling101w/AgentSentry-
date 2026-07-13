import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { overviewAlerts, overviewCausalChain, overviewCausalGraph } from "../../server/dashboard.ts";

function payloadWithCausalGraph(): Record<string, unknown> {
  return {
    findings: [{
      layer: "Semantic Action Graph",
      evidence: {
        path_id: "path-1",
        risk: "secret_to_external_sink",
        path_verdict: "block",
        path_certainty: "observed",
        path_confidence: 1,
        node_ids: ["action-read", "data-secret", "action-send", "sink-email"],
        edge_ids: ["edge-produces", "edge-consumes", "edge-targets"],
        causal_chain: ["action:read_webpage", "data:$.token", "action:send_email", "sink:send_email"],
      },
    }],
    trust: {
      semantic_action_graph: {
        version: 2,
        nodes: [
          { id: "intent-1", kind: "intent", label: "user_task", sequence: 1 },
          { id: "cap-1", kind: "capability", label: "send:email:external_side_effect", sequence: 2, source: "user", authorized: true, authorizationReason: "explicit_user_capability" },
          { id: "action-read", kind: "action", label: "read_webpage", tool: "read_webpage", sequence: 3, status: "succeeded" },
          {
            id: "data-secret",
            kind: "data",
            label: "data_field",
            path: "$.token",
            confidentiality: "secret",
            integrity: "tainted",
            transformations: ["decoded_base64"],
            sequence: 4,
            rawValue: "fixture-secret-must-not-leak",
          },
          { id: "action-send", kind: "action", label: "send_email", tool: "send_email", sequence: 5, status: "blocked" },
          { id: "sink-email", kind: "sink", label: "send_email", sink: "send_email", effect: "external", sequence: 6 },
          { id: "unrelated", kind: "data", label: "unrelated", path: "$.other", sequence: 7 },
        ],
        edges: [
          { id: "edge-declares", from: "intent-1", to: "cap-1", kind: "declares" },
          { id: "edge-authorizes", from: "cap-1", to: "action-send", kind: "authorizes" },
          { id: "edge-produces", from: "action-read", to: "data-secret", kind: "produces", basis: "observed", confidence: 1 },
          { id: "edge-consumes", from: "data-secret", to: "action-send", kind: "consumes", argPath: "$.args.body", basis: "decoded", confidence: 0.98 },
          { id: "edge-targets", from: "action-send", to: "sink-email", kind: "targets" },
          { id: "edge-unrelated", from: "action-read", to: "unrelated", kind: "produces" },
        ],
        attack_paths: [{
          id: "path-1",
          risk: "secret_to_external_sink",
          verdict: "block",
          certainty: "observed",
          confidence: 1,
          nodeIds: ["action-read", "data-secret", "action-send", "sink-email"],
          edgeIds: ["edge-produces", "edge-consumes", "edge-targets"],
        }],
      },
    },
  };
}

function callHash(callId: string): string {
  return createHash("sha256").update(callId).digest("hex").slice(0, 24);
}

function authorizedPayload(callId = "authorized-call"): Record<string, unknown> {
  return {
    toolName: "send_email",
    normalized_tool: "send_email",
    toolCallId: callId,
    decision: "allow",
    params: { to: "private-recipient@example.test", body: "private-body" },
    trust: {
      semantic_action_graph: {
        version: 2,
        nodes: [
          { id: "intent-authorized", kind: "intent", label: "user_task", sequence: 1 },
          {
            id: "cap-authorized",
            kind: "capability",
            label: "send:email:external_side_effect",
            sequence: 2,
            authorized: true,
            authorizationReason: "explicit_user_capability",
            rawTarget: "private-recipient@example.test",
          },
          {
            id: "action-authorized",
            kind: "action",
            label: "send_email",
            tool: "send_email",
            callIdHash: callHash(callId),
            sequence: 3,
            authorized: true,
            decision: "allow",
            status: "executing",
          },
          { id: "sink-authorized", kind: "sink", label: "send_email", sink: "send_email", effect: "external", sequence: 4, rawTarget: "private-recipient@example.test" },
          {
            id: "action-decoy",
            kind: "action",
            label: "send_email",
            tool: "send_email",
            callIdHash: callHash("different-call"),
            sequence: 5,
            authorized: true,
            decision: "allow",
            status: "executing",
          },
        ],
        edges: [
          { id: "edge-authorized-declares", from: "intent-authorized", to: "cap-authorized", kind: "declares", basis: "observed", confidence: 1 },
          { id: "edge-authorized-authorizes", from: "cap-authorized", to: "action-authorized", kind: "authorizes", basis: "observed", confidence: 1 },
          { id: "edge-authorized-targets", from: "action-authorized", to: "sink-authorized", kind: "targets", basis: "observed", confidence: 1 },
        ],
        attack_paths: [],
      },
    },
  };
}

function enforcementBypassPayload(): Record<string, unknown> {
  const hash = callHash("blocked-call");
  return {
    findings: [{
      layer: "Tool Boundary",
      evidence: {
        event: "enforcement_bypass",
        execution_status: "executed_after_block",
        action_node_id: "action-blocked",
      },
    }],
    trust: {
      semantic_action_graph: {
        version: 2,
        nodes: [
          { id: "intent-bypass", kind: "intent", label: "user_task", sequence: 1 },
          { id: "cap-bypass", kind: "capability", label: "send:email:external_side_effect", sequence: 2, authorized: true },
          { id: "action-blocked", kind: "action", label: "send_email", tool: "send_email", callIdHash: hash, sequence: 3, status: "blocked", decision: "deny" },
          { id: "sink-bypass", kind: "sink", label: "send_email", sink: "send_email", effect: "external", sequence: 4, rawTarget: "do-not-expose@example.test" },
          {
            id: "action-observed",
            kind: "action",
            label: "send_email",
            tool: "send_email",
            callIdHash: hash,
            sequence: 6,
            status: "observed",
            authorizationReason: "post_block_execution",
            synthetic: true,
          },
        ],
        edges: [
          { id: "edge-bypass-declares", from: "intent-bypass", to: "cap-bypass", kind: "declares", basis: "observed", confidence: 1 },
          { id: "edge-bypass-authorizes", from: "cap-bypass", to: "action-blocked", kind: "authorizes", basis: "observed", confidence: 1 },
          { id: "edge-blocked-targets", from: "action-blocked", to: "sink-bypass", kind: "targets", basis: "observed", confidence: 1 },
          { id: "edge-observed-governs", from: "intent-bypass", to: "action-observed", kind: "governs", basis: "observed", confidence: 1 },
          { id: "edge-observed-targets", from: "action-observed", to: "sink-bypass", kind: "targets", basis: "observed", confidence: 1 },
        ],
        attack_paths: [],
        lifecycle_anomalies: [{ actionNodeId: "action-blocked", from: "blocked", to: "succeeded", sequence: 5 }],
      },
    },
  };
}

describe("dashboard causal graph projection", () => {
  it("projects the typed path plus authorization context without raw graph fields", () => {
    const graph = overviewCausalGraph(payloadWithCausalGraph());

    expect(graph).toMatchObject({
      version: 2,
      trace_kind: "attack",
      path_id: "path-1",
      risk: "secret_to_external_sink",
      verdict: "block",
      certainty: "observed",
      confidence: 1,
      path_node_ids: ["action-read", "data-secret", "action-send", "sink-email"],
      path_edge_ids: ["edge-produces", "edge-consumes", "edge-targets"],
      session_node_count: 7,
      session_edge_count: 6,
      session_path_count: 1,
      snapshot_truncated: false,
      projection_truncated: true,
    });
    expect(graph?.nodes.map((node) => node.id)).toEqual(expect.arrayContaining([
      "intent-1",
      "cap-1",
      "action-read",
      "data-secret",
      "action-send",
      "sink-email",
    ]));
    expect(graph?.nodes.some((node) => node.id === "unrelated")).toBe(false);
    expect(graph?.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "edge-authorizes", kind: "authorizes", on_path: false }),
      expect.objectContaining({ id: "edge-consumes", kind: "consumes", on_path: true, arg_path: "$.args.body", basis: "decoded", confidence: 0.98 }),
    ]));
    expect(graph?.nodes).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: "cap-1",
        source: "user",
        authorization_actor: "user",
        authorized: true,
        authorization_reason: "explicit_user_capability",
      }),
      expect.objectContaining({ id: "data-secret", transformations: ["decoded_base64"] }),
    ]));
    expect(JSON.stringify(graph)).not.toContain("fixture-secret-must-not-leak");
    expect(JSON.stringify(graph)).not.toContain("rawValue");
  });

  it("provides the complete display contract in directed source-to-sink order", () => {
    const graph = overviewCausalGraph(payloadWithCausalGraph());
    const nodesById = new Map(graph?.nodes.map((node) => [String(node.id), node]));
    const orderedPath = graph?.path_node_ids.map((id) => nodesById.get(id));
    const authorization = graph?.nodes.find((node) => node.kind === "capability");

    expect(authorization).toMatchObject({
      authorization_actor: "user",
      authorized: true,
      authorization_reason: "explicit_user_capability",
    });
    expect(orderedPath?.map((node) => node?.kind)).toEqual(["action", "data", "action", "sink"]);
    expect(orderedPath?.filter((node) => node?.kind === "action").map((node) => node?.tool))
      .toEqual(["read_webpage", "send_email"]);
    expect(orderedPath?.find((node) => node?.kind === "data")).toMatchObject({
      path: "$.token",
      confidentiality: "secret",
      integrity: "tainted",
    });
    expect(orderedPath?.at(-1)).toMatchObject({ sink: "send_email", effect: "external" });
    expect(graph).toMatchObject({ verdict: "block", certainty: "observed", confidence: 1 });
  });

  it("does not expose a session graph when the current record has no causal path evidence", () => {
    const payload = payloadWithCausalGraph();
    delete payload.findings;

    expect(overviewCausalGraph(payload)).toBeNull();
  });

  it("selects the strongest causal finding instead of the first finding", () => {
    const payload = payloadWithCausalGraph();
    const findings = payload.findings as Array<Record<string, unknown>>;
    payload.findings = [{
      layer: "Semantic Action Graph",
      evidence: {
        path_id: "path-1",
        risk: "secret_to_external_sink",
        path_verdict: "review",
        path_certainty: "conservative",
        path_confidence: 0.6,
        node_ids: ["action-read", "data-secret", "action-send", "sink-email"],
        edge_ids: ["edge-produces", "edge-consumes", "edge-targets"],
      },
    }, ...findings];

    expect(overviewCausalGraph(payload)).toMatchObject({ verdict: "block", certainty: "observed", confidence: 1 });
  });

  it("projects an explicitly authorized allow as a real intent-to-sink path", () => {
    const graph = overviewCausalGraph(authorizedPayload());

    expect(graph).toMatchObject({
      version: 2,
      trace_kind: "authorized",
      risk: "authorized_tool_execution",
      verdict: "allow",
      certainty: "observed",
      confidence: 1,
      path_node_ids: ["intent-authorized", "cap-authorized", "action-authorized", "sink-authorized"],
      path_edge_ids: ["edge-authorized-declares", "edge-authorized-authorizes", "edge-authorized-targets"],
    });
    expect(graph?.edges.every((edge) => edge.synthetic !== true)).toBe(true);
    expect(JSON.stringify(graph)).not.toContain("private-recipient@example.test");
    expect(JSON.stringify(graph)).not.toContain("private-body");
    expect(JSON.stringify(graph)).not.toContain("rawTarget");
  });

  it("does not attach an allow record to another in-flight call of the same tool", () => {
    const payload = authorizedPayload();
    payload.toolCallId = "unknown-call";

    expect(overviewCausalGraph(payload)).toBeNull();
  });

  it("projects execution after block as a critical observed bypass with both branches connected", () => {
    const graph = overviewCausalGraph(enforcementBypassPayload());

    expect(graph).toMatchObject({
      version: 2,
      trace_kind: "enforcement_bypass",
      risk: "execution_after_block",
      verdict: "critical",
      certainty: "observed",
      confidence: 1,
      path_node_ids: ["intent-bypass", "action-observed", "sink-bypass"],
      path_edge_ids: ["edge-observed-governs", "edge-observed-targets"],
    });
    expect(graph?.nodes).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "action-blocked", status: "blocked" }),
      expect.objectContaining({ id: "action-observed", status: "observed", authorization_reason: "post_block_execution" }),
    ]));
    expect(graph?.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "edge-blocked-targets", from: "action-blocked", to: "sink-bypass" }),
      expect.objectContaining({ id: "edge-bypass-authorizes", from: "cap-bypass", to: "action-blocked" }),
    ]));
    expect(JSON.stringify(graph)).not.toContain("do-not-expose@example.test");
    expect(graph?.nodes.filter((node) => node.kind === "collapsed")).toHaveLength(0);
  });

  it("rejects a claimed bypass when the graph has no matching lifecycle anomaly", () => {
    const payload = enforcementBypassPayload();
    const trust = payload.trust as { semantic_action_graph: { lifecycle_anomalies: unknown[] } };
    trust.semantic_action_graph.lifecycle_anomalies = [];

    expect(overviewCausalGraph(payload)).toBeNull();
  });

  it("adds at most one useful authorized trace to the overview while risk-only lists stay unchanged", () => {
    type Event = Parameters<typeof overviewAlerts>[0][number];
    const authorizedGraph = overviewCausalGraph(authorizedPayload());
    const base: Omit<Event, "id" | "decision" | "severity" | "causal_graph"> = {
      run_id: "run",
      source: "OpenClaw",
      type: "tool_decision",
      layer: "Tool Boundary",
      tool: "email",
      title: "tool decision",
      reason: "fixture",
      rule: "fixture",
      score: 0,
      created_at: "2026-07-12T00:00:00.000Z",
      text: "fixture",
      causal_chain: [],
    };
    const events: Event[] = [
      { ...base, id: "allow-1", decision: "ALLOW", severity: "INFO", causal_graph: authorizedGraph },
      { ...base, id: "allow-2", decision: "ALLOW", severity: "MEDIUM", causal_graph: authorizedGraph },
      { ...base, id: "risk-1", decision: "BLOCK", severity: "HIGH", causal_graph: null },
    ];

    expect(overviewAlerts(events).map((row) => row.id)).toEqual(["risk-1"]);
    const overview = overviewAlerts(events, { includeAuthorizedTrace: true });
    expect(overview.map((row) => row.id)).toEqual(["allow-1", "risk-1"]);
    expect(overview.filter((row) => (row.causal_graph as { trace_kind?: string } | null)?.trace_kind === "authorized")).toHaveLength(1);
  });

  it("keeps a long review path connected through a sanitized display-only collapse", () => {
    const nodeIds = Array.from({ length: 20 }, (_, index) => `node-${index}`);
    const edgeIds = Array.from({ length: 19 }, (_, index) => `edge-${index}`);
    const supportNodeIds = Array.from({ length: 10 }, (_, index) => `support-${index}`);
    const payload: Record<string, unknown> = {
      findings: [{
        layer: "Semantic Action Graph",
        evidence: {
          path_id: "long-path",
          risk: "secret_to_external_sink",
          path_verdict: "review",
          path_certainty: "conservative",
          path_confidence: 0.72,
          node_ids: nodeIds,
          edge_ids: edgeIds,
          causal_chain: ["action:source", "sink:external"],
        },
      }],
      trust: {
        semantic_action_graph: {
          version: 2,
          nodes: [
            ...nodeIds.map((id, index) => ({
              id,
              kind: index === nodeIds.length - 1 ? "sink" : index % 2 ? "data" : "action",
              label: id,
              sequence: index + 1,
              rawValue: `omitted-secret-${index}`,
            })),
            ...supportNodeIds.map((id, index) => ({
              id,
              kind: "capability",
              label: `support capability ${index}`,
              sequence: 30 + index,
            })),
          ],
          edges: [
            ...edgeIds.map((id, index) => ({
              id,
              from: nodeIds[index],
              to: nodeIds[index + 1],
              kind: index === edgeIds.length - 1 ? "targets" : index % 2 ? "consumes" : "produces",
              basis: "conservative",
              confidence: 0.72,
            })),
            ...supportNodeIds.map((id, index) => ({
              id: `support-edge-${index}`,
              from: id,
              to: "node-0",
              kind: "authorizes",
            })),
          ],
          attack_paths: [],
        },
      },
    };

    const graph = overviewCausalGraph(payload);
    expect(graph).toMatchObject({ verdict: "review", certainty: "conservative", confidence: 0.72 });
    expect(graph).toMatchObject({ session_node_count: 30, session_edge_count: 29, projection_truncated: true });
    expect(graph?.path_node_ids[0]).toBe("node-0");
    expect(graph?.path_node_ids.at(-1)).toBe("node-19");
    expect(graph?.path_node_ids).toHaveLength(12);
    expect(graph?.nodes.length).toBeLessThanOrEqual(16);
    expect(graph?.edges.length).toBeLessThanOrEqual(24);

    const collapsedNode = graph?.nodes.find((node) => node.kind === "collapsed");
    expect(collapsedNode).toMatchObject({
      kind: "collapsed",
      effect: "display_only",
      display_only: true,
      synthetic: true,
      projection: "collapsed",
      omitted_node_count: 9,
      omitted_edge_count: 10,
    });
    expect(graph?.path_node_ids).toContain(String(collapsedNode?.id));
    const summaryEdges = graph?.edges.filter((edge) => edge.projection === "collapsed") || [];
    expect(summaryEdges).toHaveLength(2);
    expect(summaryEdges).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "summary", on_path: true, display_only: true, synthetic: true }),
    ]));

    const projectedNodeIds = new Set(graph?.nodes.map((node) => String(node.id)) || []);
    const projectedEdgeIds = new Set(graph?.edges.map((edge) => String(edge.id)) || []);
    expect(graph?.path_node_ids.every((id) => projectedNodeIds.has(id))).toBe(true);
    expect(graph?.path_edge_ids.every((id) => projectedEdgeIds.has(id))).toBe(true);
    graph?.path_node_ids.slice(1).forEach((to, index) => {
      const from = graph.path_node_ids[index];
      const connectingEdge = graph.edges.find((edge) => edge.from === from && edge.to === to && edge.on_path === true);
      expect(connectingEdge, `${from} must connect to ${to}`).toBeDefined();
      expect(graph.path_edge_ids).toContain(String(connectingEdge?.id));
    });
    expect(JSON.stringify(graph)).not.toContain("omitted-secret");
    expect(JSON.stringify(graph)).not.toContain("rawValue");
  });

  it("keeps the causal chain head and final sink when compacting long evidence", () => {
    const causalChain = Array.from({ length: 20 }, (_, index) => `step:${index}`);
    causalChain[causalChain.length - 1] = "sink:send_email";

    const projected = overviewCausalChain({
      findings: [{ evidence: { causal_chain: causalChain } }],
    });

    expect(projected).toEqual([
      ...causalChain.slice(0, 6),
      ...causalChain.slice(-6),
    ]);
    expect(projected.at(-1)).toBe("sink:send_email");
  });
});
