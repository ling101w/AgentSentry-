import { describe, expect, it } from "vitest";
import {
  activateSemanticIntent,
  beginSemanticAction,
  completeSemanticAction,
  createSemanticActionGraph,
  findSemanticActionPath,
  markSemanticActionEnforcement,
  semanticActionGraphJudgeProjection,
  semanticActionGraphSnapshot,
  semanticActionResultContext,
  setSemanticActionDecision,
  validateSemanticActionGraph,
  type SemanticActionEffects,
  type SemanticActionGraphState,
} from "../../core/semantic-action-graph.ts";
import type { DataProvenance } from "../../core/taint/provenance-graph.ts";
import {
  authorizeCapability,
  deriveTaskSpecV2,
  type CapabilityAuthorization,
  type TaskSpec,
} from "../../core/task-spec/index.ts";

const EXTERNAL_EFFECTS: SemanticActionEffects = {
  external: true,
  persistence: false,
  execution: false,
  sensitive: false,
};

const NO_EFFECTS: SemanticActionEffects = {
  external: false,
  persistence: false,
  execution: false,
  sensitive: false,
};

const READ_ONLY_AUTHORIZATION: CapabilityAuthorization = {
  action: "allow",
  authorized: true,
  reason: "explicit_capability_match",
};

function emailTask(): { taskSpec: TaskSpec; authorization: CapabilityAuthorization } {
  const taskSpec = deriveTaskSpecV2("Send report.md to teacher@example.edu.", []);
  const authorization = authorizeCapability(taskSpec, {
    tool: "send_email",
    args: { recipient: "teacher@example.edu", body: "Quarterly report" },
  });
  if (!authorization.authorized || !authorization.capability) {
    throw new Error(`email fixture was not authorized: ${authorization.reason}`);
  }
  return { taskSpec, authorization };
}

function emailGraph(): {
  graph: SemanticActionGraphState;
  intentId: string;
  authorization: CapabilityAuthorization;
} {
  const { taskSpec, authorization } = emailTask();
  const graph = createSemanticActionGraph();
  const intentId = activateSemanticIntent(graph, taskSpec);
  return { graph, intentId, authorization };
}

function provenance(
  id: string,
  overrides: Partial<DataProvenance> = {},
): DataProvenance {
  return {
    id,
    parentIds: [],
    source: "fixture",
    path: `$.${id}`,
    confidentiality: "public",
    integrity: "trusted",
    transformations: [],
    contentFingerprint: `fingerprint-${id}`,
    ...overrides,
  };
}

describe("Semantic Action Graph V2", () => {
  it("builds an intent, authorization, action, and sink DAG", () => {
    const { graph, intentId, authorization } = emailGraph();
    const attempt = beginSemanticAction(graph, {
      toolCallId: "email-call-1",
      tool: "send_email",
      originalTool: "send_email",
      authorization,
      sink: "send_email",
      effects: EXTERNAL_EFFECTS,
      provenance: [],
    });
    setSemanticActionDecision(graph, attempt.actionNodeId, "allow");

    const capability = graph.nodes.find((node) => node.kind === "capability");
    const action = graph.nodes.find((node) => node.id === attempt.actionNodeId);
    const sink = graph.nodes.find((node) => node.kind === "sink");
    expect(capability).toMatchObject({
      authorized: true,
      authorizationReason: "explicit_user_capability",
      source: "user",
    });
    expect(action).toMatchObject({ kind: "action", tool: "send_email", decision: "allow", authorized: true });
    expect(sink).toMatchObject({ sink: "send_email", effect: "external" });
    expect(graph.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ from: intentId, to: capability?.id, kind: "declares" }),
      expect.objectContaining({ from: intentId, to: attempt.actionNodeId, kind: "governs" }),
      expect.objectContaining({ from: capability?.id, to: attempt.actionNodeId, kind: "authorizes" }),
      expect.objectContaining({ from: attempt.actionNodeId, to: sink?.id, kind: "targets" }),
    ]));
    expect(findSemanticActionPath(graph, intentId, sink!.id)).not.toBeNull();
    expect(attempt.violations).toEqual([]);
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
    const snapshot = semanticActionGraphSnapshot(graph) as { nodes: Array<Record<string, unknown>> };
    expect(snapshot.nodes.find((node) => node.kind === "capability")).toMatchObject({
      source: "user",
      authorized: true,
      authorizationReason: "explicit_user_capability",
    });
  });

  it.each([
    ["secret", { confidentiality: "secret", integrity: "trusted" }, "secret_to_external_sink"],
    ["tainted", { confidentiality: "public", integrity: "tainted" }, "tainted_to_external_sink"],
  ] as const)("blocks a %s data path to an external sink", (_name, labels, expectedRisk) => {
    const { graph, authorization } = emailGraph();
    const source = provenance(`prov-${_name}`, labels);
    const attempt = beginSemanticAction(graph, {
      toolCallId: `email-${_name}`,
      tool: "send_email",
      originalTool: "send_email",
      authorization,
      sink: "send_email",
      effects: EXTERNAL_EFFECTS,
      provenance: [source],
      consumes: [{ provenanceId: source.id, argPath: "$.args.body", match: "exact" }],
    });

    expect(attempt.violations).toHaveLength(1);
    expect(attempt.violations[0]).toMatchObject({
      reason: expect.stringContaining("external sink"),
      path: {
        risk: expectedRisk,
        verdict: "block",
        certainty: "observed",
        confidence: 1,
        actionNodeId: attempt.actionNodeId,
      },
    });
    const path = attempt.violations[0].path;
    const dataNode = graph.nodes.find((node) => node.provenanceId === source.id);
    const sinkNode = graph.nodes.find((node) => node.id === path.sinkNodeId);
    expect(path.nodeIds).toEqual([dataNode?.id, attempt.actionNodeId, sinkNode?.id]);
    expect(findSemanticActionPath(graph, dataNode!.id, sinkNode!.id)).toMatchObject({
      nodeIds: [dataNode!.id, attempt.actionNodeId, sinkNode!.id],
    });
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
  });

  it("does not block trusted public data sent through an authorized external sink", () => {
    const { graph, authorization } = emailGraph();
    const source = provenance("prov-public");
    const attempt = beginSemanticAction(graph, {
      toolCallId: "email-public",
      tool: "send_email",
      originalTool: "send_email",
      authorization,
      sink: "send_email",
      effects: EXTERNAL_EFFECTS,
      provenance: [source],
      consumes: [{ provenanceId: source.id, argPath: "$.args.body", match: "exact" }],
    });

    expect(attempt.violations).toEqual([]);
    expect(graph.paths).toEqual([]);
    expect(graph.nodes.find((node) => node.provenanceId === source.id)).toMatchObject({
      confidentiality: "public",
      integrity: "trusted",
    });
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
  });

  it("keeps a semantic-only sink inference conservative", () => {
    const { graph, authorization } = emailGraph();
    const source = provenance("prov-semantic-sink", { confidentiality: "secret" });
    const attempt = beginSemanticAction(graph, {
      toolCallId: "semantic-sink",
      tool: "custom_transport",
      originalTool: "custom_transport",
      authorization,
      sink: null,
      effects: NO_EFFECTS,
      semantic: {
        operations: ["request"],
        sensitiveSources: [],
        externalSinks: ["$.args.url:https://external.invalid"],
        persistenceTargets: [],
        privilegedEffects: [],
        encodings: [],
        benignClaims: [],
        localReads: [],
        networkWrites: ["$.args.url:https://external.invalid"],
      },
      provenance: [source],
      consumes: [{ provenanceId: source.id, argPath: "$.args.body", match: "exact" }],
    });

    expect(attempt.violations).toHaveLength(1);
    expect(attempt.violations[0].path).toMatchObject({
      verdict: "review",
      certainty: "conservative",
      confidence: 0.72,
    });
    const sinkNode = graph.nodes.find((node) => node.kind === "sink");
    expect(sinkNode).toMatchObject({ synthetic: true, effect: "external" });
    expect(graph.edges.find((edge) => edge.to === sinkNode?.id)).toMatchObject({
      kind: "targets",
      basis: "conservative",
      confidence: 0.72,
    });
  });

  it("ranks an observed path ahead of newer conservative candidates before applying the report limit", () => {
    const { graph, authorization } = emailGraph();
    const sources = Array.from({ length: 7 }, (_, index) => provenance(`prov-rank-${index}`, {
      confidentiality: "secret",
    }));
    const attempt = beginSemanticAction(graph, {
      toolCallId: "ranked-sink",
      tool: "send_email",
      originalTool: "send_email",
      authorization,
      sink: "send_email",
      effects: EXTERNAL_EFFECTS,
      provenance: sources,
      consumes: sources.map((source, index) => ({
        provenanceId: source.id,
        argPath: `$.args.field_${index}`,
        match: index === 0 ? "exact" : "fuzzy",
      })),
    });

    expect(attempt.violations).toHaveLength(6);
    expect(attempt.violations[0].path).toMatchObject({ certainty: "observed", confidence: 1, verdict: "block" });
    expect(attempt.violations.filter((item) => item.path.certainty === "conservative")).toHaveLength(5);
  });

  it("chooses an observed or decoded route before a shorter higher-confidence conservative route", () => {
    const { graph, authorization } = emailGraph();
    const source = provenance("prov-route-source", { confidentiality: "secret" });
    const decodedMiddle = provenance("prov-route-decoded-middle", {
      parentIds: [source.id],
      confidentiality: "secret",
      transformations: ["encoded_exact"],
    });
    const decodedTail = provenance("prov-route-decoded-tail", {
      parentIds: [decodedMiddle.id],
      confidentiality: "secret",
      transformations: ["exact"],
    });
    const observedMiddle = provenance("prov-route-observed-middle", {
      parentIds: [source.id],
      confidentiality: "secret",
      transformations: ["exact"],
    });
    const observedTail = provenance("prov-route-observed-tail", {
      parentIds: [observedMiddle.id],
      confidentiality: "secret",
      transformations: ["exact"],
    });

    const attempt = beginSemanticAction(graph, {
      toolCallId: "competing-route-sink",
      tool: "send_email",
      originalTool: "send_email",
      authorization,
      sink: "send_email",
      effects: EXTERNAL_EFFECTS,
      provenance: [source, decodedMiddle, decodedTail, observedMiddle, observedTail],
      consumes: [
        {
          provenanceId: source.id,
          argPath: "$.args.short",
          match: "semantic",
          basis: "conservative",
          confidence: 1,
        },
        { provenanceId: decodedTail.id, argPath: "$.args.strong", match: "encoded_exact" },
        {
          provenanceId: observedTail.id,
          argPath: "$.args.observed",
          match: "exact",
          basis: "observed",
          confidence: 0.97,
        },
      ],
    });

    expect(attempt.violations).toHaveLength(1);
    const selected = attempt.violations[0].path;
    const middleNode = graph.nodes.find((node) => node.provenanceId === decodedMiddle.id);
    const tailNode = graph.nodes.find((node) => node.provenanceId === decodedTail.id);
    const lowerConfidenceNode = graph.nodes.find((node) => node.provenanceId === observedTail.id);
    expect(selected).toMatchObject({ certainty: "observed", confidence: 0.98, verdict: "block" });
    expect(selected.nodeIds).toContain(middleNode?.id);
    expect(selected.nodeIds).toContain(tailNode?.id);
    expect(selected.nodeIds).not.toContain(lowerConfidenceNode?.id);
    expect(selected.edgeIds.every((id) =>
      graph.edges.find((edge) => edge.id === id)?.basis !== "conservative"
    )).toBe(true);
  });

  it("records an unauthorized side effect as reviewable without retaining its raw target", () => {
    const graph = createSemanticActionGraph();
    const taskSpec = deriveTaskSpecV2("Summarize the quarterly report.", []);
    const intentId = activateSemanticIntent(graph, taskSpec);
    const authorization = authorizeCapability(taskSpec, {
      tool: "send_email",
      args: { recipient: "attacker@example.com", body: "summary" },
    });

    const attempt = beginSemanticAction(graph, {
      toolCallId: "unauthorized-side-effect",
      tool: "send_email",
      originalTool: "send_email",
      authorization,
      sink: "send_email",
      effects: { ...EXTERNAL_EFFECTS, sideEffect: true },
      provenance: [],
    });

    expect(authorization).toMatchObject({ action: "ask", authorized: false });
    expect(attempt.violations).toHaveLength(1);
    expect(attempt.violations[0]).toMatchObject({
      reason: "semantic action graph found a side effect without explicit capability authorization",
      path: {
        risk: "unauthorized_side_effect",
        verdict: "review",
        certainty: "observed",
        confidence: 1,
        sourceNodeId: intentId,
        actionNodeId: attempt.actionNodeId,
      },
    });
    expect(JSON.stringify(semanticActionGraphSnapshot(graph))).not.toContain("attacker@example.com");
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
  });

  it("records a target scope mismatch from capability to sink without raw targets", () => {
    const { taskSpec } = emailTask();
    const graph = createSemanticActionGraph();
    activateSemanticIntent(graph, taskSpec);
    const authorization = authorizeCapability(taskSpec, {
      tool: "send_email",
      args: { recipient: "attacker@example.com", body: "Quarterly report" },
    });

    const attempt = beginSemanticAction(graph, {
      toolCallId: "target-scope-mismatch",
      tool: "send_email",
      originalTool: "send_email",
      authorization,
      sink: "send_email",
      effects: { ...EXTERNAL_EFFECTS, sideEffect: true },
      provenance: [],
    });

    expect(authorization).toMatchObject({
      action: "deny",
      authorized: false,
      reason: "recipient_outside_authorization",
    });
    expect(attempt.violations).toHaveLength(1);
    const violation = attempt.violations[0];
    const capabilityNode = graph.nodes.find((node) => node.kind === "capability");
    expect(violation).toMatchObject({
      reason: "semantic action graph found an action target outside the authorized capability scope",
      path: {
        risk: "target_scope_mismatch",
        verdict: "block",
        certainty: "observed",
        confidence: 1,
        sourceNodeId: capabilityNode?.id,
        actionNodeId: attempt.actionNodeId,
      },
    });
    expect(graph.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({
        from: capabilityNode?.id,
        to: attempt.actionNodeId,
        kind: "constrains",
      }),
    ]));
    const snapshot = JSON.stringify(semanticActionGraphSnapshot(graph));
    expect(snapshot).not.toContain("attacker@example.com");
    expect(snapshot).not.toContain("teacher@example.edu");
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
  });

  it("adds produces edges only for successful actions", () => {
    const graph = createSemanticActionGraph();
    const input = provenance("prov-input");
    const succeeded = beginSemanticAction(graph, {
      toolCallId: "transform-success",
      tool: "summarize_text",
      originalTool: "summarize_text",
      authorization: READ_ONLY_AUTHORIZATION,
      sink: null,
      effects: NO_EFFECTS,
      provenance: [input],
      consumes: [{ provenanceId: input.id, argPath: "$.args.text" }],
    });
    const successOutput = provenance("prov-success-output", {
      parentIds: [input.id],
      transformations: ["summarize"],
    });
    expect(completeSemanticAction(graph, {
      toolCallId: "transform-success",
      tool: "summarize_text",
      status: "succeeded",
      produced: [successOutput],
      provenance: [input, successOutput],
    })).toBe(succeeded.actionNodeId);

    const failed = beginSemanticAction(graph, {
      toolCallId: "transform-failure",
      tool: "summarize_text",
      originalTool: "summarize_text",
      authorization: READ_ONLY_AUTHORIZATION,
      sink: null,
      effects: NO_EFFECTS,
      provenance: [],
    });
    const failedOutput = provenance("prov-failed-output");
    expect(completeSemanticAction(graph, {
      toolCallId: "transform-failure",
      tool: "summarize_text",
      status: "failed",
      produced: [failedOutput],
      provenance: [failedOutput],
    })).toBe(failed.actionNodeId);

    const successData = graph.nodes.find((node) => node.provenanceId === successOutput.id);
    expect(successData).toBeDefined();
    expect(graph.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ from: succeeded.actionNodeId, to: successData?.id, kind: "produces" }),
    ]));
    expect(graph.nodes.find((node) => node.id === succeeded.actionNodeId)?.status).toBe("succeeded");
    expect(graph.nodes.find((node) => node.id === failed.actionNodeId)?.status).toBe("failed");
    expect(graph.nodes.some((node) => node.provenanceId === failedOutput.id)).toBe(false);
    expect(graph.edges.some((edge) => edge.from === failed.actionNodeId && edge.kind === "produces")).toBe(false);
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
  });

  it("matches a result by raw tool alias when a call ID is unavailable", () => {
    const graph = createSemanticActionGraph();
    const attempt = beginSemanticAction(graph, {
      tool: "read_webpage",
      originalTool: "browser.open",
      authorization: READ_ONLY_AUTHORIZATION,
      sink: null,
      effects: NO_EFFECTS,
      provenance: [],
    });
    const output = provenance("prov-browser-output");

    expect(semanticActionResultContext(graph, { tool: "browser.open" })?.actionNodeId).toBe(attempt.actionNodeId);
    expect(completeSemanticAction(graph, {
      tool: "browser.open",
      status: "succeeded",
      produced: [output],
      provenance: [output],
    })).toBe(attempt.actionNodeId);

    const data = graph.nodes.find((node) => node.provenanceId === output.id);
    expect(graph.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ from: attempt.actionNodeId, to: data?.id, kind: "produces" }),
    ]));
    expect(semanticActionResultContext(graph, { tool: "browser.open" })).toBeNull();
    expect(graph.pendingCalls.size).toBe(0);
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
  });

  it("fails closed instead of guessing between ambiguous calls without IDs", () => {
    const graph = createSemanticActionGraph();
    const first = beginSemanticAction(graph, {
      tool: "summarize_text",
      originalTool: "summarize_text",
      authorization: READ_ONLY_AUTHORIZATION,
      sink: null,
      effects: NO_EFFECTS,
      provenance: [],
    });
    markSemanticActionEnforcement(graph, first.actionNodeId, { decision: "allow", status: "executing" });

    expect(() => beginSemanticAction(graph, {
      tool: "summarize_text",
      originalTool: "summarize_text",
      authorization: READ_ONLY_AUTHORIZATION,
      sink: null,
      effects: NO_EFFECTS,
      provenance: [],
    })).toThrow("ambiguous or duplicate semantic action call identity");

    completeSemanticAction(graph, { tool: "summarize_text", status: "succeeded" });
    expect(graph.nodes.find((node) => node.id === first.actionNodeId)?.status).toBe("succeeded");
  });

  it("retires an unenforced proposal before reusing a legacy no-ID tool key", () => {
    const graph = createSemanticActionGraph();
    const abandoned = beginSemanticAction(graph, {
      tool: "read_webpage",
      originalTool: "browser.open",
      authorization: READ_ONLY_AUTHORIZATION,
      sink: null,
      effects: NO_EFFECTS,
      provenance: [],
    });
    const replacement = beginSemanticAction(graph, {
      tool: "read_webpage",
      originalTool: "browser.open",
      authorization: READ_ONLY_AUTHORIZATION,
      sink: null,
      effects: NO_EFFECTS,
      provenance: [],
    });

    expect(graph.nodes.find((node) => node.id === abandoned.actionNodeId)?.status).toBe("failed");
    expect(semanticActionResultContext(graph, { tool: "browser.open" })?.actionNodeId).toBe(replacement.actionNodeId);
  });

  it("traces a long opaque tool chain without the old path-depth cutoff", () => {
    const { graph, authorization } = emailGraph();
    const source = provenance("prov-long-source", { confidentiality: "secret" });
    const sourceAction = beginSemanticAction(graph, {
      toolCallId: "long-source",
      tool: "read_webpage",
      originalTool: "read_webpage",
      authorization: READ_ONLY_AUTHORIZATION,
      sink: null,
      effects: NO_EFFECTS,
      provenance: [],
    });
    completeSemanticAction(graph, {
      toolCallId: "long-source",
      tool: "read_webpage",
      status: "succeeded",
      produced: [source],
      provenance: [source],
    });

    const provenanceNodes = [source];
    let previous = source;
    for (let index = 0; index < 14; index += 1) {
      const callId = `long-transform-${index}`;
      const attempt = beginSemanticAction(graph, {
        toolCallId: callId,
        tool: "summarize_text",
        originalTool: "summarize_text",
        authorization: READ_ONLY_AUTHORIZATION,
        sink: null,
        effects: NO_EFFECTS,
        provenance: provenanceNodes,
        consumes: [{ provenanceId: previous.id, argPath: "$.args.text", match: "exact" }],
      });
      const output = provenance(`prov-long-${index}`, {
        parentIds: [previous.id],
        confidentiality: "secret",
        transformations: [`tool:summarize_text:${index}`],
      });
      provenanceNodes.push(output);
      completeSemanticAction(graph, {
        toolCallId: callId,
        tool: "summarize_text",
        status: "succeeded",
        produced: [output],
        provenance: provenanceNodes,
      });
      expect(graph.nodes.find((node) => node.id === attempt.actionNodeId)?.status).toBe("succeeded");
      previous = output;
    }

    const sink = beginSemanticAction(graph, {
      toolCallId: "long-sink",
      tool: "send_email",
      originalTool: "send_email",
      authorization,
      sink: "send_email",
      effects: EXTERNAL_EFFECTS,
      provenance: provenanceNodes,
      consumes: [{ provenanceId: previous.id, argPath: "$.args.body", match: "exact" }],
    });

    expect(sink.violations).toHaveLength(1);
    expect(sink.violations[0].path.verdict).toBe("review");
    expect(sink.violations[0].path.certainty).toBe("conservative");
    expect(sink.violations[0].path.nodeIds.length).toBeGreaterThan(30);
    expect(sink.violations[0].path.steps.filter((step) => step.startsWith("action:"))).toHaveLength(16);
    expect(sink.violations[0].path.nodeIds[0]).toBe(sourceAction.actionNodeId);

    const snapshot = semanticActionGraphSnapshot(graph) as {
      nodes: Array<{ id: string }>;
      edges: Array<{ id: string }>;
      attack_paths: Array<{ nodeIds: string[]; edgeIds: string[] }>;
    };
    expect(snapshot.nodes.length).toBeLessThanOrEqual(36);
    expect(snapshot.edges.length).toBeLessThanOrEqual(40);
    expect(Buffer.byteLength(JSON.stringify(snapshot), "utf8")).toBeLessThanOrEqual(64 * 1024);
    const snapshotNodeIds = new Set(snapshot.nodes.map((node) => node.id));
    const snapshotEdgeIds = new Set(snapshot.edges.map((edge) => edge.id));
    expect(snapshot.attack_paths.every((path) =>
      path.nodeIds.every((id) => snapshotNodeIds.has(id))
      && path.edgeIds.every((id) => snapshotEdgeIds.has(id))
    )).toBe(true);
    expect(snapshotNodeIds.has(String((snapshot as { active_intent_id?: string }).active_intent_id || ""))).toBe(true);

    const judgeProjection = semanticActionGraphJudgeProjection(graph, 1600);
    const serializedJudgeProjection = JSON.stringify(judgeProjection);
    expect(Buffer.byteLength(serializedJudgeProjection, "utf8")).toBeLessThanOrEqual(1600);
    expect(serializedJudgeProjection).toContain("secret_to_external_sink");
    expect(serializedJudgeProjection).toContain("read_webpage");
    expect(serializedJudgeProjection).toContain("send_email");
    expect(judgeProjection).toMatchObject({ version: 2, projection_truncated: true });
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
  });

  it("keeps terminal lifecycle states stable across duplicate and late callbacks", () => {
    const graph = createSemanticActionGraph();
    const attempt = beginSemanticAction(graph, {
      toolCallId: "lifecycle-call",
      tool: "summarize_text",
      originalTool: "summarize_text",
      authorization: READ_ONLY_AUTHORIZATION,
      sink: null,
      effects: NO_EFFECTS,
      provenance: [],
    });
    markSemanticActionEnforcement(graph, attempt.actionNodeId, { decision: "allow", status: "executing" });
    expect(completeSemanticAction(graph, {
      toolCallId: "lifecycle-call",
      tool: "summarize_text",
      status: "succeeded",
    })).toBe(attempt.actionNodeId);

    markSemanticActionEnforcement(graph, attempt.actionNodeId, { decision: "deny", status: "blocked" });
    expect(completeSemanticAction(graph, {
      toolCallId: "lifecycle-call",
      tool: "summarize_text",
      status: "failed",
    })).toBe(attempt.actionNodeId);
    expect(graph.nodes.find((node) => node.id === attempt.actionNodeId)).toMatchObject({
      status: "succeeded",
      decision: "allow",
    });
    expect(graph.lifecycleAnomalies).toEqual(expect.arrayContaining([
      expect.objectContaining({ actionNodeId: attempt.actionNodeId, from: "succeeded", to: "blocked" }),
    ]));
    expect(graph.nodes.filter((node) => node.callIdHash).length).toBe(1);
  });

  it("records post-block execution as a separate observed action", () => {
    const { graph, authorization } = emailGraph();
    const source = provenance("prov-blocked-input", { confidentiality: "secret" });
    const blocked = beginSemanticAction(graph, {
      toolCallId: "blocked-but-ran",
      tool: "send_email",
      originalTool: "send_email",
      authorization,
      sink: "send_email",
      effects: EXTERNAL_EFFECTS,
      provenance: [source],
      consumes: [{ provenanceId: source.id, argPath: "$.args.body", match: "exact" }],
    });
    markSemanticActionEnforcement(graph, blocked.actionNodeId, { decision: "deny", status: "blocked" });
    const output = provenance("prov-blocked-output", { parentIds: [source.id], confidentiality: "secret" });

    expect(semanticActionResultContext(graph, {
      toolCallId: "blocked-but-ran",
      tool: "send_email",
    })?.consumedProvenanceIds).toContain(source.id);
    const observedId = completeSemanticAction(graph, {
      toolCallId: "blocked-but-ran",
      tool: "send_email",
      status: "succeeded",
      produced: [output],
      provenance: [source, output],
    });

    expect(observedId).not.toBe(blocked.actionNodeId);
    expect(graph.nodes.find((node) => node.id === blocked.actionNodeId)?.status).toBe("blocked");
    expect(graph.nodes.find((node) => node.id === observedId)).toMatchObject({
      status: "observed",
      synthetic: true,
      authorizationReason: "post_block_execution",
    });
    const sourceNode = graph.nodes.find((node) => node.provenanceId === source.id);
    expect(graph.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ from: sourceNode?.id, to: observedId, kind: "consumes" }),
      expect.objectContaining({ from: observedId, kind: "produces" }),
      expect.objectContaining({ from: observedId, kind: "targets" }),
    ]));
    expect(graph.lifecycleAnomalies).toEqual(expect.arrayContaining([
      expect.objectContaining({ actionNodeId: blocked.actionNodeId, from: "blocked", to: "succeeded" }),
    ]));
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
  });

  it("keeps a bounded graph valid after repeated path and edge pruning", () => {
    const { taskSpec, authorization } = emailTask();
    const graph = createSemanticActionGraph({ maxNodes: 8, maxEdges: 16, maxPaths: 4 });
    activateSemanticIntent(graph, taskSpec);

    for (let index = 0; index < 14; index += 1) {
      const source = provenance(`prov-pressure-${index}`, {
        confidentiality: "secret",
        source: `fixture-${index}`,
      });
      const attempt = beginSemanticAction(graph, {
        toolCallId: `pressure-call-${index}`,
        tool: "send_email",
        originalTool: "send_email",
        authorization,
        sink: "send_email",
        effects: EXTERNAL_EFFECTS,
        provenance: [source],
        consumes: [{ provenanceId: source.id, argPath: "$.args.body", match: "exact" }],
      });
      completeSemanticAction(graph, {
        toolCallId: `pressure-call-${index}`,
        tool: "send_email",
        status: "succeeded",
      });
      expect(graph.nodes.some((node) => node.id === attempt.actionNodeId) || graph.nodes.length === graph.limits.maxNodes).toBe(true);
    }

    expect(graph.nodes.length).toBeLessThanOrEqual(8);
    expect(graph.edges.length).toBeLessThanOrEqual(16);
    expect(graph.paths.length).toBeLessThanOrEqual(4);
    expect(new Set(graph.nodes.map((node) => node.id)).size).toBe(graph.nodes.length);
    expect(new Set(graph.edges.map((edge) => edge.id)).size).toBe(graph.edges.length);
    const nodeIds = new Set(graph.nodes.map((node) => node.id));
    expect(graph.edges.every((edge) => nodeIds.has(edge.from) && nodeIds.has(edge.to))).toBe(true);
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
  });

  it("protects pending-call input lineage while older edges are pruned", () => {
    const { taskSpec, authorization } = emailTask();
    const graph = createSemanticActionGraph({ maxNodes: 8, maxEdges: 16, maxPaths: 4 });
    activateSemanticIntent(graph, taskSpec);
    const source = provenance("prov-pending-pressure", { confidentiality: "secret" });
    const pending = beginSemanticAction(graph, {
      toolCallId: "pending-transform",
      tool: "summarize_text",
      originalTool: "summarize_text",
      authorization: READ_ONLY_AUTHORIZATION,
      sink: null,
      effects: NO_EFFECTS,
      provenance: [source],
      consumes: [{ provenanceId: source.id, argPath: "$.args.text", match: "exact" }],
    });
    markSemanticActionEnforcement(graph, pending.actionNodeId, { decision: "allow", status: "executing" });

    for (let index = 0; index < 20; index += 1) {
      const callId = `pressure-side-call-${index}`;
      const side = beginSemanticAction(graph, {
        toolCallId: callId,
        tool: "send_email",
        originalTool: "send_email",
        authorization,
        sink: "send_email",
        effects: EXTERNAL_EFFECTS,
        provenance: [],
      });
      markSemanticActionEnforcement(graph, side.actionNodeId, { decision: "allow", status: "executing" });
      completeSemanticAction(graph, { toolCallId: callId, tool: "send_email", status: "succeeded" });
    }

    expect(semanticActionResultContext(graph, {
      toolCallId: "pending-transform",
      tool: "summarize_text",
    })).toMatchObject({
      actionNodeId: pending.actionNodeId,
      consumedProvenanceIds: [source.id],
    });
    expect(graph.edges.length).toBeLessThanOrEqual(16);
    expect(() => validateSemanticActionGraph(graph)).not.toThrow();
  });
});
