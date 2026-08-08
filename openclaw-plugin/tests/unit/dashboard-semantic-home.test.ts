import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
// @ts-expect-error The dashboard adapter is a browser-native ES module served without a build step.
import { buildDashboardModel, causalPathTitles } from "../../public/graph-adapter.js";

const indexSource = readFileSync(new URL("../../public/index.html", import.meta.url), "utf8");

describe("semantic action graph homepage", () => {
  it("projects a real causal graph into typed security nodes and an explicit decision chain", () => {
    const model = buildDashboardModel({
      overview: {
        alerts: [{
          id: "decision-1",
          action: "BLOCK",
          severity: "CRITICAL",
          reason: "tool arguments carry secret-tainted data",
          rule: "TAINT_TO_EXTERNAL_SINK",
          score: 94,
          causal_graph: {
            version: 2,
            trace_kind: "attack",
            risk: "secret_to_external_sink",
            verdict: "block",
            certainty: "observed",
            confidence: 0.98,
            path_node_ids: ["action-read", "data-secret", "action-send", "sink-email"],
            path_edge_ids: ["returns", "uses", "targets"],
            nodes: [
              { id: "intent", kind: "intent", label: "user_task", sequence: 1 },
              { id: "capability", kind: "capability", label: "send:email", authorized: false, sequence: 2 },
              { id: "action-read", kind: "action", tool: "read_webpage", sequence: 3 },
              { id: "data-secret", kind: "data", path: "response.body", confidentiality: "secret", integrity: "tainted", sequence: 4 },
              { id: "action-send", kind: "action", tool: "send_email", status: "blocked", sequence: 5 },
              { id: "sink-email", kind: "sink", sink: "attacker.example", effect: "external", sequence: 6 },
            ],
            edges: [
              { id: "auth", from: "capability", to: "action-send", kind: "constrains" },
              { id: "returns", from: "action-read", to: "data-secret", kind: "produces", on_path: true, confidence: 1 },
              { id: "uses", from: "data-secret", to: "action-send", kind: "consumes", on_path: true, confidence: 0.98 },
              { id: "targets", from: "action-send", to: "sink-email", kind: "targets", on_path: true, confidence: 1 },
            ],
          },
        }],
      },
      records: [{
        id: "decision-1",
        session_key: "agent:demo:exfiltration",
        created_at: "2026-08-07T08:21:06.000Z",
        type: "tool_decision",
        severity: "danger",
        payload: { decision: "deny", toolName: "send_email" },
      }],
    });

    const session = model.sessions[0];
    expect(session.title).toBe("机密数据外传");
    expect(session.decision).toBe("deny");
    expect(session.graph.derived).not.toBe(true);
    expect(session.graph.nodes.map((node: { kind: string }) => node.kind)).toEqual(expect.arrayContaining([
      "intent", "capability", "secret", "action", "sink", "guard", "decision",
    ]));
    expect(session.graph.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ label: "uses", onPath: true }),
      expect.objectContaining({ label: "blocked-by", displayOnly: true }),
    ]));
    expect(causalPathTitles(session.graph).at(-1)).toBe("拒绝");
    expect(session.reasons.map((reason: { title: string }) => reason.title)).toEqual(expect.arrayContaining([
      "能力未获授权", "参数包含污染数据", "检测到敏感信息",
    ]));
  });

  it("derives a labeled projection for sessions that do not carry a backend causal graph", () => {
    const model = buildDashboardModel({
      records: [
        {
          id: "prompt",
          session_key: "agent:demo:normal",
          created_at: "2026-08-07T08:00:00.000Z",
          type: "lab_command",
          severity: "info",
          payload: { command: "读取项目说明" },
        },
        {
          id: "decision",
          session_key: "agent:demo:normal",
          created_at: "2026-08-07T08:00:01.000Z",
          type: "tool_decision",
          severity: "success",
          payload: { normalized_tool: "read_file", decision: "allow", task_spec: { allowed_tools: ["read_file"] } },
        },
      ],
    });

    const session = model.sessions[0];
    expect(session.decision).toBe("allow");
    expect(session.graph).toMatchObject({ derived: true, certainty: "projection", traceKind: "authorized" });
    expect(session.graph.nodes).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "intent" }),
      expect.objectContaining({ kind: "capability", authorized: true }),
      expect.objectContaining({ kind: "guard", displayOnly: true }),
      expect.objectContaining({ kind: "decision", state: "ALLOW" }),
    ]));
  });

  it("makes the incident context, causal graph, evidence inspector and replay rail the homepage structure", () => {
    for (const id of ["requestContext", "graphViewport", "graphNodes", "inspectorBody", "summaryMetrics", "timelineRange", "pathFocusBtn"]) {
      expect(indexSource).toContain(`id="${id}"`);
    }
    expect(indexSource).toContain("攻击因果图 / 语义行动图");
    expect(indexSource).toContain("对话 / 请求上下文");
    expect(indexSource).toContain("证据详情");
    expect(indexSource).toContain("事件时间线");
    expect(indexSource).not.toContain("id=\"statsGrid\"");
  });
});
