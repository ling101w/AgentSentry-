import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
// @ts-expect-error The dashboard adapter is a browser-native ES module served without a build step.
import { buildDashboardModel, buildIncidentConclusion, buildSelectionEvidence, causalPathTitles, primaryPathGraph } from "../../public/graph-adapter.js";

const indexSource = readFileSync(new URL("../../public/index.html", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../../public/app.js", import.meta.url), "utf8");
const graphSource = readFileSync(new URL("../../public/semantic-graph.js", import.meta.url), "utf8");
const dashboardSource = readFileSync(new URL("../../public/dashboard.js", import.meta.url), "utf8");
const dashboardStylesSource = readFileSync(new URL("../../public/dashboard.css", import.meta.url), "utf8");

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
            path_node_ids: ["action-read", "data-prompt", "data-secret", "action-send", "sink-email"],
            path_edge_ids: ["returns", "derives", "uses", "targets"],
            nodes: [
              { id: "intent", kind: "intent", label: "user_task", sequence: 1 },
              { id: "capability", kind: "capability", label: "send:email", authorized: false, sequence: 2 },
              { id: "action-read", kind: "action", tool: "read_webpage", sequence: 3 },
              { id: "data-prompt", kind: "data", path: "response.body.hidden_prompt", confidentiality: "public", integrity: "tainted", sequence: 4 },
              { id: "data-secret", kind: "data", path: "response.body", confidentiality: "secret", integrity: "tainted", sequence: 5 },
              { id: "action-send", kind: "action", tool: "send_email", status: "blocked", sequence: 6 },
              { id: "sink-email", kind: "sink", sink: "attacker.example", effect: "external", sequence: 7 },
              { id: "support-agent", kind: "agent", label: "background planning", sequence: 2 },
            ],
            edges: [
              { id: "support", from: "intent", to: "support-agent", kind: "requests" },
              { id: "auth", from: "capability", to: "action-send", kind: "constrains" },
              { id: "returns", from: "action-read", to: "data-prompt", kind: "produces", on_path: true, confidence: 1 },
              { id: "derives", from: "data-prompt", to: "data-secret", kind: "derives", on_path: true, confidence: 0.98 },
              { id: "uses", from: "data-secret", to: "action-send", kind: "consumes", arg_path: "$.args.body", on_path: true, confidence: 0.98 },
              { id: "targets", from: "action-send", to: "sink-email", kind: "targets", on_path: true, confidence: 1 },
            ],
          },
        }],
      },
      records: [
        {
          id: "web-result",
          session_key: "agent:demo:exfiltration",
          created_at: "2026-08-07T08:21:04.000Z",
          type: "tool_result",
          severity: "warning",
          payload: { toolName: "read_webpage", preview: "Ignore previous instructions" },
        },
        {
          id: "decision-1",
          session_key: "agent:demo:exfiltration",
          created_at: "2026-08-07T08:21:06.000Z",
          type: "tool_decision",
          severity: "danger",
          payload: { decision: "deny", toolName: "send_email" },
        },
      ],
    });

    const session = model.sessions[0];
    expect(session.title).toBe("机密数据外传");
    expect(session.decision).toBe("deny");
    expect(session.graph.derived).not.toBe(true);
    expect(session.graph.nodes.map((node: { kind: string }) => node.kind)).toEqual(expect.arrayContaining([
      "intent", "capability", "secret", "action", "sink", "guard", "decision",
    ]));
    expect(session.graph.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ label: "使用数据", onPath: true }),
      expect.objectContaining({ label: "策略阻断", displayOnly: true }),
    ]));
    expect(causalPathTitles(session.graph).at(-1)).toBe("阻断");
    expect(session.reasons.map((reason: { title: string }) => reason.title)).toEqual(expect.arrayContaining([
      "能力未获授权", "参数包含污染数据", "检测到敏感信息",
    ]));

    const edge = session.graph.edges.find((item: { id: string }) => item.id === "uses");
    const edgeEvidence = buildSelectionEvidence(session, { type: "edge", value: edge });
    expect(edgeEvidence).toMatchObject({
      type: "edge",
      id: "uses",
      kindLabel: "语义关系",
      title: "使用数据",
      state: "攻击路径",
      records: [expect.objectContaining({ id: "decision-1" })],
    });
    expect(edgeEvidence.subtitle).toContain("敏感数据");
    expect(edgeEvidence.subtitle).toContain("工具动作");
    expect(edgeEvidence.facts).toEqual(expect.arrayContaining([
      expect.objectContaining({ label: "目标参数", value: "$.args.body" }),
      expect.objectContaining({ label: "置信度", value: "98%" }),
    ]));
    expect(edgeEvidence.policies).toContain("TAINT_TO_EXTERNAL_SINK");
    expect(session.timeline[0]).toEqual(expect.objectContaining({ nodeId: expect.any(String), revealSequence: expect.any(Number) }));
    expect(session.timeline.find((event: { id: string }) => event.id === "web-result")).toMatchObject({
      nodeId: "data-prompt",
      stage: "Prompt 注入",
    });

    const conclusion = buildIncidentConclusion(session);
    expect(conclusion).toMatchObject({
      severity: "高危",
      attackType: "Prompt Injection",
      result: "未发生数据泄露",
      policy: "TAINT_TO_EXTERNAL_SINK",
      target: "attacker.example",
      tone: "safe",
    });
    expect(conclusion.summary).toContain("已被 TAINT_TO_EXTERNAL_SINK 阻断");

    const primaryGraph = primaryPathGraph(session.graph);
    expect(primaryGraph.primaryView).toBe(true);
    expect(primaryGraph.nodes.some((node: { id: string }) => node.id === "support-agent")).toBe(false);
    expect(primaryGraph.nodes.some((node: { id: string }) => node.id === "capability")).toBe(false);
    expect(primaryGraph.edges.some((edgeValue: { id: string }) => edgeValue.id === "support")).toBe(false);
    expect(primaryGraph.nodes.length).toBeLessThan(session.graph.nodes.length);
  });

  it("does not mislabel a capability review as Prompt Injection", () => {
    const model = buildDashboardModel({
      overview: {
        alerts: [{
          id: "review-decision",
          action: "ASK",
          severity: "MEDIUM",
          time: "08:10:03",
          reason: "recipient is outside the current TaskSpec target scope",
          rule: "CAPABILITY_SCOPE_DENIED",
        }],
      },
      records: [
        {
          id: "review-user",
          session_key: "agent:demo:review",
          created_at: "2026-08-07T08:10:00.000Z",
          type: "lab_command",
          severity: "info",
          payload: { command: "生成周报并准备邮件" },
        },
        {
          id: "review-decision",
          session_key: "agent:demo:review",
          created_at: "2026-08-07T08:10:03.000Z",
          type: "approval_request",
          severity: "warning",
          payload: {
            normalized_tool: "send_email",
            decision: "ask",
            reason: "recipient is outside the current TaskSpec target scope",
            task_spec: { allowed_tools: ["send_email"], allowed_targets: ["team@example.test"] },
          },
        },
      ],
    });

    expect(model.sessions[0].requestContext).toMatchObject({
      attackDetected: true,
      promptInjectionDetected: false,
      detectionTime: "2026-08-07T08:10:03.000Z",
      detectionType: "授权范围待确认",
    });
    expect(buildIncidentConclusion(model.sessions[0]).attackType).toBe("未授权工具调用");
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

  it("keeps the event list and incident investigation as one monitor workflow", () => {
    for (const id of ["attackSessionsView", "attackSessionList", "attackSearch", "backToSessions"]) {
      expect(indexSource).toContain(`id="${id}"`);
    }
    for (const id of ["attackDetailView", "detailConclusionType", "detailRequestContext", "semanticViewport", "semanticNodes", "semanticInspector", "incidentTimeline", "graphPathButton", "graphResetButton"]) {
      expect(indexSource).toContain(`id="${id}"`);
    }
    expect(indexSource).toContain("攻击类型 / 用户任务");
    expect(indexSource).toContain("攻击结果");
    expect(indexSource).toContain("玄鉴裁决");
    expect(dashboardSource).toContain("function renderAttackSessions()");
    expect(dashboardSource).toContain("function openAttackSession(id)");
    expect(dashboardSource).toContain('attackSubview: new URLSearchParams(window.location.search).has("session") ? "detail" : "sessions"');
    expect(dashboardSource).toContain("window.history.pushState");
    expect(indexSource).toContain("核心结论");
    expect(indexSource).toContain("语义动作图");
    expect(indexSource).toContain("请求上下文");
    for (const className of ["context-conversation", "context-message-user", "context-message-model", "context-capabilities", "attack-detection-summary", "context-payload-label"]) {
      expect(dashboardSource).toContain(className);
    }
    expect(dashboardSource).toContain("SECURITY VERDICT");
    expect(dashboardSource).toContain("PAYLOAD EVIDENCE");
    expect(dashboardStylesSource).toContain(".context-message-model .context-message-body");
    expect(dashboardStylesSource).toContain(".context-meta>span:last-child");
    expect(indexSource).toContain("证据详情");
    expect(indexSource).toContain("会话处理时间线");
    expect(indexSource).toContain('class="dashboard-brand-logo"');
    expect(indexSource).toContain('alt="玄鉴 AgentSentry"');
    expect(indexSource).toContain('aria-label="主导航"');
    expect(indexSource).toContain("智能体行为安全裁决系统");
    expect(indexSource).toContain("Agent Security Controls");
    expect(indexSource).toContain("用控流、控权、控态三条主线约束数据流、能力边界与执行状态");
    for (const control of ["控流", "控权", "控态", "数据从哪里来", "用户究竟授权了什么", "是否仍在合法生命周期"]) {
      expect(indexSource).toContain(control);
    }
    for (const key of ["taint", "auth", "state"]) {
      expect(indexSource).toContain(`data-risk-surface="${key}"`);
      expect(indexSource).toContain(`data-control-line="${key}"`);
    }
    expect(dashboardSource).toContain("function classifyControlLines(session)");
    expect(dashboardSource).toContain("function buildControlLineSummary()");
    expect(dashboardSource).toContain("classifyControlLines(session).forEach");
    expect(indexSource).toContain('class="control-rails"');
    expect(indexSource).toContain('class="control-rail rail-taint');
    expect(indexSource).toContain('class="control-rail rail-auth');
    expect(indexSource).toContain('class="control-rail rail-state');
    expect(indexSource).toContain("三条主线并行判定");
    expect(indexSource).not.toContain("control-graph-lines");
    expect(indexSource).not.toContain("control-center-label");
    expect(indexSource).not.toContain('data-risk-surface="injection"');
    expect(indexSource).not.toContain('data-risk-surface="persistence"');
    expect(indexSource).not.toContain('data-risk-surface="hijack"');
    expect(dashboardSource).toContain("function buildSemanticLayout(nodes, viewportWidth)");
    expect(dashboardSource).toContain("applySemanticCanvasStyles()");
    expect(dashboardStylesSource).toContain("width:var(--semantic-node-width,188px)");
    expect(dashboardStylesSource).toContain(".semantic-edge-group.tone-danger path{stroke:#df6a5b;stroke-width:1.8}");
    expect(indexSource).not.toContain("v1.2.0");
  });

  it("keeps capability inventory as the single tools entry point", () => {
    expect(indexSource).not.toContain('data-page="assets"');
    expect(indexSource).not.toContain('data-page="policy"');
    expect(indexSource).not.toContain('id="profileSelect"');
    expect(indexSource).not.toContain('id="page-assets"');
    expect(indexSource).not.toContain('id="page-policy"');
    expect(indexSource).toContain('id="capabilityInventoryGrid"');
    for (const label of ["登记工具", "MCP 工具", "Skill", "会话记忆"]) {
      expect(dashboardSource).toContain(`label: "${label}"`);
    }
    expect(dashboardSource).toContain('["能力资产",capabilityTotal');
    expect(indexSource).toContain('<div class="tool-table-head"><span>工具</span><span>风险</span><span>副作用</span><span>智能体</span><span>24h</span><span>完整性</span><span></span></div>');
    expect(indexSource).not.toContain('<div class="tool-table-head"><span>工具</span><span>风险</span><span>来源</span>');
    expect(dashboardSource).not.toContain('<span class="tool-source">');
    expect(dashboardSource).toContain('<span class="side-effect-tags">');
  });

  it("keeps graph selections stable and reserves edge labels for edge interaction", () => {
    expect(appSource).toContain("selectedEdgeId, preserveTransform: true");
    expect(appSource).toContain("primaryPathGraph(graph)");
    expect(appSource).toContain("selectionKeyFacts(evidence, session)");
    expect(appSource).toContain("openSelectedTrace");
    expect(graphSource).toContain('event.target.closest(".semantic-edge-group")');
    expect(graphSource).toContain('labelHit.setAttribute("class", "semantic-edge-label-hit")');
    expect(graphSource).toContain('labelHit.addEventListener("pointerdown", reserveEdgePointer)');
    expect(graphSource).toContain("placeEdgeLabel(geometry");
    expect(graphSource).toContain("|| this.nodeDrag");
    expect(graphSource).toContain("resetLayout()");
    expect(graphSource).toContain("window.localStorage.removeItem(manualLayoutStorageKey(key))");
  });
});
