/**
 * graph-adapter.js
 * 把 dashboard 现有的 records / findings / tool calls / causal_graph
 * 统一映射成「语义动作图」模型 { nodes:[], edges:[] }，供 SemanticGraph 渲染。
 *
 * 设计目标（Phase-1）：
 *   ① 不改后端检测逻辑，只做前端数据归一化。
 *   ② 节点带语义类型 + 图标 + 裁决状态（allow/ask/deny）。
 *   ③ 边带语义标签，并用 onPath 标注真正的攻击因果链。
 *   ④ Allow / Ask / Deny 成为图的一部分（追加 decision 节点）。
 *
 * 该文件同时支持浏览器（挂到 window.GraphAdapter）与 Node/测试环境
 * （module.exports），方便 vitest 单测。
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && typeof module.exports === "object") {
    module.exports = api;
  }
  if (root) root.GraphAdapter = api;
})(typeof self !== "undefined" ? self : typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // 语义字典：节点类型 / 边类型 → 图标、中文标签、CSS 类
  // ---------------------------------------------------------------------------
  const NODE_KINDS = {
    intent:     { icon: "👤", label: "意图",   cls: "kind-intent" },
    capability: { icon: "🔑", label: "能力",   cls: "kind-capability" },
    agent:      { icon: "🤖", label: "智能体", cls: "kind-agent" },
    action:     { icon: "🔧", label: "动作",   cls: "kind-action" },
    data:       { icon: "📄", label: "数据",   cls: "kind-data" },
    tainted:    { icon: "☣️", label: "污染数据", cls: "kind-tainted" },
    secret:     { icon: "🔐", label: "机密",   cls: "kind-secret" },
    sink:       { icon: "🌐", label: "出口 Sink", cls: "kind-sink" },
    guard:      { icon: "🛡", label: "守卫",   cls: "kind-guard" },
    judge:      { icon: "⚖️", label: "裁决器", cls: "kind-judge" },
    decision:   { icon: "⚖️", label: "裁决",   cls: "kind-decision" },
    collapsed:  { icon: "⋯", label: "折叠段", cls: "kind-collapsed" },
  };

  const EDGE_LABELS = {
    declares: "声明", governs: "约束", authorizes: "授权", constrains: "范围限制",
    requests: "请求", consumes: "消费", produces: "产生", derives: "派生",
    targets: "指向", summary: "折叠展示",
    invokes: "调用", returns: "返回", "derived-from": "派生自", taints: "污染",
    uses: "使用", "writes-to": "写入", "sends-to": "发送",
    "blocked-by": "被阻断", "approved-by": "被批准", asks: "需审批", verdict: "裁决",
  };

  const RISK_LABELS = {
    secret_to_external_sink: "机密数据 → 外部出口",
    tainted_to_external_sink: "污染指令 → 外部出口",
    secret_to_persistent_state: "机密数据 → 持久状态",
    tainted_to_persistent_state: "污染指令 → 持久状态",
    secret_to_execution: "机密数据 → 进程执行",
    tainted_to_execution: "污染指令 → 进程执行",
    unauthorized_side_effect: "未授权能力 → 外部副作用",
    target_scope_mismatch: "授权范围 → 目标越界",
    authorized_tool_execution: "显式授权 → 正常执行",
    execution_after_block: "已阻断 → 仍然执行",
  };

  const DECISION_META = {
    allow: { icon: "✅", label: "已放行", cls: "verdict-allow" },
    ask: { icon: "🟡", label: "需审批", cls: "verdict-ask" },
    deny: { icon: "⛔", label: "已阻断", cls: "verdict-deny" },
  };

  // ---------------------------------------------------------------------------
  // 小工具
  // ---------------------------------------------------------------------------
  function asString(value, limit) {
    const text = typeof value === "string" ? value : value === undefined || value === null ? "" : String(value);
    const cleaned = text.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
    return limit ? cleaned.slice(0, limit) : cleaned;
  }

  function nodeTitle(node) {
    if (!node) return "node";
    const kind = node.kind;
    if (kind === "action") return asString(node.tool || node.label, 96) || "unknown_tool";
    if (kind === "data") return asString(node.path || node.label, 96) || "data_field";
    if (kind === "sink") return asString(node.sink || node.label, 96) || "sink";
    if (kind === "collapsed") return `中间 ${Number(node.omitted_node_count) || 0} 个已验证节点`;
    return asString(node.label, 96) || asString(kind, 24) || "node";
  }

  function nodeStateText(node) {
    if (!node) return "";
    const kind = node.kind;
    if (kind === "capability") return node.authorized === true ? "已授权" : "未授权";
    if (kind === "data") {
      if (node.confidentiality === "secret") return "SECRET";
      if (node.integrity === "tainted") return "TAINTED";
    }
    if (kind === "action") return asString(node.status || node.decision, 32) || "proposed";
    if (kind === "collapsed") return "DISPLAY ONLY";
    return asString(node.effect, 48);
  }

  function normalizeDecision(raw) {
    const value = asString(raw, 24).toLowerCase();
    if (["allow", "allowed", "approve", "approved", "pass", "success"].includes(value)) return "allow";
    if (["ask", "review", "require_approval", "pending", "approval"].includes(value)) return "ask";
    if (["deny", "denied", "block", "blocked", "reject"].includes(value)) return "deny";
    return "";
  }

  // 从原始 causal_graph 节点 → 语义节点
  function displayKind(node) {
    const kind = asString(node && node.kind, 24);
    if (kind === "data") {
      if (node.confidentiality === "secret") return "secret";
      if (node.integrity === "tainted") return "tainted";
      return "data";
    }
    if (NODE_KINDS[kind]) return kind;
    return "data";
  }

  function mapNode(raw, pathSet) {
    const kind = displayKind(raw);
    const meta = NODE_KINDS[kind] || NODE_KINDS.data;
    const id = asString(raw.id, 96);
    return {
      id,
      kind,
      icon: meta.icon,
      kindLabel: meta.label,
      cls: meta.cls,
      label: nodeTitle(raw),
      stateText: nodeStateText(raw),
      decision: normalizeDecision(raw.decision),
      status: asString(raw.status, 32),
      onPath: pathSet.has(id),
      confidential: raw.confidentiality === "secret",
      tainted: raw.integrity === "tainted",
      raw,
    };
  }

  function mapEdge(raw, pathEdgeSet) {
    const kind = asString(raw.kind, 32);
    const id = asString(raw.id, 96);
    return {
      id,
      source: asString(raw.from, 96),
      target: asString(raw.to, 96),
      kind,
      label: EDGE_LABELS[kind] || kind || "流转",
      onPath: raw.on_path === true || pathEdgeSet.has(id),
      basis: asString(raw.basis, 24) || "observed",
      confidence: Math.max(0, Math.min(1, Number(raw.confidence) || 0)),
      synthetic: raw.synthetic === true || raw.display_only === true,
      raw,
    };
  }

  // ---------------------------------------------------------------------------
  // 主入口：alert.causal_graph → SemanticGraph
  // ---------------------------------------------------------------------------
  function mapCausalGraph(cg, alert) {
    const rawNodes = Array.isArray(cg.nodes) ? cg.nodes.filter(Boolean) : [];
    const rawEdges = Array.isArray(cg.edges) ? cg.edges.filter(Boolean) : [];
    const pathNodeIds = (Array.isArray(cg.path_node_ids) ? cg.path_node_ids : []).map(String);
    const pathEdgeIds = (Array.isArray(cg.path_edge_ids) ? cg.path_edge_ids : []).map(String);
    const pathNodeSet = new Set(pathNodeIds);
    const pathEdgeSet = new Set(pathEdgeIds);

    const nodes = rawNodes.map((n) => mapNode(n, pathNodeSet));
    const nodeIds = new Set(nodes.map((n) => n.id));
    const edges = rawEdges
      .filter((e) => nodeIds.has(asString(e.from, 96)) && nodeIds.has(asString(e.to, 96)))
      .map((e) => mapEdge(e, pathEdgeSet));

    // 追加 decision 节点：把 Allow / Ask / Deny 变成图的一部分。
    const verdict = normalizeDecision(alert && (alert.action || alert.decision)) || normalizeDecision(cg.verdict);
    if (verdict) {
      const decisionId = `__decision__:${asString(alert && alert.id, 48) || "alert"}`;
      const dmeta = DECISION_META[verdict];
      const lastPathNode = [...pathNodeIds].reverse().find((id) => nodeIds.has(id));
      nodes.push({
        id: decisionId,
        kind: "decision",
        icon: dmeta.icon,
        kindLabel: "裁决",
        cls: `kind-decision ${dmeta.cls}`,
        label: dmeta.label,
        stateText: riskLabel(cg.risk),
        decision: verdict,
        status: verdict,
        onPath: Boolean(lastPathNode),
        confidential: false,
        tainted: false,
        raw: { decision: verdict, risk: cg.risk, verdict: cg.verdict },
      });
      if (lastPathNode) {
        const edgeKind = verdict === "deny" ? "blocked-by" : verdict === "ask" ? "asks" : "approved-by";
        edges.push({
          id: `__decision-edge__:${decisionId}`,
          source: lastPathNode,
          target: decisionId,
          kind: edgeKind,
          label: EDGE_LABELS[edgeKind],
          onPath: true,
          basis: "observed",
          confidence: 1,
          synthetic: false,
          raw: {},
        });
        pathNodeSet.add(decisionId);
      }
    }

    return {
      nodes,
      edges,
      pathNodeIds: [...pathNodeSet],
      meta: {
        risk: asString(cg.risk, 48),
        riskLabel: riskLabel(cg.risk),
        verdict: asString(cg.verdict, 24),
        traceKind: asString(cg.trace_kind, 32),
        confidence: Number(cg.confidence) || 0,
        certainty: asString(cg.certainty, 24),
        alertId: asString(alert && alert.id, 48),
        attackType: asString(alert && alert.type, 64),
        reason: asString(alert && alert.reason, 200),
        rule: asString(alert && alert.rule, 120),
      },
    };
  }

  // 没有 causal_graph 时的兜底：从 alert 自身合成一条最短因果链。
  function synthesizeFromAlert(alert) {
    const decision = normalizeDecision(alert && (alert.action || alert.decision)) || "deny";
    const dmeta = DECISION_META[decision];
    const tool = asString(alert && alert.tool, 64) || "工具调用";
    const nodes = [
      { id: "intent", kind: "intent", icon: NODE_KINDS.intent.icon, kindLabel: NODE_KINDS.intent.label, cls: NODE_KINDS.intent.cls, label: "用户任务", stateText: "上下文输入", decision: "", status: "", onPath: true, confidential: false, tainted: false, raw: {} },
      { id: "action", kind: "action", icon: NODE_KINDS.action.icon, kindLabel: NODE_KINDS.action.label, cls: NODE_KINDS.action.cls, label: tool, stateText: asString(alert && alert.reason, 48), decision, status: "", onPath: true, confidential: false, tainted: false, raw: {} },
      { id: "decision", kind: "decision", icon: dmeta.icon, kindLabel: "裁决", cls: `kind-decision ${dmeta.cls}`, label: dmeta.label, stateText: riskLabel(""), decision, status: decision, onPath: true, confidential: false, tainted: false, raw: {} },
    ];
    const edges = [
      { id: "e1", source: "intent", target: "action", kind: "invokes", label: EDGE_LABELS.invokes, onPath: true, basis: "observed", confidence: 0.6, synthetic: true, raw: {} },
      { id: "e2", source: "action", target: "decision", kind: decision === "deny" ? "blocked-by" : decision === "ask" ? "asks" : "approved-by", label: decision === "deny" ? EDGE_LABELS["blocked-by"] : decision === "ask" ? EDGE_LABELS.asks : EDGE_LABELS["approved-by"], onPath: true, basis: "observed", confidence: 1, synthetic: false, raw: {} },
    ];
    return {
      nodes,
      edges,
      pathNodeIds: ["intent", "action", "decision"],
      meta: {
        risk: "", riskLabel: asString(alert && alert.type, 64) || "运行风险事件",
        verdict: decision, traceKind: "attack", confidence: 0.5, certainty: "inferred",
        alertId: asString(alert && alert.id, 48), attackType: asString(alert && alert.type, 64),
        reason: asString(alert && alert.reason, 200), rule: asString(alert && alert.rule, 120),
      },
    };
  }

  function fromAlert(alert) {
    const cg = alert && typeof alert.causal_graph === "object" ? alert.causal_graph : null;
    if (cg && Array.isArray(cg.nodes) && cg.nodes.length >= 2) return mapCausalGraph(cg, alert);
    if (alert) return synthesizeFromAlert(alert);
    return null;
  }

  function riskLabel(risk) {
    return RISK_LABELS[asString(risk, 48)] || asString(risk, 48) || "跨工具数据流";
  }

  // ---------------------------------------------------------------------------
  // Session 故事列表：records → 叙事卡片
  // ---------------------------------------------------------------------------
  function buildSessions(records) {
    const list = Array.isArray(records) ? records : [];
    const groups = new Map();
    for (const record of list) {
      const key = record.session_key || "session_unknown";
      const item = groups.get(key) || { key, count: 0, latest: record.created_at, danger: 0, warning: 0, alerts: 0, toolCalls: 0, blocked: 0, asked: 0, secret: false };
      item.count += 1;
      if (new Date(record.created_at) > new Date(item.latest)) item.latest = record.created_at;
      if (record.severity === "danger") item.danger += 1;
      if (record.severity === "warning") item.warning += 1;
      if (record.type === "alert") item.alerts += 1;
      if (record.type === "tool_decision" || record.type === "tool_result") item.toolCalls += 1;
      const decision = normalizeDecision(record.decision || (record.payload && record.payload.decision));
      if (decision === "deny") item.blocked += 1;
      if (decision === "ask") item.asked += 1;
      const text = `${record.title || ""} ${record.summary || ""}`.toLowerCase();
      if (/secret|credential|\.env|token/.test(text)) item.secret = true;
      groups.set(key, item);
    }
    return [...groups.values()]
      .map((session) => ({ ...session, story: sessionStory(session) }))
      .sort((a, b) => new Date(b.latest) - new Date(a.latest));
  }

  function sessionStory(session) {
    const time = formatTime(session.latest);
    const actions = session.count;
    if (session.blocked && session.secret) return { icon: "🔴", tone: "danger", title: "敏感数据外泄", verdict: "DENIED", time, actions };
    if (session.blocked) return { icon: "🔴", tone: "danger", title: "高风险工具被拦截", verdict: "DENIED", time, actions };
    if (session.asked) return { icon: "🟡", tone: "warning", title: "待人工审批", verdict: "ASK", time, actions };
    if (session.alerts) return { icon: "🟠", tone: "warning", title: "触发安全告警", verdict: "ALERT", time, actions };
    if (session.danger) return { icon: "🟠", tone: "warning", title: "存在高危事件", verdict: "RISK", time, actions };
    return { icon: "🟢", tone: "success", title: "正常业务会话", verdict: "ALLOWED", time, actions };
  }

  function formatTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "--:--";
    const pad = (n) => String(n).padStart(2, "0");
    return `${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  // ---------------------------------------------------------------------------
  // 时间轴：records → 有序事件序列（供回放）
  // ---------------------------------------------------------------------------
  function buildTimeline(records) {
    const list = Array.isArray(records) ? records : [];
    return list
      .slice()
      .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
      .map((record, index) => ({
        index,
        id: record.id,
        time: record.created_at,
        type: record.type,
        severity: record.severity,
        title: record.title || record.type,
        decision: normalizeDecision(record.decision || (record.payload && record.payload.decision)),
      }));
  }

  return {
    NODE_KINDS,
    EDGE_LABELS,
    RISK_LABELS,
    DECISION_META,
    fromAlert,
    mapCausalGraph,
    synthesizeFromAlert,
    buildSessions,
    buildTimeline,
    riskLabel,
    normalizeDecision,
    nodeTitle,
    displayKind,
    formatTime,
  };
});
