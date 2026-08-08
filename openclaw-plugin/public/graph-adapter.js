const DECISION_ORDER = { deny: 4, ask: 3, allow: 2, info: 1 };
const SEVERITY_ORDER = { critical: 5, high: 4, danger: 4, medium: 3, warning: 3, info: 1, success: 0 };

const TOOL_LABELS = {
  agents_list: "列出 Agent",
  read_webpage: "读取网页",
  browser_open: "打开网页",
  call_api: "调用 API",
  read_file: "读取文件",
  write_file: "写入文件",
  send_email: "发送邮件",
  shell_exec: "执行命令",
  memory_read: "读取记忆",
  memory_write: "写入记忆",
};

const TYPE_LABELS = {
  session_start: "会话开始",
  lab_command: "用户指令",
  provenance_scan: "溯源扫描",
  llm_input: "模型输入",
  message_write: "消息写入",
  tool_decision: "工具裁决",
  tool_result: "工具返回",
  guard_finding: "安全发现",
  alert: "告警",
  approval_request: "等待审批",
  approval_resolution: "审批结果",
  response_cover: "响应覆盖",
  runtime: "运行时事件",
};

const RISK_LABELS = {
  secret_to_external_sink: "机密数据外传",
  tainted_to_external_sink: "污染指令外传",
  secret_to_persistent_state: "机密写入持久状态",
  tainted_to_persistent_state: "污染记忆持久化",
  secret_to_execution: "机密流向代码执行",
  tainted_to_execution: "污染指令触发执行",
  unauthorized_side_effect: "未授权外部副作用",
  target_scope_mismatch: "授权目标越界",
  authorized_tool_execution: "精确授权执行",
  execution_after_block: "阻断后仍执行",
};

const KIND_LABELS = {
  intent: "Intent",
  capability: "Capability",
  agent: "Agent",
  action: "Action",
  data: "Data",
  taint: "Tainted Data",
  secret: "Secret",
  sink: "Sink",
  guard: "Guard",
  judge: "Judge",
  decision: "Decision",
  collapsed: "Collapsed",
};

const KIND_ICONS = {
  intent: "message-square-text",
  capability: "key-round",
  agent: "bot",
  action: "wrench",
  data: "database",
  taint: "shield-alert",
  secret: "lock-keyhole",
  sink: "radio-tower",
  guard: "shield-check",
  judge: "scale",
  decision: "gavel",
  collapsed: "ellipsis",
};

const EXTERNAL_TOOLS = new Set(["send_email", "call_api", "write_file", "shell_exec", "memory_write"]);

export function buildDashboardModel({ overview = {}, records = [] } = {}) {
  const safeRecords = Array.isArray(records) ? records.filter(isObject) : [];
  const alerts = Array.isArray(overview?.alerts) ? overview.alerts.filter(isObject).map(normalizeAlert) : [];
  const recordById = new Map(safeRecords.map((record) => [String(record.id || ""), record]));
  const groups = new Map();

  for (const record of safeRecords) {
    const key = String(record.session_key || record.run_id || "session_unknown");
    if (!groups.has(key)) groups.set(key, { id: key, records: [], alerts: [] });
    groups.get(key).records.push(record);
  }

  for (const alert of alerts) {
    const record = recordById.get(alert.id);
    const key = String(record?.session_key || record?.run_id || `alert:${alert.id}`);
    if (!groups.has(key)) groups.set(key, { id: key, records: [], alerts: [] });
    groups.get(key).alerts.push({ ...alert, record });
  }

  const sessions = [...groups.values()]
    .map(buildSession)
    .sort((left, right) => {
      const decisionDelta = DECISION_ORDER[right.decision] - DECISION_ORDER[left.decision];
      if (decisionDelta && right.isRecentRisk && left.isRecentRisk) return decisionDelta;
      return right.latestMs - left.latestMs;
    });

  const source = isObject(overview?.source) ? overview.source : {};
  return {
    sessions,
    generatedAt: String(overview?.generated_at || ""),
    protectionIndex: clampNumber(overview?.protectionIndex, 0, 100),
    source: {
      label: source.primary || "OpenClaw plugin records",
      totalRecords: numberOr(source.total_records, safeRecords.length),
      windowRecords: numberOr(source.window_records, safeRecords.length),
      available: source.openclaw_available !== false,
    },
  };
}

function buildSession(group) {
  const records = group.records.slice().sort(compareCreatedAsc);
  const alerts = group.alerts.slice().sort(compareAlertPriority);
  const primaryAlert = alerts[0] || alertFromRecords(records);
  const graph = primaryAlert?.causalGraph
    ? normalizeCausalGraph(primaryAlert.causalGraph, primaryAlert, primaryAlert.record)
    : deriveGraphFromRecords(records, primaryAlert);
  const decision = primaryAlert?.decision || decisionFromRecords(records);
  const severity = primaryAlert?.severity || severityFromRecords(records);
  const latest = records.at(-1)?.created_at || primaryAlert?.createdAt || "";
  const latestMs = dateMs(latest);
  const actionCount = graph.nodes.filter((node) => node.kind === "action").length;
  const timeline = buildTimeline(records, primaryAlert);
  const policies = policyList(primaryAlert, records);

  return {
    id: group.id,
    title: sessionTitle(group.id, primaryAlert, graph, records),
    subtitle: sessionSubtitle(primaryAlert, graph, records),
    decision,
    decisionLabel: decisionLabel(decision),
    severity,
    tone: decision === "deny" ? "danger" : decision === "ask" ? "warning" : severity === "high" || severity === "critical" ? "danger" : "safe",
    latest,
    latestMs,
    isRecentRisk: latestMs > Date.now() - 24 * 60 * 60 * 1000 && decision !== "allow",
    actionCount,
    recordCount: records.length,
    records,
    alerts,
    alert: primaryAlert || null,
    graph,
    timeline,
    policies,
    reasons: buildWhyReasons({ alert: primaryAlert, graph, records }),
  };
}

function normalizeAlert(raw) {
  return {
    ...raw,
    id: String(raw.id || ""),
    decision: normalizeDecision(raw.action || raw.decision),
    severity: normalizeSeverity(raw.severity),
    causalGraph: isObject(raw.causal_graph) ? raw.causal_graph : null,
    causalChain: Array.isArray(raw.causal_chain) ? raw.causal_chain.map(String) : [],
    reason: humanizeReason(raw.reason || ""),
    rawReason: String(raw.reason || ""),
    rule: String(raw.rule || ""),
    tool: String(raw.tool || ""),
    type: String(raw.type || "安全裁决"),
    score: numberOr(raw.score, 0),
    createdAt: String(raw.created_at || raw.time || ""),
  };
}

function normalizeCausalGraph(raw, alert, record) {
  const rawNodes = Array.isArray(raw.nodes) ? raw.nodes.filter(isObject) : [];
  const rawEdges = Array.isArray(raw.edges) ? raw.edges.filter(isObject) : [];
  const sourcePathNodeIds = arrayStrings(raw.path_node_ids);
  const sourcePathEdgeIds = arrayStrings(raw.path_edge_ids);
  const pathNodeSet = new Set(sourcePathNodeIds);
  const pathEdgeSet = new Set(sourcePathEdgeIds);
  const nodes = rawNodes.map((node, index) => normalizeNode(node, index, pathNodeSet));
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const edges = rawEdges
    .map((edge, index) => normalizeEdge(edge, index, pathEdgeSet, nodeById))
    .filter((edge) => nodeById.has(edge.from) && nodeById.has(edge.to));
  const maxSequence = Math.max(0, ...nodes.map((node) => node.sequence));
  const decision = alert?.decision || normalizeDecision(raw.verdict);
  const traceKind = ["attack", "authorized", "enforcement_bypass"].includes(String(raw.trace_kind))
    ? String(raw.trace_kind)
    : decision === "allow" ? "authorized" : "attack";
  const lastPathNode = [...sourcePathNodeIds].reverse().find((id) => nodeById.has(id)) || nodes.at(-1)?.id || "";
  const guardId = uniqueId("view-guard", nodeById);
  const decisionId = uniqueId("view-decision", nodeById);
  const guardTitle = guardTitleFor(alert, raw);
  const guardNode = normalizeNode({
    id: guardId,
    kind: "guard",
    label: guardTitle,
    status: decision === "deny" ? "triggered" : decision === "ask" ? "review" : "passed",
    sequence: maxSequence + 1,
    display_only: true,
    basis: "dashboard_projection",
  }, nodes.length, new Set([guardId]));
  const decisionNode = normalizeNode({
    id: decisionId,
    kind: "decision",
    label: decisionLabel(decision).toUpperCase(),
    decision,
    status: decision,
    sequence: maxSequence + 2,
    display_only: true,
    basis: "dashboard_projection",
  }, nodes.length + 1, new Set([decisionId]));
  nodes.push(guardNode, decisionNode);
  nodeById.set(guardId, guardNode);
  nodeById.set(decisionId, decisionNode);

  if (lastPathNode) {
    edges.push(normalizeEdge({
      id: `view-edge-guard-${alert?.id || "decision"}`,
      from: lastPathNode,
      to: guardId,
      kind: decision === "deny" ? "blocked_by" : decision === "ask" ? "reviewed_by" : "approved_by",
      display_only: true,
      basis: "projection",
      confidence: 1,
      on_path: true,
    }, edges.length, new Set(), nodeById));
  }
  edges.push(normalizeEdge({
    id: `view-edge-decision-${alert?.id || "decision"}`,
    from: guardId,
    to: decisionId,
    kind: "decides",
    display_only: true,
    basis: "projection",
    confidence: 1,
    on_path: true,
  }, edges.length, new Set(), nodeById));

  return {
    version: numberOr(raw.version, 2),
    traceKind,
    risk: String(raw.risk || riskFromRecords(record ? [record] : [])),
    riskLabel: riskLabel(raw.risk),
    verdict: decision,
    certainty: String(raw.certainty || "observed"),
    confidence: clampNumber(raw.confidence, 0, 1),
    sourceNodeCount: numberOr(raw.session_node_count, rawNodes.length),
    sourceEdgeCount: numberOr(raw.session_edge_count, rawEdges.length),
    partial: raw.snapshot_truncated === true || raw.projection_truncated === true,
    nodes,
    edges,
    pathNodeIds: [...sourcePathNodeIds, guardId, decisionId].filter((id, index, values) => id && values.indexOf(id) === index),
    pathEdgeIds: [...sourcePathEdgeIds, ...edges.filter((edge) => edge.displayOnly && edge.onPath).map((edge) => edge.id)],
    selectedNodeId: decisionId,
    raw,
  };
}

function deriveGraphFromRecords(records, alert) {
  const decisionRecord = records
    .filter((record) => record.type === "tool_decision" || record.type === "alert" || record.type === "approval_request")
    .sort((left, right) => decisionRankFromRecord(right) - decisionRankFromRecord(left))[0];
  const toolRecord = decisionRecord || records.find((record) => record.type === "tool_result");
  const intentRecord = records.find((record) => record.type === "lab_command")
    || records.find((record) => record.type === "message_write" && record.payload?.role === "user")
    || records.find((record) => record.type === "llm_input")
    || records[0];
  const resultRecord = records.find((record) => record.type === "tool_result");
  const decision = alert?.decision || decisionFromRecords(records);
  const tool = String(toolRecord?.payload?.normalized_tool || toolRecord?.payload?.toolName || alert?.tool || "agent_plan");
  const taskSpec = toolRecord?.payload?.task_spec || {};
  const explicitCapabilities = Array.isArray(taskSpec.capabilities) ? taskSpec.capabilities : [];
  const allowedTools = Array.isArray(taskSpec.allowed_tools) ? taskSpec.allowed_tools.map(String) : [];
  const capabilityLabel = String(explicitCapabilities[0] || (tool !== "agent_plan" ? `use:${tool}` : "reason:agent"));
  const authorized = decision === "allow" || allowedTools.includes(tool);
  const text = records.map(recordText).join(" ");
  const tainted = /prompt.?injection|taint|untrusted|污染|不可信|ignore previous/i.test(text);
  const secret = /secret|credential|private.?key|api.?key|token|password|密钥|凭据|私钥/i.test(text);
  const external = EXTERNAL_TOOLS.has(tool);
  const nodes = [
    node("intent", "intent", intentTitle(intentRecord), 1, { source: "user" }),
    node("capability", "capability", capabilityLabel, 2, { authorized, authorization_actor: authorized ? "user" : "unknown" }),
    node("agent", "agent", "Agent Plan", 3, { status: "planned" }),
    node("action", "action", tool === "agent_plan" ? "等待工具调用" : tool, 4, { tool, status: decision === "deny" ? "blocked" : decision === "ask" ? "pending" : "observed", authorized }),
  ];
  if (resultRecord || tainted || secret) {
    nodes.push(node("data", "data", dataTitle(resultRecord, tainted, secret), 5, {
      integrity: tainted ? "tainted" : "trusted",
      confidentiality: secret ? "secret" : "public",
      path: resultRecord?.payload?.source || "tool.response",
    }));
  }
  if (external) nodes.push(node("sink", "sink", sinkTitle(tool, toolRecord), 6, { effect: "external", sink: tool }));
  const guardSequence = Math.max(...nodes.map((item) => item.sequence)) + 1;
  nodes.push(node("guard", "guard", guardTitleFor(alert, {}), guardSequence, { status: decision === "deny" ? "triggered" : decision === "ask" ? "review" : "passed", display_only: true }));
  nodes.push(node("decision", "decision", decisionLabel(decision).toUpperCase(), guardSequence + 1, { decision, status: decision, display_only: true }));

  const edges = [
    edge("intent-capability", "intent", "capability", "declares", true),
    edge("capability-agent", "capability", "agent", authorized ? "authorizes" : "constrains", true),
    edge("agent-action", "agent", "action", "invokes", true),
  ];
  let last = "action";
  if (nodes.some((item) => item.id === "data")) {
    edges.push(edge("action-data", "action", "data", "produces", true));
    last = "data";
  }
  if (nodes.some((item) => item.id === "sink")) {
    edges.push(edge("data-sink", last, "sink", "targets", true));
    last = "sink";
  }
  edges.push(edge("sink-guard", last, "guard", decision === "deny" ? "blocked_by" : decision === "ask" ? "reviewed_by" : "approved_by", true, true));
  edges.push(edge("guard-decision", "guard", "decision", "decides", true, true));

  const normalizedNodes = nodes.map((item, index) => normalizeNode(item, index, new Set(nodes.map(({ id }) => id))));
  const nodeById = new Map(normalizedNodes.map((item) => [item.id, item]));
  const normalizedEdges = edges.map((item, index) => normalizeEdge(item, index, new Set(edges.map(({ id }) => id)), nodeById));
  const risk = alert?.causalGraph?.risk || riskFromText(text, decision, external, tainted, secret);
  return {
    version: 2,
    traceKind: decision === "allow" ? "authorized" : "attack",
    risk,
    riskLabel: riskLabel(risk),
    verdict: decision,
    certainty: "projection",
    confidence: alert ? 0.72 : 0.45,
    sourceNodeCount: normalizedNodes.filter((item) => !item.displayOnly).length,
    sourceEdgeCount: normalizedEdges.filter((item) => !item.displayOnly).length,
    partial: true,
    nodes: normalizedNodes,
    edges: normalizedEdges,
    pathNodeIds: normalizedNodes.map((item) => item.id),
    pathEdgeIds: normalizedEdges.map((item) => item.id),
    selectedNodeId: "decision",
    derived: true,
    raw: null,
  };
}

function normalizeNode(raw, index, pathNodeSet) {
  const id = String(raw.id || `node-${index + 1}`);
  const originalKind = String(raw.kind || "data").toLowerCase();
  const integrity = String(raw.integrity || "").toLowerCase();
  const confidentiality = String(raw.confidentiality || "").toLowerCase();
  const kind = originalKind === "data" && confidentiality === "secret"
    ? "secret"
    : originalKind === "data" && integrity === "tainted" ? "taint" : originalKind;
  const title = nodeTitle(raw, originalKind);
  const state = nodeState(raw, kind);
  return {
    ...raw,
    id,
    kind,
    originalKind,
    kindLabel: KIND_LABELS[kind] || KIND_LABELS.data,
    icon: KIND_ICONS[kind] || "circle",
    title,
    state,
    meta: nodeMeta(raw, kind),
    sequence: numberOr(raw.sequence, index + 1),
    integrity,
    confidentiality,
    onPath: pathNodeSet.has(id),
    displayOnly: raw.display_only === true || raw.displayOnly === true,
  };
}

function normalizeEdge(raw, index, pathEdgeSet, nodeById) {
  const id = String(raw.id || `edge-${index + 1}`);
  const from = String(raw.from || "");
  const to = String(raw.to || "");
  const kind = String(raw.kind || "flows").toLowerCase();
  const onPath = raw.on_path === true || raw.onPath === true || pathEdgeSet.has(id);
  return {
    ...raw,
    id,
    from,
    to,
    kind,
    label: edgeLabel({ ...raw, kind }, nodeById?.get(from), nodeById?.get(to)),
    onPath,
    confidence: clampNumber(raw.confidence, 0, 1),
    displayOnly: raw.display_only === true || raw.displayOnly === true || raw.basis === "projection",
    basis: String(raw.basis || (raw.display_only ? "projection" : "observed")),
  };
}

function buildTimeline(records, alert) {
  const events = records.map((record, index) => ({
    id: String(record.id || `event-${index}`),
    time: String(record.created_at || ""),
    title: eventTitle(record),
    type: String(record.type || "record"),
    decision: normalizeDecision(record.payload?.decision || record.payload?.verdict || ""),
    severity: normalizeSeverity(record.severity),
    record,
  }));
  if (!events.length && alert) {
    events.push({
      id: alert.id,
      time: alert.createdAt,
      title: alert.type || "安全裁决",
      type: "alert",
      decision: alert.decision,
      severity: alert.severity,
      record: null,
    });
  }
  return events.slice(-80);
}

export function buildWhyReasons({ alert, graph, records = [] } = {}) {
  const reasons = [];
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const capability = nodes.find((node) => node.kind === "capability" && node.authorized === false);
  const taint = nodes.find((node) => node.kind === "taint" || node.integrity === "tainted");
  const secret = nodes.find((node) => node.kind === "secret" || node.confidentiality === "secret");

  if (capability || graph?.risk === "unauthorized_side_effect") {
    reasons.push({
      title: "能力未获授权",
      detail: capability?.title || "目标动作不在当前 TaskSpec 中",
      code: "CAPABILITY_SCOPE_DENIED",
    });
  } else if (graph?.risk === "target_scope_mismatch") {
    reasons.push({ title: "授权目标越界", detail: "目标超出当前任务允许范围", code: "CAPABILITY_TARGET_MISMATCH" });
  }
  if (taint) reasons.push({ title: "参数包含污染数据", detail: taint.title || "字段来自不可信工具结果", code: "TAINT_TO_SINK" });
  if (secret) reasons.push({ title: "检测到敏感信息", detail: secret.title || "字段标记为 SECRET", code: "SENSITIVE_DATA_FLOW" });
  if (alert?.reason) reasons.push({ title: alert.decision === "allow" ? "放行依据" : "策略证据", detail: alert.reason, code: alert.rule || "POLICY_MATCH" });

  const findings = records.flatMap((record) => Array.isArray(record.payload?.findings) ? record.payload.findings : []);
  for (const finding of findings) {
    const detail = humanizeReason(finding?.reason || "");
    if (!detail || reasons.some((reason) => reason.detail === detail)) continue;
    reasons.push({ title: finding?.finding_type === "semantic" ? "语义复核" : "安全规则命中", detail, code: finding?.id || finding?.type || "FINDING" });
    if (reasons.length >= 4) break;
  }

  if (!reasons.length) {
    reasons.push({
      title: graph?.verdict === "allow" ? "在授权范围内" : "等待更多证据",
      detail: graph?.verdict === "allow" ? "动作、目标与当前 TaskSpec 一致" : "当前记录没有可展示的详细原因",
      code: graph?.verdict === "allow" ? "AUTHORIZED_ACTION" : "NO_EXPLICIT_REASON",
    });
  }
  return reasons.slice(0, 4);
}

export function nodeKindLabel(kind) {
  return KIND_LABELS[kind] || "Node";
}

export function riskLabel(value) {
  const key = String(value || "");
  return RISK_LABELS[key] || (key ? key.replaceAll("_", " ") : "实时行为链");
}

export function decisionLabel(value) {
  return ({ deny: "拒绝", ask: "询问", allow: "允许", info: "观察" })[normalizeDecision(value)] || "观察";
}

export function decisionCode(value) {
  return ({ deny: "DENY", ask: "ASK", allow: "ALLOW", info: "INFO" })[normalizeDecision(value)] || "INFO";
}

export function edgeLabel(edgeValue, fromNode, toNode) {
  const kind = String(edgeValue?.kind || edgeValue || "").toLowerCase();
  if (kind === "targets") {
    const tool = String(fromNode?.tool || fromNode?.title || "").toLowerCase();
    if (tool.includes("email")) return "sends-to";
    if (tool.includes("file") || toNode?.effect === "persistent") return "writes-to";
    if (tool.includes("shell")) return "executes-at";
  }
  return ({
    declares: "authorizes",
    governs: "governs",
    authorizes: "permits",
    constrains: "constrains",
    requests: "invokes",
    invokes: "invokes",
    consumes: "uses",
    produces: "returns",
    derives: "derived-from",
    taints: "taints",
    targets: "targets",
    blocked_by: "blocked-by",
    reviewed_by: "reviewed-by",
    approved_by: "approved-by",
    decides: "decides",
    summary: "collapsed-path",
    flows: "flows-to",
  })[kind] || kind.replaceAll("_", "-") || "flows-to";
}

export function causalPathTitles(graph) {
  if (!graph) return [];
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  return graph.pathNodeIds.map((id) => nodeById.get(id)?.title).filter(Boolean);
}

export function formatTool(value) {
  const key = String(value || "");
  return TOOL_LABELS[key] || key.replaceAll("_", ".") || "Agent Action";
}

export function humanizeReason(value) {
  return String(value || "")
    .replace(/tool ([\w.-]+) is outside TaskSpec/gi, (_, tool) => `${formatTool(tool)} 超出当前 TaskSpec`)
    .replace(/tool ([\w.-]+) lacks explicit capability authorization/gi, (_, tool) => `${formatTool(tool)} 缺少显式能力授权`)
    .replace(/task intent does not allow email/gi, "当前任务未授权邮件外发")
    .replace(/dynamic intent tracking detected drift from read-only task to high-risk action/gi, "只读任务漂移到高风险动作")
    .replace(/content contains prompt-injection or exfiltration indicators/gi, "检测到提示注入或数据外传信号")
    .replace(/content attempts to persist privileged instructions into memory or startup flow/gi, "检测到特权指令持久化尝试")
    .replace(/read path references sensitive asset/gi, "读取路径指向敏感资产")
    .replace(/tool arguments carry secret-tainted data/gi, "工具参数携带机密污染数据")
    .replace(/tool arguments match deterministic trust-risk policy/gi, "工具参数命中确定性信任风险策略")
    .trim();
}

function nodeTitle(raw, originalKind) {
  if (originalKind === "action") return formatTool(raw.tool || raw.label || "tool_action");
  if (originalKind === "data") return String(raw.path || raw.label || "data_field");
  if (originalKind === "sink") return sinkDisplay(raw.sink || raw.label || raw.effect || "external_sink");
  if (originalKind === "capability") return capabilityDisplay(raw.label || "requested_capability");
  if (originalKind === "intent") return intentDisplay(raw.label || "user_task");
  if (originalKind === "collapsed") return `中间 ${numberOr(raw.omitted_node_count, 0)} 个节点`;
  return String(raw.label || raw.title || originalKind || "node");
}

function nodeState(raw, kind) {
  if (kind === "capability") return raw.authorized === true ? "AUTHORIZED" : raw.authorized === false ? "UNSCOPED" : "REQUESTED";
  if (kind === "taint") return "TAINTED";
  if (kind === "secret") return "SECRET";
  if (kind === "decision") return decisionCode(raw.decision || raw.status);
  if (kind === "guard") return String(raw.status || "EVALUATING").toUpperCase();
  if (kind === "collapsed") return "DISPLAY ONLY";
  return String(raw.status || raw.decision || raw.effect || "OBSERVED").toUpperCase();
}

function nodeMeta(raw, kind) {
  if (kind === "intent") return "当前用户任务边界";
  if (kind === "capability") return raw.authorized === true ? "用户显式授权" : "未进入授权范围";
  if (kind === "action") return `${raw.status || raw.decision || "observed"} · ${raw.authorized === true ? "authorized" : raw.authorized === false ? "unscoped" : "observed"}`;
  if (kind === "taint") return `${raw.path || "field"} · untrusted`;
  if (kind === "secret") return `${raw.path || "field"} · sensitive`;
  if (kind === "sink") return String(raw.effect || "external destination");
  if (kind === "guard") return raw.display_only ? "裁决视图投影" : "deterministic policy";
  if (kind === "decision") return raw.display_only ? "最终裁决投影" : "runtime decision";
  if (kind === "collapsed") return "不代表新增血缘证据";
  return String(raw.meta || raw.effect || "runtime evidence");
}

function node(id, kind, label, sequence, extra = {}) {
  return { id, kind, label, sequence, ...extra };
}

function edge(id, from, to, kind, onPath = false, displayOnly = false) {
  return { id, from, to, kind, on_path: onPath, display_only: displayOnly, basis: displayOnly ? "projection" : "observed", confidence: displayOnly ? 0 : 1 };
}

function compareAlertPriority(left, right) {
  const decision = DECISION_ORDER[right.decision] - DECISION_ORDER[left.decision];
  if (decision) return decision;
  const bypass = Number(right.causalGraph?.trace_kind === "enforcement_bypass") - Number(left.causalGraph?.trace_kind === "enforcement_bypass");
  if (bypass) return bypass;
  const severity = SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];
  if (severity) return severity;
  return dateMs(right.createdAt) - dateMs(left.createdAt);
}

function alertFromRecords(records) {
  const record = records
    .filter((item) => ["alert", "tool_decision", "approval_request", "approval_resolution"].includes(String(item.type)))
    .sort((left, right) => decisionRankFromRecord(right) - decisionRankFromRecord(left))[0];
  if (!record) return null;
  const payload = isObject(record.payload) ? record.payload : {};
  return normalizeAlert({
    id: record.id,
    action: payload.decision || payload.verdict || (record.severity === "danger" ? "BLOCK" : "INFO"),
    severity: record.severity,
    type: record.title || TYPE_LABELS[record.type] || record.type,
    tool: payload.normalized_tool || payload.toolName || payload.tool,
    reason: payload.reason || payload.summary || record.summary,
    rule: payload.rule || "",
    score: payload.risk_score || payload.sentry_score || 0,
    created_at: record.created_at,
    causal_graph: null,
    record,
  });
}

function decisionFromRecords(records) {
  let selected = "info";
  for (const record of records) {
    const decision = normalizeDecision(record.payload?.decision || record.payload?.verdict || record.payload?.original_decision || "");
    if (DECISION_ORDER[decision] > DECISION_ORDER[selected]) selected = decision;
    if (record.severity === "danger" && selected === "info") selected = "deny";
  }
  return selected;
}

function severityFromRecords(records) {
  return records.reduce((selected, record) => {
    const next = normalizeSeverity(record.severity);
    return SEVERITY_ORDER[next] > SEVERITY_ORDER[selected] ? next : selected;
  }, "info");
}

function decisionRankFromRecord(record) {
  return DECISION_ORDER[normalizeDecision(record?.payload?.decision || record?.payload?.verdict || record?.payload?.original_decision || (record?.severity === "danger" ? "deny" : "info"))];
}

function sessionTitle(id, alert, graph, records) {
  if (graph?.risk && RISK_LABELS[graph.risk]) return RISK_LABELS[graph.risk];
  const joined = `${alert?.type || ""} ${alert?.reason || ""} ${records.map(recordText).join(" ")}`.toLowerCase();
  if (/prompt.?injection|taint|污染|不可信/.test(joined)) return "Prompt Injection 传播";
  if (/email|邮件/.test(joined)) return alert?.decision === "allow" ? "授权邮件工作流" : "可疑邮件动作";
  if (/memory|poison|记忆|投毒/.test(joined)) return "记忆投毒尝试";
  if (/secret|credential|private.?key|密钥|凭据|私钥/.test(joined)) return "敏感数据访问";
  const tool = records.map((record) => record.payload?.normalized_tool || record.payload?.toolName).find(Boolean);
  if (tool) return `${formatTool(tool)}工作流`;
  const compact = String(id).split(":").filter(Boolean).at(-1) || "Agent Session";
  return compact.length > 28 ? `${compact.slice(0, 25)}...` : compact;
}

function sessionSubtitle(alert, graph, records) {
  if (alert?.reason) return alert.reason;
  if (graph?.derived) return "由审计记录生成的语义视图投影";
  const latest = records.at(-1);
  return humanizeReason(latest?.summary || latest?.title || "等待下一条行为事件");
}

function policyList(alert, records) {
  const policies = new Set();
  if (alert?.rule) policies.add(alert.rule);
  for (const record of records) {
    const payload = record.payload || {};
    for (const violation of Array.isArray(payload.violations) ? payload.violations : []) policies.add(String(violation));
    for (const finding of Array.isArray(payload.findings) ? payload.findings : []) {
      if (finding?.id || finding?.type) policies.add(String(finding.id || finding.type));
    }
  }
  return [...policies].filter(Boolean).slice(0, 6);
}

function eventTitle(record) {
  const tool = record.payload?.normalized_tool || record.payload?.toolName || record.payload?.tool;
  if (record.type === "tool_decision" && tool) return `${formatTool(tool)} · ${decisionCode(record.payload?.decision || record.payload?.verdict)}`;
  if (record.type === "tool_result" && tool) return `${formatTool(tool)}返回`;
  return humanizeReason(record.title || TYPE_LABELS[record.type] || record.type || "运行事件");
}

function guardTitleFor(alert, raw) {
  if (String(alert?.rule || "").trim()) return String(alert.rule).split(/[;,|]/)[0].slice(0, 36);
  const risk = String(raw?.risk || alert?.causalGraph?.risk || "");
  if (risk.includes("tainted") || risk.includes("secret")) return "Taint Boundary Guard";
  if (risk.includes("unauthorized") || risk.includes("scope")) return "TaskSpec Guard";
  return "Policy Guard";
}

function intentTitle(record) {
  const value = record?.payload?.command || record?.payload?.preview || record?.summary || record?.title || "当前用户请求";
  return String(value).replace(/\s+/g, " ").slice(0, 48);
}

function dataTitle(record, tainted, secret) {
  if (record?.payload?.source) return String(record.payload.source).slice(0, 44);
  if (secret) return "敏感字段";
  if (tainted) return "不可信工具结果";
  return "tool.response";
}

function sinkTitle(tool, record) {
  const payload = record?.payload || {};
  return sinkDisplay(payload.to || payload.url || payload.path || payload.target || tool);
}

function sinkDisplay(value) {
  const text = String(value || "external_sink");
  return formatTool(text) || text;
}

function capabilityDisplay(value) {
  const parts = String(value || "").split(":").filter(Boolean);
  if (!parts.length) return "请求能力";
  const verbs = { read: "读取", write: "写入", send: "发送", execute: "执行", request: "请求", use: "调用", reason: "推理" };
  const resources = { file: "文件", email: "邮件", api: "API", shell: "命令", memory: "记忆", agent: "Agent" };
  if (parts.length === 1) return formatTool(parts[0]);
  return `${verbs[parts[0]] || parts[0]}${resources[parts[1]] || formatTool(parts[1])}`;
}

function intentDisplay(value) {
  const text = String(value || "user_task");
  return text === "user_task" ? "当前用户请求" : text.replaceAll("_", " ").slice(0, 48);
}

function riskFromRecords(records) {
  return riskFromText(records.map(recordText).join(" "), decisionFromRecords(records), false, false, false);
}

function riskFromText(text, decision, external, tainted, secret) {
  if (external && secret) return "secret_to_external_sink";
  if (external && tainted) return "tainted_to_external_sink";
  if (decision !== "allow") return "unauthorized_side_effect";
  return "authorized_tool_execution";
}

function recordText(record) {
  return `${record?.title || ""} ${record?.summary || ""} ${JSON.stringify(record?.payload || {})}`;
}

function normalizeDecision(value) {
  const text = String(value || "").toLowerCase();
  if (["block", "blocked", "deny", "denied", "reject", "rejected"].includes(text)) return "deny";
  if (["ask", "review", "pending", "require_approval", "approval"].includes(text)) return "ask";
  if (["allow", "allowed", "pass", "passed", "success"].includes(text)) return "allow";
  return "info";
}

function normalizeSeverity(value) {
  const text = String(value || "info").toLowerCase();
  if (text === "danger") return "high";
  if (text === "warning") return "medium";
  if (text === "success") return "info";
  return ["critical", "high", "medium", "info"].includes(text) ? text : "info";
}

function compareCreatedAsc(left, right) {
  return dateMs(left.created_at) - dateMs(right.created_at);
}

function dateMs(value) {
  const parsed = new Date(value || 0).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function uniqueId(base, map) {
  if (!map.has(base)) return base;
  let index = 2;
  while (map.has(`${base}-${index}`)) index += 1;
  return `${base}-${index}`;
}

function arrayStrings(value) {
  return Array.isArray(value) ? value.map(String).filter(Boolean) : [];
}

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function numberOr(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function clampNumber(value, min, max) {
  return Math.max(min, Math.min(max, numberOr(value, min)));
}
