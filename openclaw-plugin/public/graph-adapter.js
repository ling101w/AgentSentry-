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

export function buildDashboardModel({ overview = {}, records = [], recordsMeta = {} } = {}) {
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
      label: source.primary || "玄鉴审计记录",
      totalRecords: numberOr(source.total_records, numberOr(recordsMeta.totalRecords, safeRecords.length)),
      windowRecords: numberOr(source.window_records, numberOr(recordsMeta.windowRecords, safeRecords.length)),
      available: source.openclaw_available !== false,
      alertCount: numberOr(overview?.alertCount, alerts.length),
      recordsPath: String(recordsMeta.recordsPath || source.openclaw_source || ""),
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
  graph.sessionId = group.id;
  linkGraphEvidence(graph, records, primaryAlert);
  const decision = primaryAlert?.decision || decisionFromRecords(records);
  const severity = primaryAlert?.severity || severityFromRecords(records);
  const latest = records.at(-1)?.created_at || primaryAlert?.createdAt || "";
  const latestMs = dateMs(latest);
  const actionCount = graph.nodes.filter((node) => node.kind === "action").length;
  const timeline = buildTimeline(records, primaryAlert, graph);
  const policies = policyList(primaryAlert, records);
  const metadata = buildSessionMetadata(group.id, records, primaryAlert);
  const requestContext = buildRequestContext(records, graph, primaryAlert);

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
    metadata,
    requestContext,
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

function linkGraphEvidence(graph, records, alert) {
  const prepared = records.map((record) => ({
    record,
    id: String(record.id || ""),
    type: String(record.type || ""),
    tool: String(record.payload?.normalized_tool || record.payload?.toolName || record.payload?.tool || "").toLowerCase(),
    decision: normalizeDecision(record.payload?.decision || record.payload?.verdict || record.payload?.original_decision || ""),
    text: recordText(record).toLowerCase(),
    timeMs: dateMs(record.created_at),
  }));
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));

  for (const node of graph.nodes) {
    let matches = prepared.filter((item) => recordMatchesNode(item, node));
    if (!matches.length && ["guard", "decision"].includes(node.kind)) {
      matches = prepared.filter((item) => ["alert", "tool_decision", "approval_request", "approval_resolution"].includes(item.type));
    }
    const ordered = matches.slice().sort((left, right) => left.timeMs - right.timeMs);
    const representative = representativeNodeRecord(node, ordered);
    node.recordIds = ordered.map((item) => item.id).filter(Boolean).slice(0, 12);
    node.recordId = representative?.id || "";
    node.time = String(representative?.record?.created_at || "");
    node.evidenceTitle = String(representative?.record?.title || "");
    node.evidenceSummary = String(representative?.record?.summary || representative?.record?.payload?.reason || "");
  }

  for (const edgeValue of graph.edges) {
    const from = nodeById.get(edgeValue.from);
    const to = nodeById.get(edgeValue.to);
    const relatedIds = new Set([...(from?.recordIds || []), ...(to?.recordIds || [])]);
    let candidates = prepared.filter((item) => relatedIds.has(item.id));
    const argPath = String(edgeValue.arg_path || edgeValue.argPath || "");
    if (argPath) {
      const argTerms = [argPath, argPath.split(/[.[\]]/).filter(Boolean).at(-1)].filter(Boolean).map((item) => String(item).toLowerCase());
      const argumentMatches = candidates.filter((item) => argTerms.some((term) => item.text.includes(term)));
      if (argumentMatches.length) candidates = argumentMatches;
    }
    candidates = candidates.slice().sort((left, right) => left.timeMs - right.timeMs);
    edgeValue.recordIds = candidates.map((item) => item.id).filter(Boolean).slice(0, 10);
    edgeValue.time = String(to?.time || from?.time || "");
    edgeValue.policyCodes = policyCodesForRelation(edgeValue.kind, candidates.map((item) => item.record), alert);
    edgeValue.fromState = String(from?.state || "");
    edgeValue.toState = String(to?.state || "");
  }
}

function recordMatchesNode(item, node) {
  const type = item.type;
  const payload = item.record.payload || {};
  const terms = nodeSearchTerms(node);
  const includesNodeTerm = terms.some((term) => item.text.includes(term));

  if (node.kind === "intent") {
    return ["lab_command", "user_message", "command"].includes(type)
      || (type === "message_write" && String(payload.role || "").toLowerCase() === "user")
      || (type === "llm_input" && Boolean(payload.command || payload.preview));
  }
  if (node.kind === "capability") {
    if (type === "task_spec" || isObject(payload.task_spec)) return includesNodeTerm || !terms.length;
    return ["tool_decision", "approval_request", "alert", "guard_finding"].includes(type)
      && (includesNodeTerm || /taskspec|capabilit|authoriz|scope|intent|授权|能力|越权/.test(item.text));
  }
  if (node.kind === "agent") return ["llm_input", "message_write", "session_start", "tool_call"].includes(type);
  if (node.kind === "action") {
    const nodeTool = String(node.tool || node.original_tool || "").toLowerCase();
    const toolMatch = nodeTool ? item.tool === nodeTool || item.text.includes(nodeTool) : includesNodeTerm;
    return toolMatch && ["tool_call", "tool_decision", "tool_result", "alert", "approval_request", "approval_resolution", "guard_finding"].includes(type);
  }
  if (node.kind === "taint") {
    return ["tool_result", "guard_finding", "alert", "provenance_scan", "llm_input"].includes(type)
      && (includesNodeTerm || /prompt.?injection|taint|untrusted|污染|不可信|ignore previous/.test(item.text));
  }
  if (node.kind === "secret") {
    return ["tool_result", "guard_finding", "alert", "provenance_scan", "tool_decision"].includes(type)
      && (includesNodeTerm || /secret|credential|private.?key|api.?key|token|password|敏感|密钥|凭据|私钥/.test(item.text));
  }
  if (node.kind === "data") {
    return ["tool_result", "guard_finding", "alert", "provenance_scan"].includes(type)
      && (includesNodeTerm || type === "tool_result");
  }
  if (node.kind === "sink") {
    return ["tool_call", "tool_decision", "tool_result", "alert", "approval_request"].includes(type)
      && (includesNodeTerm || (node.effect === "external" && /recipient|target|url|external|email|api|外发|目标/.test(item.text)));
  }
  if (node.kind === "guard") return ["guard_finding", "alert", "tool_decision", "approval_request", "approval_resolution"].includes(type);
  if (node.kind === "decision") return item.decision !== "info" || ["alert", "approval_request", "approval_resolution"].includes(type);
  return includesNodeTerm;
}

function nodeSearchTerms(node) {
  const ignored = new Set(["data_field", "tool.response", "current user request", "当前用户请求", "agent plan", "policy guard"]);
  return [node.tool, node.original_tool, node.path, node.sink, node.source, node.label, node.title]
    .map((value) => String(value || "").trim().toLowerCase())
    .filter((value, index, values) => value.length >= 3 && !ignored.has(value) && values.indexOf(value) === index)
    .slice(0, 8);
}

function representativeNodeRecord(node, matches) {
  if (!matches.length) return null;
  const priorities = {
    intent: ["lab_command", "user_message", "command", "message_write", "llm_input"],
    capability: ["task_spec", "tool_decision", "approval_request", "guard_finding", "alert"],
    agent: ["llm_input", "message_write", "tool_call", "session_start"],
    action: String(node.state || "").toUpperCase().includes("BLOCK")
      ? ["tool_decision", "tool_call", "alert", "tool_result", "guard_finding"]
      : ["tool_call", "tool_decision", "tool_result", "alert", "guard_finding"],
    data: ["tool_result", "provenance_scan", "guard_finding", "alert"],
    taint: ["tool_result", "guard_finding", "provenance_scan", "alert"],
    secret: ["tool_result", "guard_finding", "tool_decision", "alert"],
    sink: ["tool_call", "tool_decision", "approval_request", "alert", "tool_result"],
    guard: ["guard_finding", "alert", "tool_decision", "approval_request", "approval_resolution"],
    decision: ["approval_resolution", "alert", "tool_decision", "approval_request", "tool_result"],
  }[node.kind] || [];
  for (const type of priorities) {
    const candidates = matches.filter((item) => item.type === type);
    if (candidates.length) return node.kind === "guard" || node.kind === "decision" ? candidates.at(-1) : candidates[0];
  }
  return node.kind === "guard" || node.kind === "decision" ? matches.at(-1) : matches[0];
}

function policyCodesForRelation(kind, records, alert) {
  const values = new Set();
  if (alert?.rule) values.add(String(alert.rule));
  for (const record of records) {
    const payload = record.payload || {};
    if (payload.rule) values.add(String(payload.rule));
    for (const violation of Array.isArray(payload.violations) ? payload.violations : []) values.add(String(violation));
    for (const finding of Array.isArray(payload.findings) ? payload.findings : []) {
      if (finding?.id || finding?.type) values.add(String(finding.id || finding.type));
    }
    if (record.type === "guard_finding" && (payload.id || payload.type)) values.add(String(payload.id || payload.type));
  }
  const relation = String(kind || "").toLowerCase();
  const pattern = ["declares", "governs", "authorizes", "constrains", "requests"].includes(relation)
    ? /task|capabil|intent|scope|authoriz|recipient|target|授权|能力|越权/i
    : ["produces", "derives", "taints", "consumes"].includes(relation)
      ? /taint|secret|sensitive|provenance|inject|trust|data|exfil|污染|敏感|溯源/i
      : relation === "targets"
        ? /sink|external|recipient|target|email|api|write|exfil|外发|目标/i
        : null;
  const all = [...values].filter(Boolean);
  if (!pattern) return all.slice(0, 6);
  const matched = all.filter((value) => pattern.test(value));
  return matched.slice(0, 6);
}

function buildTimeline(records, alert, graph) {
  const events = records.map((record, index) => ({
    id: String(record.id || `event-${index}`),
    time: String(record.created_at || ""),
    title: eventTitle(record),
    detail: humanizeReason(record.summary || record.payload?.reason || ""),
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
      detail: alert.reason || "",
      type: "alert",
      decision: alert.decision,
      severity: alert.severity,
      record: null,
    });
  }
  for (const event of events) {
    const node = bestTimelineNode(event, graph);
    const edgeValue = node ? graph.edges.find((edge) => edge.to === node.id && edge.recordIds?.includes(event.id)) : null;
    event.nodeId = node?.id || "";
    event.edgeId = edgeValue?.id || "";
    event.stage = timelineStage(event, node);
    event.revealSequence = timelineRevealSequence(event, graph, node);
  }
  return events.slice(-80);
}

function bestTimelineNode(event, graph) {
  if (!graph?.nodes?.length) return null;
  let candidates = graph.nodes.filter((node) => node.recordIds?.includes(event.id));
  const eventTool = String(event.record?.payload?.normalized_tool || event.record?.payload?.toolName || event.record?.payload?.tool || "").toLowerCase();
  if (String(event.type || "") === "tool_call" && eventTool) {
    const toolMatches = graph.nodes.filter((node) => node.kind === "action" && [node.tool, node.original_tool, node.title]
      .map((value) => String(value || "").toLowerCase())
      .some((value) => value === eventTool || value.endsWith(`.${eventTool}`)));
    const linkedToolMatches = candidates.filter((node) => toolMatches.some((match) => match.id === node.id));
    if (linkedToolMatches.length) candidates = linkedToolMatches;
    else if (toolMatches.length) candidates = toolMatches;
  }
  if (!candidates.length) return null;
  const type = String(event.type || "");
  const payload = event.record?.payload || {};
  const preferredKinds = ["lab_command", "user_message", "command"].includes(type)
    ? ["intent"]
    : type === "task_spec" ? ["capability"]
      : type === "tool_call" ? ["action", "sink"]
        : type === "tool_result" && (payload.preview || payload.adversarial_input)
          ? ["taint", "secret", "data", "action"]
          : type === "tool_result" && (payload.blocked || payload.execution_status === "blocked")
            ? ["decision", "guard", "action"]
            : type === "tool_result" ? ["data", "action", "decision"]
              : type === "guard_finding" ? ["taint", "secret", "capability", "guard"]
                : type === "alert" ? ["guard", "decision", "action"]
                  : ["decision", "guard", "action", "agent", "data"];
  return candidates.slice().sort((left, right) => {
    const leftRank = preferredKinds.indexOf(left.kind);
    const rightRank = preferredKinds.indexOf(right.kind);
    const normalizedLeft = leftRank < 0 ? preferredKinds.length : leftRank;
    const normalizedRight = rightRank < 0 ? preferredKinds.length : rightRank;
    return normalizedLeft - normalizedRight || left.sequence - right.sequence;
  })[0];
}

function timelineRevealSequence(event, graph, selectedNode) {
  const eventMs = dateMs(event.time);
  const reached = graph.nodes.filter((node) => {
    const nodeMs = dateMs(node.time);
    return nodeMs > 0 && eventMs > 0 && nodeMs <= eventMs;
  });
  return Math.max(0, selectedNode?.sequence || 0, ...reached.map((node) => node.sequence));
}

function timelineStage(event, node) {
  if (node) {
    if (node.kind === "intent") return "用户输入";
    if (node.kind === "capability") return node.authorized === false ? "授权越界" : "意图解析";
    if (node.kind === "agent") return "Agent 计划";
    if (node.kind === "action") return "工具调用";
    if (node.kind === "taint") return "Prompt 注入";
    if (node.kind === "secret") return "敏感数据";
    if (node.kind === "data") return "工具返回";
    if (node.kind === "sink") return "外部目标";
    if (node.kind === "guard") return "玄鉴拦截";
    if (node.kind === "decision") return "安全裁决";
  }
  return event.title || "运行事件";
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

function buildSessionMetadata(sessionId, records, alert) {
  const decisionRecord = records.find((record) => record.id === alert?.id)
    || [...records].reverse().find((record) => ["alert", "tool_decision", "approval_request", "approval_resolution"].includes(String(record.type)));
  return {
    incidentId: String(alert?.id || decisionRecord?.id || records.at(-1)?.id || sessionId || ""),
    sessionId: String(sessionId || ""),
    runId: firstString(...records.map((record) => record.run_id)),
    source: firstString(alert?.source, ...records.map((record) => record.payload?.source)),
    scenario: firstString(...records.map((record) => record.payload?.scenario)),
    ip: firstString(...records.map((record) => record.payload?.ip_address || record.payload?.ip)),
    createdAt: String(records[0]?.created_at || alert?.createdAt || ""),
    latestAt: String(records.at(-1)?.created_at || alert?.createdAt || ""),
  };
}

function buildRequestContext(records, graph, alert) {
  const userRecord = records.find((record) => ["lab_command", "user_message", "command"].includes(String(record.type)))
    || records.find((record) => record.type === "message_write" && String(record.payload?.role || "").toLowerCase() === "user")
    || records.find((record) => record.type === "llm_input")
    || null;
  const taintRecord = records.find((record) => record.payload?.adversarial_input)
    || records.find((record) => record.type === "tool_result" && record.payload?.preview && /prompt.?injection|ignore previous|taint|污染|不可信/i.test(recordText(record)))
    || records.find((record) => record.type === "guard_finding" && /prompt.?injection|taint|污染|不可信/i.test(recordText(record)))
    || null;
  const detectionRecord = taintRecord
    || records.find((record) => record.id === alert?.id)
    || [...records].reverse().find((record) => ["alert", "guard_finding", "tool_decision", "approval_request", "approval_resolution"].includes(String(record.type)))
    || null;
  const tools = Array.from(new Set([
    ...graph.nodes.filter((node) => node.kind === "action").map((node) => node.tool || node.original_tool),
    ...records.map((record) => record.payload?.normalized_tool || record.payload?.toolName || record.payload?.tool),
  ].map((value) => String(value || "").trim()).filter(Boolean)));
  const findings = records.flatMap((record) => Array.isArray(record.payload?.findings) ? record.payload.findings : []);
  const detectionSources = Array.from(new Set([
    ...findings.map((finding) => finding?.id || finding?.type || finding?.finding_type || finding?.layer),
    alert?.rule,
  ].map((value) => String(value || "").trim()).filter(Boolean)));
  const taintNode = graph.nodes.find((node) => node.kind === "taint");
  const detectionSignal = [
    taintRecord ? recordText(taintRecord) : "",
    taintNode?.title,
    taintNode?.path,
    alert?.type,
    alert?.rawReason,
    graph.risk,
  ].filter(Boolean).join(" ");
  const promptInjectionDetected = /prompt.?injection|ignore previous|override (?:the )?instructions|system prompt|提示注入|注入|越权指令/i.test(detectionSignal);
  const riskDetected = Boolean(taintNode || taintRecord || graph.verdict === "deny" || graph.verdict === "ask");
  const detectionType = promptInjectionDetected
    ? "Prompt Injection"
    : graph.verdict === "ask"
      ? "授权范围待确认"
      : graph.verdict === "deny"
        ? "未授权工具调用"
        : taintNode || taintRecord ? "不可信数据流" : "";
  return {
    input: firstString(userRecord?.payload?.command, userRecord?.payload?.input, userRecord?.summary, graph.nodes.find((node) => node.kind === "intent")?.title),
    originalInput: firstString(userRecord?.payload?.raw_input, userRecord?.payload?.preview, userRecord?.payload?.command, userRecord?.summary),
    tools,
    adversarial: firstString(
      taintRecord?.payload?.adversarial_input,
      taintRecord?.payload?.preview,
      findingEvidenceText(findings),
      taintNode?.title,
      alert?.rawReason,
    ),
    attackDetected: riskDetected,
    promptInjectionDetected,
    detectionType,
    eventTime: String(userRecord?.created_at || ""),
    detectionTime: String(detectionRecord?.created_at || alert?.createdAt || ""),
    channel: firstString(userRecord?.payload?.channel, userRecord?.payload?.source),
    detectionSources,
  };
}

function findingEvidenceText(findings) {
  for (const finding of findings) {
    const evidence = isObject(finding?.evidence) ? finding.evidence : {};
    const value = firstString(
      evidence.preview,
      Array.isArray(evidence.matched) ? evidence.matched[0] : "",
      finding?.reason,
    );
    if (value) return value;
  }
  return "";
}

export function buildSelectionEvidence(session, selection) {
  if (!session || !selection?.value) return null;
  const graph = session.graph;
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const recordById = new Map(session.records.map((record) => [String(record.id || ""), record]));

  if (selection.type === "edge") {
    const edgeValue = graph.edges.find((edge) => edge.id === selection.value.id) || selection.value;
    const from = nodeById.get(edgeValue.from);
    const to = nodeById.get(edgeValue.to);
    const records = (edgeValue.recordIds || []).map((id) => recordById.get(id)).filter(Boolean);
    const downstreamDecision = reachableDecision(graph, edgeValue.to);
    const facts = compactFacts([
      ["语义关系", edgeValue.label],
      ["来源节点", nodeEvidenceLabel(from, edgeValue.from)],
      ["目标节点", nodeEvidenceLabel(to, edgeValue.to)],
      ["来源状态", from?.state],
      ["目标状态", to?.state],
      ["来源字段", from?.path || from?.source],
      ["目标参数", edgeValue.arg_path || edgeValue.argPath || edgeValue.match],
      ["证据依据", evidenceBasisLabel(edgeValue)],
      ["置信度", Number.isFinite(Number(edgeValue.confidence)) ? `${Math.round(Number(edgeValue.confidence) * 100)}%` : ""],
      ["攻击路径", edgeValue.onPath ? "是" : "否"],
      ["字段变换", Array.isArray(to?.transformations) ? to.transformations.join(" → ") : ""],
    ]);
    return {
      type: "edge",
      id: edgeValue.id,
      kind: edgeValue.kind,
      kindLabel: "语义关系",
      title: edgeValue.label,
      subtitle: `${nodeEvidenceLabel(from, edgeValue.from)} → ${nodeEvidenceLabel(to, edgeValue.to)}`,
      state: edgeValue.onPath ? "攻击路径" : "支撑关系",
      occurredAt: edgeValue.time || to?.time || from?.time || "",
      tone: selectionTone(session, edgeValue, to),
      description: describeEdge(edgeValue, from, to),
      facts,
      observations: recordObservations(records, { includePolicy: true }),
      relations: [],
      records: records.map(publicEvidenceRecord).slice(0, 8),
      policies: edgeValue.policyCodes || [],
      downstreamDecision: downstreamDecision ? {
        id: downstreamDecision.id,
        title: downstreamDecision.title,
        state: downstreamDecision.state,
      } : null,
      raw: { edge: edgeValue, records },
    };
  }

  const node = graph.nodes.find((item) => item.id === selection.value.id) || selection.value;
  const records = (node.recordIds || []).map((id) => recordById.get(id)).filter(Boolean);
  const incoming = graph.edges.filter((edge) => edge.to === node.id);
  const outgoing = graph.edges.filter((edge) => edge.from === node.id);
  const facts = compactFacts([
    ["语义类型", node.kindLabel || nodeKindLabel(node.kind)],
    ["当前状态", node.state],
    ["工具", node.tool || node.original_tool],
    ["字段路径", node.path],
    ["数据来源", node.source],
    ["数据完整性", node.integrity ? String(node.integrity).toUpperCase() : ""],
    ["保密级别", node.confidentiality ? String(node.confidentiality).toUpperCase() : ""],
    ["授权状态", node.authorized === true ? "已授权" : node.authorized === false ? "未授权" : ""],
    ["授权主体", node.authorization_actor],
    ["授权依据", node.authorization_reason],
    ["目标", node.sink],
    ["副作用", node.effect],
    ["血缘 ID", node.provenance_id || node.provenanceId],
    ["字段变换", Array.isArray(node.transformations) ? node.transformations.join(" → ") : ""],
    ["证据边界", node.displayOnly ? "视图投影" : "运行时观测"],
  ]);
  return {
    type: "node",
    id: node.id,
    kind: node.kind,
    kindLabel: node.kindLabel || nodeKindLabel(node.kind),
    title: nodeDisplayTitle(node),
    subtitle: node.title,
    state: node.state,
    occurredAt: node.time || "",
    tone: selectionTone(session, null, node),
    description: describeNode(node, records, session),
    facts,
    observations: recordObservations(records, { includePolicy: ["capability", "taint", "secret", "guard", "decision"].includes(node.kind) }),
    relations: [
      ...incoming.map((edge) => ({ direction: "in", edgeId: edge.id, label: edge.label, nodeId: edge.from, nodeTitle: nodeEvidenceLabel(nodeById.get(edge.from), edge.from) })),
      ...outgoing.map((edge) => ({ direction: "out", edgeId: edge.id, label: edge.label, nodeId: edge.to, nodeTitle: nodeEvidenceLabel(nodeById.get(edge.to), edge.to) })),
    ],
    records: records.map(publicEvidenceRecord).slice(0, 8),
    policies: selectionPolicies(node, records, session.alert),
    downstreamDecision: node.kind === "decision" ? null : reachableDecision(graph, node.id),
    raw: { node, records },
  };
}

function describeNode(node, records, session) {
  const record = records.find((item) => item.id === node.recordId) || records[0];
  const payload = record?.payload || {};
  if (node.kind === "intent") {
    const command = firstString(payload.command, payload.input, record?.summary, node.title);
    return command ? `玄鉴收到用户任务：“${command}”` : "玄鉴记录了本次会话的用户任务边界。";
  }
  if (node.kind === "capability") {
    return node.authorized === false
      ? `玄鉴观察到当前任务请求了“${node.title}”，但该能力没有进入 TaskSpec 授权范围。`
      : node.authorized === true
        ? `玄鉴把用户任务解析为“${node.title}”，并确认该能力已获授权。`
        : `玄鉴从当前任务中识别出能力请求“${node.title}”，授权状态尚未明确。`;
  }
  if (node.kind === "agent") return `玄鉴观察到智能体在此阶段形成或更新执行计划：${node.title}。`;
  if (node.kind === "action") {
    const status = node.state ? `，运行状态为 ${node.state}` : "";
    const blocked = /BLOCK|DENY|UNSCOPED|REJECT/.test(String(node.state || "").toUpperCase()) || node.authorized === false;
    return blocked
      ? `玄鉴观察到工具调用 ${node.tool || node.title}${status}，并在实际执行前将其阻断。`
      : `玄鉴观察到工具调用 ${node.tool || node.title}${status}。`;
  }
  if (node.kind === "taint") return `玄鉴在工具返回或外部内容中识别到“${node.title}”，将其标记为不可信数据并追踪后续传播。`;
  if (node.kind === "secret") return `字段“${node.path || node.title}”同时携带敏感性${node.integrity === "tainted" ? "和污染" : ""}标签。`;
  if (node.kind === "data") return `工具产生了数据“${node.path || node.title}”，玄鉴记录了它的来源与完整性标签。`;
  if (node.kind === "sink") return `玄鉴观察到动作目标指向“${node.sink || node.title}”${node.effect ? `，副作用类型为 ${node.effect}` : ""}。`;
  if (node.kind === "guard") return `玄鉴在执行边界运行“${node.title}”，状态为 ${node.state || "未记录"}。`;
  if (node.kind === "decision") return `玄鉴根据已观测到的行为链输出最终裁决：${node.state || session.decisionLabel}。`;
  if (node.kind === "collapsed") return "后端返回的因果路径超过视图上限，中间节点在此处按边界信息折叠展示。";
  return node.evidenceSummary || node.meta || "玄鉴记录了该语义阶段的运行时证据。";
}

function describeEdge(edgeValue, from, to) {
  const source = nodeEvidenceLabel(from, edgeValue.from);
  const target = nodeEvidenceLabel(to, edgeValue.to);
  const argPath = String(edgeValue.arg_path || edgeValue.argPath || "");
  const relation = String(edgeValue.kind || "").toLowerCase();
  if (["declares", "authorizes"].includes(relation)) return `“${source}”为“${target}”提供了明确的任务授权依据。`;
  if (relation === "constrains") return `“${source}”形成授权边界，“${target}”超出了这条边界。`;
  if (["requests", "invokes"].includes(relation)) return `Agent 计划从“${source}”推进到工具动作“${target}”。`;
  if (relation === "produces") return `“${source}”执行后返回了数据“${target}”。`;
  if (relation === "derives") return `“${target}”由上游数据“${source}”派生，血缘关系被玄鉴保留。`;
  if (relation === "taints") return `不可信数据“${source}”污染了下游字段“${target}”。`;
  if (relation === "consumes") return `“${target}”使用了“${source}”${argPath ? `，进入参数 ${argPath}` : ""}。`;
  if (relation === "targets") return `动作“${source}”把副作用指向目标“${target}”。`;
  if (relation === "blocked_by") return `“${source}”在执行前被“${target}”拦截。`;
  if (relation === "reviewed_by") return `“${source}”被交给“${target}”进行人工复核。`;
  if (relation === "approved_by") return `“${source}”通过了“${target}”的执行边界校验。`;
  if (relation === "decides") return `“${source}”将本次安全裁决写入“${target}”。`;
  return `“${source}”通过 ${edgeValue.label} 关联到“${target}”。`;
}

function recordObservations(records, { includePolicy = false } = {}) {
  const observations = [];
  const add = (label, value, record) => {
    const text = displayValue(value);
    if (!text || observations.some((item) => item.label === label && item.value === text)) return;
    observations.push({ label, value: text, recordId: String(record?.id || "") });
  };
  for (const record of records) {
    const payload = record.payload || {};
    add("用户请求", payload.command || payload.input, record);
    add("工具参数", payload.params, record);
    add("返回预览", payload.preview, record);
    add("执行状态", payload.execution_status, record);
    add("运行裁决", payload.decision || payload.verdict, record);
    add("记录原因", payload.reason || record.summary, record);
    add("数据来源", payload.source, record);
    add("场景", payload.scenario, record);
    if (isObject(payload.task_spec)) {
      add("任务能力", payload.task_spec.capabilities, record);
      add("允许工具", payload.task_spec.allowed_tools, record);
      add("允许目标", payload.task_spec.allowed_targets, record);
    }
    if (includePolicy) add("策略信号", payload.violations, record);
    if (observations.length >= 10) break;
  }
  return observations.slice(0, 10);
}

function publicEvidenceRecord(record) {
  return {
    id: String(record.id || ""),
    time: String(record.created_at || ""),
    type: String(record.type || ""),
    layer: String(record.layer || ""),
    severity: String(record.severity || ""),
    title: String(record.title || ""),
    summary: humanizeReason(record.summary || record.payload?.reason || ""),
  };
}

function selectionPolicies(node, records, alert) {
  if (!["capability", "taint", "secret", "guard", "decision"].includes(node.kind)
    && !(node.kind === "action" && /BLOCK|DENY|UNSCOPED|REJECT/.test(String(node.state || "").toUpperCase()))) return [];
  return policyCodesForRelation(node.kind === "capability" ? "constrains" : node.kind === "guard" || node.kind === "decision" ? "decides" : "consumes", records, alert);
}

function reachableDecision(graph, startId) {
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const outgoing = new Map();
  for (const edgeValue of graph.edges) outgoing.set(edgeValue.from, [...(outgoing.get(edgeValue.from) || []), edgeValue.to]);
  const queue = [startId];
  const seen = new Set(queue);
  while (queue.length) {
    const current = queue.shift();
    const node = nodeById.get(current);
    if (node?.kind === "decision") return node;
    for (const next of outgoing.get(current) || []) {
      if (seen.has(next)) continue;
      seen.add(next);
      queue.push(next);
    }
  }
  return null;
}

function nodeDisplayTitle(node) {
  if (node.kind === "intent") return "用户任务";
  if (node.kind === "capability") return node.authorized === false ? "未授权能力" : "意图与能力解析";
  if (node.kind === "agent") return "Agent 计划";
  if (node.kind === "action") return "工具动作";
  if (node.kind === "taint") return "不可信数据";
  if (node.kind === "secret") return "敏感数据";
  if (node.kind === "data") return "运行数据";
  if (node.kind === "sink") return "副作用目标";
  if (node.kind === "guard") return "玄鉴执行边界";
  if (node.kind === "decision") return "安全裁决";
  return node.title || node.kindLabel || "语义节点";
}

function nodeEvidenceLabel(node, fallback = "") {
  if (!node) return String(fallback || "未记录");
  const role = nodeDisplayTitle(node);
  const title = String(node.title || "").trim();
  return title && title !== role ? `${role} · ${title}` : role || String(fallback || "未记录");
}

function selectionTone(session, edgeValue, node) {
  const relation = String(edgeValue?.kind || "").toLowerCase();
  if (node?.kind === "decision") return node.state === "ASK" ? "warning" : "safe";
  if (node?.kind === "guard") return session.decision === "ask" ? "warning" : "safe";
  if (["blocked_by", "approved_by", "decides"].includes(relation)) return session.decision === "ask" ? "warning" : "safe";
  if (node?.kind === "taint" || ["taints", "consumes"].includes(relation)) return "danger";
  if (node?.kind === "secret" || node?.kind === "sink" || node?.authorized === false) return "warning";
  if (edgeValue?.onPath && session.decision === "deny") return "warning";
  if (session.decision === "ask") return "warning";
  return "neutral";
}

function evidenceBasisLabel(edgeValue) {
  if (edgeValue.displayOnly || edgeValue.basis === "projection") return "视图投影";
  if (edgeValue.basis === "decoded") return "解码复现";
  if (edgeValue.basis === "conservative") return "保守推断";
  if (edgeValue.basis === "observed") return "运行时观测";
  return String(edgeValue.basis || "");
}

function compactFacts(rows) {
  return rows
    .map(([label, value]) => ({ label: String(label), value: displayValue(value) }))
    .filter((item) => item.value);
}

function displayValue(value) {
  if (value === undefined || value === null || value === "") return "";
  if (Array.isArray(value)) return value.map((item) => String(item)).filter(Boolean).join("、").slice(0, 800);
  if (isObject(value)) {
    try {
      return JSON.stringify(value, null, 2).slice(0, 1200);
    } catch {
      return String(value).slice(0, 1200);
    }
  }
  return String(value).trim().slice(0, 1200);
}

function firstString(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (text) return text;
  }
  return "";
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

export function primaryPathGraph(graph) {
  if (!graph || !Array.isArray(graph.nodes) || graph.nodes.length < 2) return graph;
  const pathIds = new Set(arrayStrings(graph.pathNodeIds));
  for (const node of graph.nodes) {
    // An unauthorized capability explains the denial, but it is supporting context.
    // Keep it for the expanded graph so the default view stays on the causal attack path.
    if ((node.onPath && !(node.kind === "capability" && node.authorized === false))
      || ["taint", "secret", "guard", "decision"].includes(node.kind)) pathIds.add(node.id);
    if (node.kind === "sink" && String(node.effect || "").toLowerCase() === "external") pathIds.add(node.id);
  }

  const intent = graph.nodes.find((node) => node.kind === "intent");
  if (intent) pathIds.add(intent.id);
  const authorizedCapability = graph.nodes.find((node) => node.kind === "capability" && node.authorized === true);
  if (authorizedCapability) pathIds.add(authorizedCapability.id);

  const connectingEdges = graph.edges.filter((edgeValue) => {
    if (pathIds.has(edgeValue.from) && pathIds.has(edgeValue.to)) return true;
    if (edgeValue.kind !== "constrains" || !pathIds.has(edgeValue.to)) return false;
    const source = graph.nodes.find((node) => node.id === edgeValue.from);
    if (source?.kind !== "capability" || source.authorized !== false) pathIds.add(edgeValue.from);
    return true;
  });
  const edges = graph.edges.filter((edgeValue) => pathIds.has(edgeValue.from) && pathIds.has(edgeValue.to)
    && (edgeValue.onPath || edgeValue.displayOnly || connectingEdges.some((item) => item.id === edgeValue.id)));
  const nodes = graph.nodes.filter((node) => pathIds.has(node.id));
  if (nodes.length < 2 || !edges.length) return graph;

  const nodeIdSet = new Set(nodes.map((node) => node.id));
  const edgeIdSet = new Set(edges.map((edgeValue) => edgeValue.id));
  return {
    ...graph,
    nodes,
    edges,
    pathNodeIds: arrayStrings(graph.pathNodeIds).filter((id) => nodeIdSet.has(id)),
    pathEdgeIds: arrayStrings(graph.pathEdgeIds).filter((id) => edgeIdSet.has(id)),
    selectedNodeId: nodeIdSet.has(graph.selectedNodeId)
      ? graph.selectedNodeId
      : [...nodes].reverse().find((node) => node.kind === "decision")?.id || nodes.at(-1)?.id || "",
    primaryView: true,
  };
}

export function buildIncidentConclusion(session) {
  if (!session?.graph) {
    return {
      severity: "等待",
      attackType: "等待事件分析",
      summary: "真实审计事件进入后自动生成攻击结论。",
      result: "等待裁决",
      tone: "neutral",
      policy: "",
      target: "",
    };
  }

  const graph = session.graph;
  const tainted = graph.nodes.some((node) => node.kind === "taint" || String(node.integrity || "").toLowerCase() === "tainted")
    || /taint|prompt.?injection|污染|注入/i.test(`${graph.risk || ""} ${session.title || ""} ${session.subtitle || ""}`);
  const secret = graph.nodes.some((node) => node.kind === "secret" || String(node.confidentiality || "").toLowerCase() === "secret");
  const sink = graph.nodes.find((node) => node.kind === "sink" && String(node.effect || "").toLowerCase() === "external")
    || graph.nodes.find((node) => node.kind === "sink");
  const target = firstString(sink?.rawTarget, sink?.sink, sink?.title).slice(0, 120);
  const policies = Array.from(new Set([
    session.alert?.rule,
    ...(Array.isArray(session.policies) ? session.policies : []),
    ...(Array.isArray(session.reasons) ? session.reasons.map((reason) => reason?.code) : []),
  ].map((value) => String(value || "").trim()).filter(Boolean)));
  const policy = policies.find((value) => /CAPABILITY_RECIPIENT_DENIED/i.test(value))
    || policies.find((value) => /TAINT_TO_EXTERNAL_SINK/i.test(value))
    || policies.find((value) => /CAPABILITY|TAINT|SINK|DENIED|BLOCK/i.test(value))
    || policies[0]
    || "EXECUTION_BOUNDARY";
  const bypass = graph.traceKind === "enforcement_bypass" || graph.risk === "execution_after_block";
  const denied = session.decision === "deny";
  const attackType = tainted ? "Prompt Injection" : secret && target ? "敏感数据外传" : session.decision === "allow" ? "授权工作流" : "未授权工具调用";
  const severity = session.decision === "allow"
    ? "安全"
    : ["critical", "high", "danger"].includes(String(session.severity || "").toLowerCase()) || denied
      ? "高危"
      : "中危";
  const subject = secret || tainted ? "敏感信息" : "高风险数据";
  const destination = target ? `发送到外部目标 ${target}` : "传入外部执行目标";
  const summary = denied
    ? bypass
      ? `攻击触发 ${policy} 后仍出现执行迹象，需要立即核查外部副作用。`
      : `攻击试图将${subject}${destination}，已被 ${policy} 阻断。`
    : session.decision === "ask"
      ? `玄鉴发现高风险工具调用，${policy} 已暂停执行并等待人工确认。`
      : `当前工具调用、参数和目标均处于任务授权范围内。`;
  const result = denied
    ? bypass ? "存在阻断后执行迹象" : target ? "未发生数据泄露" : "危险动作未执行"
    : session.decision === "ask" ? "执行已暂停" : "授权操作已完成";
  return {
    severity,
    attackType,
    summary,
    result,
    tone: denied ? bypass ? "danger" : "safe" : session.decision === "ask" ? "warning" : "safe",
    policy,
    target,
  };
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
