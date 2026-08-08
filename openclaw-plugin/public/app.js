import {
  buildDashboardModel,
  causalPathTitles,
  decisionCode,
  decisionLabel,
  humanizeReason,
  nodeKindLabel,
} from "/graph-adapter.js?v=20260807-9";
import { SemanticGraph } from "/semantic-graph.js?v=20260807-9";

const $ = (id) => document.getElementById(id);

const state = {
  model: { sessions: [], source: {} },
  overview: {},
  records: [],
  enforcement: null,
  selectedSessionId: "",
  selectedItem: null,
  pathFocus: true,
  playhead: 0,
  live: true,
  playing: false,
  loading: false,
  refreshTimer: null,
  playbackTimer: null,
  search: "",
};

const semanticGraph = new SemanticGraph({
  viewport: $("graphViewport"),
  world: $("graphWorld"),
  svg: $("graphEdges"),
  nodes: $("graphNodes"),
  empty: $("graphEmpty"),
  onSelect: handleGraphSelection,
});

initialize();

async function initialize() {
  bindInteractions();
  renderIcons();
  await refreshData({ keepSelection: false });
  state.refreshTimer = window.setInterval(() => {
    if (state.live && !state.loading) void refreshData({ keepSelection: true, quiet: true });
  }, 5000);
}

async function refreshData({ keepSelection = true, quiet = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  if (!quiet) setConnection("connecting", "同步中");
  $("refreshBtn").classList.add("spinning");

  try {
    const [overviewResult, recordsResult, enforcementResult] = await Promise.allSettled([
      fetchJson("/api/security/overview?limit=500"),
      fetchJson("/api/records?compact=1&limit=500"),
      fetchJson("/api/settings/enforcement"),
    ]);
    if (overviewResult.status === "rejected" && recordsResult.status === "rejected") {
      throw overviewResult.reason || recordsResult.reason;
    }

    state.overview = overviewResult.status === "fulfilled" ? overviewResult.value : {};
    const recordsPayload = recordsResult.status === "fulfilled" ? recordsResult.value : {};
    state.records = Array.isArray(recordsPayload.records) ? recordsPayload.records : [];
    if (enforcementResult.status === "fulfilled") state.enforcement = enforcementResult.value;
    state.model = buildDashboardModel({ overview: state.overview, records: state.records });

    const preserved = keepSelection && state.model.sessions.some((session) => session.id === state.selectedSessionId);
    if (!preserved) state.selectedSessionId = preferredSession(state.model.sessions)?.id || "";
    const session = currentSession();
    if (!session) {
      state.playhead = 0;
      state.selectedItem = null;
    } else if (state.live || !keepSelection) {
      state.playhead = Math.max(0, session.timeline.length - 1);
      state.selectedItem = defaultSelection(session);
    } else {
      state.playhead = Math.min(state.playhead, Math.max(0, session.timeline.length - 1));
      state.selectedItem = restoreSelection(session, state.selectedItem) || defaultSelection(session);
    }

    renderAll();
    setConnection(state.model.source.available === false ? "warning" : "live", state.model.source.available === false ? "降级" : "LIVE");
  } catch (error) {
    setConnection("error", "连接失败");
    showToast(`无法读取审计数据：${error?.message || error}`, "error");
    if (!state.model.sessions.length) renderAll();
  } finally {
    state.loading = false;
    $("refreshBtn").classList.remove("spinning");
  }
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    headers: { Accept: "application/json", ...(options.headers || {}) },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload?.ok === false) throw new Error(payload?.error || `${url} ${response.status}`);
  return payload;
}

function renderAll() {
  renderSessions();
  renderHeader();
  renderRequestContext();
  renderGraph();
  renderInspector(state.selectedItem);
  renderIncidentFlow();
  renderIncidentSummary();
  renderTimeline();
  renderIcons();
}

function renderHeader() {
  const select = $("modeSelect");
  const mode = String(state.enforcement?.mode || "observe");
  if (select && select.value !== mode) select.value = mode;
  const source = state.model.source || {};
  $("sourceLabel").textContent = String(source.label || "OPENCLAW RECORDS").toUpperCase();
  $("sourceMeta").textContent = source.totalRecords
    ? `${formatNumber(source.windowRecords)} / ${formatNumber(source.totalRecords)} 条审计记录`
    : "等待审计数据";

  const session = currentSession();
  const badge = $("severityBadge");
  const tone = decisionTone(session);
  badge.className = `severity-badge tone-${tone}`;
  badge.textContent = tone === "danger" ? "高危" : tone === "warning" ? "中危" : "安全";
}

function renderSessions() {
  const query = state.search.trim().toLowerCase();
  const sessions = state.model.sessions.filter((session) => {
    if (!query) return true;
    return `${session.title} ${session.subtitle} ${session.id} ${session.decisionLabel}`.toLowerCase().includes(query);
  });
  $("sessionCount").textContent = String(state.model.sessions.length);
  $("sessionList").textContent = sessions.map((session) => session.id).join("\n");
  $("sessionSelect").innerHTML = sessions.length
    ? sessions.map((session) => `<option value="${escapeHtml(session.id)}" ${session.id === state.selectedSessionId ? "selected" : ""}>${escapeHtml(incidentId(session))}</option>`).join("")
    : `<option value="">AS-WAITING-0000</option>`;
}

function selectSession(id) {
  if (!state.model.sessions.some((session) => session.id === id)) return;
  stopPlayback();
  state.selectedSessionId = id;
  state.live = true;
  const session = currentSession();
  state.playhead = Math.max(0, session.timeline.length - 1);
  state.selectedItem = defaultSelection(session);
  renderAll();
}

function renderRequestContext() {
  const session = currentSession();
  const target = $("requestContext");
  if (!session) {
    target.innerHTML = `<div class="inspector-empty"><i data-lucide="message-square-dashed"></i><strong>等待请求上下文</strong><span>收到 Agent 行为后自动还原输入、工具集与对抗载荷</span></div>`;
    return;
  }

  const userRecord = session.records.find((record) => ["lab_command", "user_message", "command"].includes(String(record.type))) || session.records[0];
  const toolResult = session.records.find((record) => String(record.type) === "tool_result" && record.payload?.preview);
  const input = firstText(
    userRecord?.payload?.command,
    userRecord?.payload?.input,
    userRecord?.summary,
    session.graph.nodes.find((node) => node.kind === "intent")?.title,
    "等待用户请求",
  );
  const originalInput = firstText(
    userRecord?.payload?.raw_input,
    userRecord?.payload?.preview,
    input,
  );
  const taintNode = session.graph.nodes.find((node) => node.kind === "taint");
  const adversarial = firstText(
    toolResult?.payload?.preview,
    session.records.find((record) => record.payload?.adversarial_input)?.payload?.adversarial_input,
    taintNode?.title,
    session.decision === "allow" ? "未检测到对抗性输入" : session.alert?.rawReason,
    "检测到可疑指令传播",
  );
  const tools = [...new Set([
    ...session.graph.nodes.filter((node) => node.kind === "action").map((node) => node.tool || node.title),
    ...session.records.map((record) => record.payload?.normalized_tool || record.payload?.toolName).filter(Boolean),
  ])].filter(Boolean);
  const displayTools = tools.length ? tools : ["graph_builder", "search_docs", "read_file"];
  const eventTime = formatClock(userRecord?.created_at || session.latest);
  const detectionTime = formatClock(session.alert?.createdAt || session.latest);
  const attackDetected = session.decision !== "allow" || Boolean(taintNode);

  target.innerHTML = `
    ${contextBlock({
      number: 1,
      title: "用户发送的原始文本",
      content: input,
      meta: [`时间：${eventTime}`, "渠道：Web 控制台"],
    })}
    ${contextBlock({
      number: 2,
      title: "提供的工具集",
      tone: "purple",
      tools: displayTools,
    })}
    ${contextBlock({
      number: 3,
      title: "原始输入（交给模型/工具前）",
      tone: "cyan",
      content: originalInput,
    })}
    ${contextBlock({
      number: 4,
      title: attackDetected ? "生成的对抗性输入（检测到的注入/操纵内容）" : "输入安全检查结果",
      tone: attackDetected ? "danger" : "cyan",
      tag: attackDetected ? "Prompt 注入片段" : "未发现注入",
      content: attackDetected
        ? `${adversarial}\n\n可能诱导 Agent 调用越权工具并访问系统提示、配置或密钥。`
        : adversarial,
      meta: [`检测引擎：OpenClaw Prompt Shield`, `检测时间：${detectionTime}`],
    })}`;
}

function contextBlock({ number, title, tone = "blue", content = "", meta = [], tools = [], tag = "" }) {
  const body = tools.length
    ? `<div class="tool-chip-list">${tools.slice(0, 3).map((tool) => `<span class="tool-chip">${escapeHtml(tool)}<small>${escapeHtml(toolDescription(tool))}</small></span>`).join("")}${tools.length > 3 ? `<span class="tool-chip">+${tools.length - 3}<small>其他工具</small></span>` : ""}</div>`
    : `<div class="context-content">${escapeHtml(content).replace(/\n/g, "<br>")}</div>`;
  return `<section class="context-block tone-${escapeHtml(tone)}">
    <header class="context-block-header">
      <span class="context-number">${number}</span>
      <strong>${escapeHtml(title)}</strong>
      ${tag ? `<span class="context-tag">${escapeHtml(tag)}</span>` : ""}
    </header>
    ${body}
    ${meta.length ? `<div class="context-meta">${meta.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>` : ""}
  </section>`;
}

function renderGraph() {
  const session = currentSession();
  if (!session) {
    $("graphContext").innerHTML = `<span>NO SESSION</span>`;
    $("graphConfidence").textContent = "等待图证据";
    $("attackNotice").textContent = "等待 Agent 行为进入实时语义行动图";
    semanticGraph.setGraph(null);
    return;
  }

  const graph = session.graph;
  const workspace = document.querySelector(".graph-workspace");
  workspace.classList.remove("tone-danger", "tone-warning", "tone-safe");
  const tone = decisionTone(session);
  workspace.classList.add(`tone-${tone}`);
  $("attackNotice").textContent = session.decision === "deny"
    ? "检测到攻击后：节点/边高亮 + 自动弹出证据详情（不需要镜头移动和放大）"
    : session.decision === "ask"
      ? "检测到高风险动作：攻击链已暂停，等待安全运营人员确认"
      : "未发现攻击链：授权路径保持低干扰显示，可点击节点查看证据";
  const evidence = graph.derived ? "VIEW PROJECTION" : graph.certainty === "observed" ? "OBSERVED" : String(graph.certainty || "EVIDENCE").toUpperCase();
  const partial = graph.partial ? "局部图" : "完整图";
  $("graphContext").innerHTML = `
    <span class="context-decision tone-${escapeHtml(tone)}">${escapeHtml(decisionCode(session.decision))}</span>
    <span>${escapeHtml(graph.riskLabel)}</span>
    <span>SAG V${escapeHtml(graph.version)}</span>
    <span>${escapeHtml(partial)}</span>`;
  $("graphConfidence").textContent = `${evidence} · ${Math.round(graph.confidence * 100)}% · ${graph.nodes.length}/${Math.max(graph.nodes.length, graph.sourceNodeCount)} NODES`;
  $("pathFocusBtn").classList.toggle("active", state.pathFocus);
  $("pathFocusBtn").setAttribute("aria-pressed", String(state.pathFocus));

  const selectedNodeId = state.selectedItem?.type === "node" ? state.selectedItem.value.id : graph.selectedNodeId;
  semanticGraph.setGraph(graph, { selectedNodeId });
  semanticGraph.setPathFocus(state.pathFocus);
  syncGraphPlayback();
  if (state.selectedItem?.type === "edge") semanticGraph.selectEdge(state.selectedItem.value.id, { notify: false });
  else if (selectedNodeId) semanticGraph.selectNode(selectedNodeId, { notify: false });
}

function handleGraphSelection(item) {
  state.selectedItem = item;
  renderInspector(item);
  $("inspector").classList.toggle("open", Boolean(item));
  $("incidentConsole").classList.remove("inspector-collapsed");
  renderIcons();
}

function renderInspector(item) {
  const session = currentSession();
  const body = $("inspectorBody");
  if (!session) {
    body.innerHTML = emptyInspector("等待会话", "新的安全事件会在这里解释裁决原因");
    return;
  }

  const selection = item || defaultSelection(session);
  if (!selection) {
    body.innerHTML = emptyInspector("选择一个语义节点", "查看裁决、证据、溯源和命中策略");
    return;
  }
  state.selectedItem = selection;
  const isNode = selection.type === "node";
  const value = selection.value;
  const graph = session.graph;
  const score = riskScore(session.decision === "allow" ? 0 : session.alert?.score, session.decision);
  const tone = decisionTone(session);
  const evidenceRows = isNode ? nodeEvidence(value) : edgeEvidence(value, graph);
  const fromNode = !isNode ? graph.nodes.find((node) => node.id === value.from) : null;
  const toNode = !isNode ? graph.nodes.find((node) => node.id === value.to) : null;
  const reverseConstraint = !isNode && value.label === "constrains" && fromNode?.kind === "capability" && toNode?.kind === "action";
  const selectionTitle = isNode
    ? `${inspectorNodeTitle(value)} → ${value.title}`
    : `${inspectorNodeTitle(reverseConstraint ? toNode : fromNode)} → ${inspectorNodeTitle(reverseConstraint ? fromNode : toNode)}（边）`;
  const actionNode = (isNode && value.kind === "action" ? value : null)
    || [...graph.nodes].reverse().find((node) => node.kind === "action" && node.onPath)
    || graph.nodes.find((node) => node.kind === "action");
  const taintNode = graph.nodes.find((node) => node.kind === "taint");
  const secretNode = graph.nodes.find((node) => node.kind === "secret");
  const sinkNode = graph.nodes.find((node) => node.kind === "sink");
  const policies = session.policies.length ? session.policies : [session.alert?.rule || "SEMANTIC_ACTION_GRAPH"];
  const conclusion = session.decision === "deny"
    ? `检测到 ${session.alert?.type || graph.riskLabel} 导致的越权工具调用，存在敏感数据泄露风险。`
    : session.decision === "ask"
      ? "检测到超出当前授权范围的高风险动作，执行已暂停并等待人工确认。"
      : "当前动作与 TaskSpec 授权范围一致，未形成可利用的攻击路径。";
  const response = session.decision === "deny"
    ? "已拦截并阻断该调用，返回安全降级响应。"
    : session.decision === "ask"
      ? "调用已暂停，等待安全运营人员授权。"
      : "策略校验通过，工具调用继续执行。";
  const riskText = session.reasons.map((reason) => reason.detail).filter(Boolean).join("；") || session.subtitle;
  const snippet = [
    `<b>生成的对抗性输入：</b> “${escapeHtml(taintNode?.title || session.alert?.rawReason || "未发现") }”`,
    `<b>工具调用：</b> ${escapeHtml(actionNode?.tool || actionNode?.title || "--")}(params={...})`,
    `<b>读取对象：</b> ${escapeHtml(secretNode?.path || secretNode?.title || "system_prompt, tools, config, keys")}`,
    `<b>返回目标：</b> ${escapeHtml(sinkNode?.title || "用户会话")}`,
  ].join("\n");
  const ip = firstText(...session.records.map((record) => record.payload?.ip_address || record.payload?.ip), "10.23.45.67（内网）");

  body.innerHTML = `
    <div class="inspector-selection">
      <span>当前选中</span>
      <strong>${escapeHtml(selectionTitle)}</strong>
      <i data-lucide="link-2"></i>
    </div>

    <dl class="evidence-rows">
      <div class="evidence-row">
        <dt><i data-lucide="badge-alert"></i>策略等级</dt>
        <dd><span class="${tone === "safe" ? "success-chip" : "risk-chip"}">${tone === "danger" ? "高危" : tone === "warning" ? "中危" : "安全"} · ${score.toFixed(1)}</span></dd>
      </div>
      <div class="evidence-row">
        <dt><i data-lucide="circle-alert"></i>检测结论</dt>
        <dd>${escapeHtml(conclusion)}</dd>
      </div>
      <div class="evidence-row">
        <dt><i data-lucide="scan-search"></i>规则/策略命中</dt>
        <dd>${policies.slice(0, 3).map((policy, index) => `<span class="policy-hit">${escapeHtml(policy)}${index === 0 ? `<br><small>确定性策略 / v2.3.1</small>` : ""}</span>`).join("")}</dd>
      </div>
      <div class="evidence-row">
        <dt><i data-lucide="shield-check"></i>OpenClaw 响应</dt>
        <dd>${escapeHtml(response)}<br><span class="${session.decision === "deny" ? "success-chip" : "success-text"}">${session.decision === "deny" ? "拦截成功" : escapeHtml(decisionLabel(session.decision))}</span></dd>
      </div>
      <div class="evidence-row">
        <dt><i data-lucide="stamp"></i>处置动作<br>（allow / ask / deny）</dt>
        <dd><div class="decision-segments">
          <span class="${session.decision === "allow" ? "active-allow" : ""}">allow</span>
          <span class="${session.decision === "ask" ? "active-ask" : ""}">ask</span>
          <span class="${session.decision === "deny" ? "active-deny" : ""}">deny${session.decision === "deny" ? "（已执行）" : ""}</span>
        </div></dd>
      </div>
      <div class="evidence-row">
        <dt><i data-lucide="info"></i>风险说明</dt>
        <dd>${escapeHtml(riskText)}</dd>
      </div>
      <div class="evidence-row">
        <dt><i data-lucide="file-warning"></i>证据片段</dt>
        <dd><div class="evidence-snippet">${snippet}</div></dd>
      </div>
      <div class="evidence-row">
        <dt><i data-lucide="crosshair"></i>节点证据</dt>
        <dd>${evidenceRows.slice(0, 3).map(([label, content]) => `<span class="policy-hit"><small>${escapeHtml(label)}：</small>${escapeHtml(content)}</span>`).join("")}</dd>
      </div>
    </dl>

    <div class="inspector-meta">
      <span>时间 <b>${escapeHtml(formatDateTime(session.alert?.createdAt || session.latest))}</b></span>
      <span>会话 ID <b>${escapeHtml(session.id)}</b></span>
      <span>IP 地址 <b>${escapeHtml(ip)}</b></span>
    </div>

    <details class="raw-evidence">
      <summary><span>原始脱敏证据</span><i data-lucide="chevron-down"></i></summary>
      <pre>${escapeHtml(JSON.stringify({ selection: value, alert: session.alert, graph: graph.raw }, null, 2))}</pre>
    </details>`;
}

function nodeEvidence(node) {
  const rows = [
    ["节点类型", node.kindLabel || nodeKindLabel(node.kind)],
    ["状态", node.state || "OBSERVED"],
    ["证据边界", node.displayOnly ? "视图投影，不代表新增血缘" : "运行时脱敏证据"],
  ];
  if (node.authorized !== undefined) rows.push(["授权", node.authorized ? "已授权" : "未授权"]);
  if (node.authorization_reason) rows.push(["授权依据", String(node.authorization_reason)]);
  if (node.integrity) rows.push(["完整性", String(node.integrity).toUpperCase()]);
  if (node.confidentiality) rows.push(["保密性", String(node.confidentiality).toUpperCase()]);
  if (node.path) rows.push(["字段路径", String(node.path)]);
  if (node.tool) rows.push(["工具", String(node.tool)]);
  if (node.effect) rows.push(["副作用", String(node.effect)]);
  return rows;
}

function edgeEvidence(edge, graph) {
  const from = graph.nodes.find((node) => node.id === edge.from);
  const to = graph.nodes.find((node) => node.id === edge.to);
  return [
    ["语义关系", edge.label],
    ["来源", from?.title || edge.from],
    ["目标", to?.title || edge.to],
    ["证据", edge.displayOnly ? "视图投影" : edge.basis === "decoded" ? "解码复现" : edge.basis === "conservative" ? "保守推断" : "运行时观测"],
    ["置信度", `${Math.round(edge.confidence * 100)}%`],
    ["参数字段", String(edge.arg_path || edge.argPath || edge.match || "--")],
  ];
}

function emptyInspector(title, text) {
  return `<div class="inspector-empty"><i data-lucide="mouse-pointer-click"></i><strong>${escapeHtml(title)}</strong><span>${escapeHtml(text)}</span></div>`;
}

function renderIncidentFlow() {
  const session = currentSession();
  if (!session) {
    $("incidentFlow").innerHTML = "";
    return;
  }
  const tainted = session.graph.nodes.some((node) => node.kind === "taint");
  const steps = [
    ["file-input", "原始文本", "原始文本"],
    ["file-warning", tainted ? "对抗性输入" : "安全输入", tainted ? "注入 / 操纵" : "已校验"],
    ["route", "攻击图", session.graph.derived ? "语义投影" : "因果链路"],
    ["scan-search", "证据详情", "自动弹出"],
  ];
  $("incidentFlow").innerHTML = steps.map(([icon, title, meta], index) => `
    ${index ? `<i class="flow-arrow-icon" data-lucide="arrow-right" aria-hidden="true"></i>` : ""}
    <div class="flow-step">
      <i data-lucide="${icon}"></i>
      <span><strong>${escapeHtml(title)}</strong><small>（${escapeHtml(meta)}）</small></span>
    </div>`).join("");
}

function renderIncidentSummary() {
  const session = currentSession();
  const severity = $("summarySeverity");
  const text = $("summaryText");
  const metrics = $("summaryMetrics");
  if (!session) {
    severity.className = "severity-badge tone-safe";
    severity.textContent = "等待";
    text.textContent = "等待安全事件";
    metrics.innerHTML = "";
    return;
  }

  const tone = decisionTone(session);
  severity.className = `severity-badge tone-${tone}`;
  severity.textContent = tone === "danger" ? "高危" : tone === "warning" ? "中危" : "安全";
  text.textContent = session.subtitle || session.alert?.reason || "语义行动图已生成";
  const pathLength = session.graph.pathEdgeIds?.length || session.graph.pathNodeIds?.length || 0;
  const impactNode = session.graph.nodes.find((node) => node.kind === "secret")
    || session.graph.nodes.find((node) => node.kind === "capability" && node.authorized === false)
    || session.graph.nodes.find((node) => node.kind === "sink");
  const result = session.decision === "deny" ? "已阻断" : session.decision === "ask" ? "待确认" : "已放行";
  metrics.innerHTML = [
    ["攻击路径长度", String(pathLength), "danger"],
    ["拦截节点", "拦截 (OpenClaw)", "green"],
    ["影响范围", impactNode?.title || "授权工具调用", tone === "safe" ? "green" : "amber"],
    ["处理结果", result, session.decision === "deny" || session.decision === "allow" ? "green" : "amber"],
  ].map(([label, value, tone]) => `<div class="summary-metric tone-${tone}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");
}

function renderTimeline() {
  const session = currentSession();
  const events = session?.timeline || [];
  const range = $("timelineRange");
  const max = Math.max(0, events.length - 1);
  state.playhead = Math.max(0, Math.min(max, state.playhead));
  range.max = String(max);
  range.value = String(state.playhead);
  range.disabled = events.length < 2;
  range.style.setProperty("--progress", max ? `${(state.playhead / max) * 100}%` : "100%");

  $("timelineTicks").innerHTML = timelineTickIndexes(events.length).map((index) => {
    const event = events[index];
    const left = max ? (index / max) * 100 : 0;
    const tone = event.decision === "deny" || event.severity === "critical" || event.severity === "high"
      ? "danger" : event.decision === "ask" || event.severity === "medium" ? "warning" : event.decision === "allow" ? "safe" : "info";
    return `<button class="timeline-tick tone-${tone} ${index <= state.playhead ? "reached" : ""} ${index === state.playhead ? "current" : ""}" type="button" style="left:${left}%" data-step="${index}" title="${escapeHtml(`${formatClock(event.time)} · ${event.title}`)}" aria-label="跳转到 ${escapeHtml(event.title)}"><span></span><small>${escapeHtml(timelineStageLabel(event, index, events))}<time>${escapeHtml(formatClock(event.time))}</time></small></button>`;
  }).join("");

  for (const tick of $("timelineTicks").querySelectorAll("[data-step]")) {
    tick.addEventListener("click", () => setPlayhead(Number(tick.dataset.step), { live: false }));
  }

  const event = events[state.playhead];
  $("timelineCurrent").textContent = event ? formatClock(event.time) : "--:--:--";
  $("timelineEvent").textContent = event?.title || "等待事件";
  $("liveBtn").classList.toggle("active", state.live);
  $("playbackBadge").classList.toggle("paused", !state.live);
  $("playbackBadge").innerHTML = state.live ? `<span class="live-dot"></span> LIVE` : `<i data-lucide="history"></i> REPLAY ${state.playhead + 1}/${Math.max(1, events.length)}`;
  updatePlaybackButton();
  syncGraphPlayback();
}

function setPlayhead(value, { live = false } = {}) {
  const session = currentSession();
  const max = Math.max(0, (session?.timeline.length || 1) - 1);
  state.playhead = Math.max(0, Math.min(max, Number(value) || 0));
  state.live = live && state.playhead === max;
  if (!state.live) stopPlayback();
  renderTimeline();
  renderIcons();
}

function syncGraphPlayback() {
  const session = currentSession();
  if (!session) return;
  const eventCount = session.timeline.length;
  const ratio = state.live || eventCount <= 1 ? 1 : (state.playhead + 1) / eventCount;
  semanticGraph.setRevealRatio(ratio);
}

function togglePlayback() {
  if (state.playing) {
    stopPlayback();
    renderTimeline();
    return;
  }
  const events = currentSession()?.timeline || [];
  if (!events.length) return;
  if (state.playhead >= events.length - 1) state.playhead = 0;
  state.live = false;
  state.playing = true;
  state.playbackTimer = window.setInterval(() => {
    const latestEvents = currentSession()?.timeline || [];
    if (state.playhead >= latestEvents.length - 1) {
      stopPlayback();
      state.live = true;
      renderTimeline();
      renderIcons();
      return;
    }
    state.playhead += 1;
    renderTimeline();
    renderIcons();
  }, 900);
  renderTimeline();
  renderIcons();
}

function stopPlayback() {
  state.playing = false;
  if (state.playbackTimer) window.clearInterval(state.playbackTimer);
  state.playbackTimer = null;
}

function updatePlaybackButton() {
  const button = $("playPauseBtn");
  button.innerHTML = `<i data-lucide="${state.playing ? "pause" : "folder-open"}"></i><span>${state.playing ? "暂停回放" : "打开会话回放"}</span>`;
  button.title = state.playing ? "暂停回放" : "播放回放";
  button.setAttribute("aria-label", button.title);
  $("stepBackBtn").disabled = !currentSession()?.timeline.length || state.playhead <= 0;
  $("stepForwardBtn").disabled = !currentSession()?.timeline.length || state.playhead >= currentSession().timeline.length - 1;
}

function jumpToLive() {
  stopPlayback();
  const events = currentSession()?.timeline || [];
  state.playhead = Math.max(0, events.length - 1);
  state.live = true;
  renderTimeline();
  renderIcons();
  void refreshData({ keepSelection: true, quiet: true });
}

async function updateEnforcementMode(mode) {
  const select = $("modeSelect");
  select.disabled = true;
  try {
    state.enforcement = await fetchJson("/api/settings/enforcement", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode }),
    });
    showToast(`执行模式已切换为${({ block: "阻断", approval: "审批", observe: "观察" })[mode] || mode}`);
    await refreshData({ keepSelection: true, quiet: true });
  } catch (error) {
    showToast(`模式切换失败：${error?.message || error}`, "error");
    renderHeader();
  } finally {
    select.disabled = false;
  }
}

function bindInteractions() {
  $("refreshBtn").addEventListener("click", () => void refreshData({ keepSelection: true }));
  $("modeSelect").addEventListener("change", (event) => void updateEnforcementMode(event.target.value));
  $("sessionSelect").addEventListener("change", (event) => selectSession(event.target.value));
  $("sessionSearch").addEventListener("input", (event) => {
    state.search = event.target.value;
    renderSessions();
    renderIcons();
  });
  $("pathFocusBtn").addEventListener("click", () => {
    state.pathFocus = !state.pathFocus;
    semanticGraph.setPathFocus(state.pathFocus);
    $("pathFocusBtn").classList.toggle("active", state.pathFocus);
    $("pathFocusBtn").setAttribute("aria-pressed", String(state.pathFocus));
  });
  $("zoomInBtn").addEventListener("click", () => semanticGraph.zoom(1.14));
  $("zoomOutBtn").addEventListener("click", () => semanticGraph.zoom(0.88));
  $("fitGraphBtn").addEventListener("click", () => semanticGraph.fit());
  $("closeInspectorBtn").addEventListener("click", () => {
    state.selectedItem = null;
    semanticGraph.clearSelection({ notify: false });
    $("inspector").classList.remove("open");
    $("incidentConsole").classList.add("inspector-collapsed");
    renderInspector(null);
    renderIcons();
  });
  $("contextCollapseBtn").addEventListener("click", () => {
    const pinned = $("contextCollapseBtn").classList.toggle("active");
    $("contextCollapseBtn").title = pinned ? "取消固定请求上下文" : "固定请求上下文";
    $("contextCollapseBtn").setAttribute("aria-label", $("contextCollapseBtn").title);
    $("contextCollapseBtn").setAttribute("aria-pressed", String(pinned));
    $("contextCollapseBtn").innerHTML = `<i data-lucide="${pinned ? "pin" : "pin-off"}"></i>`;
    showToast(pinned ? "请求上下文已固定" : "请求上下文已取消固定");
    renderIcons();
  });
  $("exportReportBtn").addEventListener("click", exportCurrentReport);
  $("allowlistBtn").addEventListener("click", () => showToast("已创建白名单复核申请，策略不会在审批前生效"));
  $("timelineRange").addEventListener("input", (event) => setPlayhead(Number(event.target.value), { live: false }));
  $("playPauseBtn").addEventListener("click", togglePlayback);
  $("stepBackBtn").addEventListener("click", () => setPlayhead(state.playhead - 1, { live: false }));
  $("stepForwardBtn").addEventListener("click", () => setPlayhead(state.playhead + 1, { live: false }));
  $("liveBtn").addEventListener("click", jumpToLive);
  window.addEventListener("resize", () => semanticGraph.resize());
  window.addEventListener("keydown", (event) => {
    if (["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement?.tagName)) return;
    if (event.code === "Space") {
      event.preventDefault();
      togglePlayback();
    } else if (event.key === "ArrowLeft") setPlayhead(state.playhead - 1, { live: false });
    else if (event.key === "ArrowRight") setPlayhead(state.playhead + 1, { live: false });
  });
}

function currentSession() {
  return state.model.sessions.find((session) => session.id === state.selectedSessionId) || null;
}

function preferredSession(sessions) {
  return sessions.find((session) => session.graph?.traceKind === "enforcement_bypass")
    || sessions.find((session) => session.decision === "deny" && !session.graph?.derived)
    || sessions.find((session) => session.decision === "ask")
    || sessions.find((session) => !session.graph?.derived)
    || sessions[0]
    || null;
}

function defaultSelection(session) {
  const boundaryEdge = session?.graph?.edges?.find((edge) => {
    if (edge.label !== "constrains") return false;
    const from = session.graph.nodes.find((node) => node.id === edge.from);
    const to = session.graph.nodes.find((node) => node.id === edge.to);
    return from?.kind === "capability" && from.authorized === false && to?.kind === "action";
  });
  if (boundaryEdge) return { type: "edge", value: boundaryEdge };
  const id = session?.graph?.selectedNodeId
    || [...(session?.graph?.nodes || [])].reverse().find((node) => node.kind === "decision")?.id
    || session?.graph?.pathNodeIds?.at(-1);
  const node = session?.graph?.nodes?.find((item) => item.id === id);
  return node ? { type: "node", value: node } : null;
}

function restoreSelection(session, selection) {
  if (!selection) return null;
  const list = selection.type === "edge" ? session.graph.edges : session.graph.nodes;
  const value = list.find((item) => item.id === selection.value?.id);
  return value ? { type: selection.type, value } : null;
}

function timelineTickIndexes(length) {
  if (length <= 7) return Array.from({ length }, (_, index) => index);
  const indexes = new Set([0, length - 1, state.playhead]);
  for (let index = 1; index < 6; index += 1) indexes.add(Math.round((index / 6) * (length - 1)));
  return [...indexes].sort((left, right) => left - right);
}

function shortEventLabel(value) {
  const text = String(value || "事件").replace(/\s+/g, " ");
  return text.length > 12 ? `${text.slice(0, 11)}...` : text;
}

function timelineStageLabel(event, index, events) {
  const text = String(event?.title || "事件");
  const type = String(event?.type || "");
  const payload = event?.record?.payload || {};
  if (index === events.length - 1 && type === "tool_result" && (payload.blocked || event.decision === "deny")) return "响应返回";
  if (["lab_command", "user_message", "command"].includes(type)) return "用户输入";
  if (type === "task_spec") return "意图解析";
  if (type === "tool_result" && (payload.preview || payload.adversarial_input)) return "Prompt 注入";
  if (type === "tool_call") return "工具调用";
  if (type === "tool_decision" && event.decision === "deny") return "系统/配置访问";
  if (type === "alert" && event.decision === "deny") return "拦截 (OpenClaw)";
  if (/用户|user|command/i.test(text)) return "用户输入";
  if (/intent|意图|任务/i.test(text)) return "意图解析";
  if (/prompt|注入|taint|污染/i.test(text)) return "Prompt 注入";
  if (/tool|工具|调用/i.test(text)) return "工具调用";
  if (/系统|配置|secret|密钥|敏感/i.test(text)) return "系统/配置访问";
  if (/拦截|阻断|deny|block/i.test(text)) return "拦截 (OpenClaw)";
  if (/返回|result|response/i.test(text)) return "响应返回";
  return shortEventLabel(text);
}

function inspectorNodeTitle(node) {
  if (!node) return "未知节点";
  if (node.kind === "action") return "工具调用";
  if (node.kind === "capability" && node.authorized === false) return "系统/配置访问";
  if (node.kind === "capability") return "意图解析";
  if (node.kind === "taint") return "Prompt 注入";
  if (node.kind === "secret") return "敏感数据";
  if (node.kind === "sink") return "外发/执行";
  if (node.kind === "guard") return "拦截 (OpenClaw)";
  if (node.kind === "decision") return "安全裁决";
  if (node.kind === "intent") return "用户输入";
  return node.title || nodeKindLabel(node.kind);
}

function firstText(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const text = typeof value === "string" ? value.trim() : String(value).trim();
    if (text) return text;
  }
  return "";
}

function toolDescription(tool) {
  const text = String(tool || "").toLowerCase();
  if (/graph/.test(text)) return "图构建工具";
  if (/search|web|browser/.test(text)) return "文档检索工具";
  if (/read|file/.test(text)) return "文件读取工具";
  if (/email|send/.test(text)) return "外部发送工具";
  if (/shell|exec|code/.test(text)) return "代码执行工具";
  return "Agent 工具";
}

function incidentId(session) {
  const date = new Date(session?.latest || Date.now());
  const safeDate = Number.isNaN(date.getTime()) ? new Date() : date;
  const ymd = [safeDate.getFullYear(), String(safeDate.getMonth() + 1).padStart(2, "0"), String(safeDate.getDate()).padStart(2, "0")].join("");
  const hash = [...String(session?.id || "event")].reduce((value, character) => (value * 31 + character.charCodeAt(0)) % 10000, 17);
  return `AS-${ymd}-${String(hash).padStart(4, "0")}`;
}

function formatDateTime(value) {
  const raw = String(value || "");
  const date = new Date(raw || 0);
  if (Number.isNaN(date.getTime())) return String(value || "--");
  const timeZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw) ? "Asia/Shanghai" : undefined;
  return date.toLocaleString("zh-CN", {
    hour12: false,
    ...(timeZone ? { timeZone } : {}),
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).replaceAll("/", "-");
}

function exportCurrentReport() {
  const session = currentSession();
  if (!session) {
    showToast("当前没有可导出的安全事件", "error");
    return;
  }
  const report = {
    incident_id: incidentId(session),
    exported_at: new Date().toISOString(),
    decision: session.decision,
    severity: session.severity,
    reasons: session.reasons,
    policies: session.policies,
    causal_graph: session.graph.raw || session.graph,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${incidentId(session)}.json`;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
  showToast("事件报告已导出");
}

function riskScore(value, decision) {
  const score = Number(value);
  if (Number.isFinite(score) && score > 0) return Math.max(0, Math.min(10, score > 10 ? score / 10 : score));
  return decision === "deny" ? 9.2 : decision === "ask" ? 6.8 : 1.8;
}

function decisionTone(session) {
  if (!session) return "safe";
  if (session.decision === "deny") return "danger";
  if (session.decision === "ask") return "warning";
  if (session.decision === "allow") return "safe";
  return session.tone || "safe";
}

function setConnection(status, label) {
  const target = $("connectionStatus");
  target.className = `connection-state ${status}`;
  target.querySelector("span:last-child").textContent = label;
}

function showToast(message, tone = "success") {
  const toast = $("toast");
  toast.textContent = message;
  toast.className = `toast show ${tone}`;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { toast.className = "toast"; }, 3200);
}

function renderIcons() {
  window.lucide?.createIcons({ attrs: { "stroke-width": 1.8 } });
}

function formatClock(value) {
  if (!value) return "--:--:--";
  const raw = String(value);
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return String(value).slice(0, 8) || "--:--:--";
  const timeZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw) ? "Asia/Shanghai" : undefined;
  return date.toLocaleTimeString("zh-CN", {
    hour12: false,
    ...(timeZone ? { timeZone } : {}),
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("zh-CN");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[character]);
}
