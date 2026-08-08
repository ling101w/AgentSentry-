import {
  buildDashboardModel,
  buildSelectionEvidence,
  decisionCode,
} from "/graph-adapter.js?v=20260808-10";
import { SemanticGraph } from "/semantic-graph.js?v=20260808-10";

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
      fetchJson("/api/records?limit=500"),
      fetchJson("/api/settings/enforcement"),
    ]);
    if (overviewResult.status === "rejected" && recordsResult.status === "rejected") {
      throw overviewResult.reason || recordsResult.reason;
    }

    state.overview = overviewResult.status === "fulfilled" ? overviewResult.value : {};
    const recordsPayload = recordsResult.status === "fulfilled" ? recordsResult.value : {};
    state.records = Array.isArray(recordsPayload.records) ? recordsPayload.records : [];
    if (enforcementResult.status === "fulfilled") state.enforcement = enforcementResult.value;
    state.model = buildDashboardModel({ overview: state.overview, records: state.records, recordsMeta: recordsPayload });

    const preserved = keepSelection && state.model.sessions.some((session) => session.id === state.selectedSessionId);
    if (!preserved) state.selectedSessionId = preferredSession(state.model.sessions)?.id || "";
    const session = currentSession();
    if (!session) {
      state.playhead = 0;
      state.selectedItem = null;
    } else {
      state.playhead = state.live
        ? Math.max(0, session.timeline.length - 1)
        : Math.min(state.playhead, Math.max(0, session.timeline.length - 1));
      state.selectedItem = keepSelection
        ? restoreSelection(session, state.selectedItem) || defaultSelection(session)
        : defaultSelection(session);
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
  const mode = String(state.enforcement?.mode || "");
  if (select && mode && select.value !== mode) select.value = mode;
  const source = state.model.source || {};
  $("sourceLabel").textContent = String(source.label || "玄鉴审计记录").toUpperCase();
  $("sourceMeta").textContent = source.totalRecords
    ? `${formatNumber(source.windowRecords)} / ${formatNumber(source.totalRecords)} 条审计记录`
    : "等待审计数据";
  const alertCount = Math.max(0, Number(source.alertCount) || 0);
  for (const id of ["headerAlertCount", "navAlertCount"]) {
    const target = $(id);
    if (!target) continue;
    target.textContent = alertCount > 99 ? "99+" : String(alertCount);
    target.hidden = alertCount === 0;
  }
  const runtimeProfile = $("runtimeProfile");
  if (runtimeProfile) {
    runtimeProfile.textContent = [state.enforcement?.profile, mode].filter(Boolean).join(" · ") || "未记录";
  }

  const session = currentSession();
  const badge = $("severityBadge");
  const tone = decisionTone(session);
  badge.className = `severity-badge tone-${tone}`;
  badge.textContent = !session ? "等待" : tone === "danger" ? "高危" : tone === "warning" ? "中危" : "安全";
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
    : `<option value="">等待事件</option>`;
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

  const context = session.requestContext || {};
  const eventMeta = [
    context.eventTime ? `时间：${formatDateTime(context.eventTime)}` : "",
    context.channel ? `渠道：${context.channel}` : "",
  ].filter(Boolean);
  const detectionMeta = [
    context.detectionSources?.length ? `证据来源：${context.detectionSources.slice(0, 3).join("、")}` : "",
    context.detectionTime ? `检测时间：${formatDateTime(context.detectionTime)}` : "",
  ].filter(Boolean);

  target.innerHTML = `
    ${contextBlock({
      number: 1,
      title: "用户发送的原始文本",
      content: context.input,
      meta: eventMeta,
    })}
    ${contextBlock({
      number: 2,
      title: "提供的工具集",
      tone: "purple",
      tools: context.tools || [],
    })}
    ${contextBlock({
      number: 3,
      title: "原始输入（交给模型/工具前）",
      tone: "cyan",
      content: context.originalInput,
    })}
    ${contextBlock({
      number: 4,
      title: context.attackDetected ? "检测到的注入 / 操纵内容" : "对抗性输入证据",
      tone: context.attackDetected ? "danger" : "cyan",
      tag: context.attackDetected && context.adversarial ? "Prompt 注入片段" : "无独立片段",
      content: context.adversarial,
      meta: detectionMeta,
    })}`;
}

function contextBlock({ number, title, tone = "blue", content = "", meta = [], tools = [], tag = "" }) {
  const body = tools.length
    ? `<div class="tool-chip-list">${tools.slice(0, 3).map((tool) => `<span class="tool-chip">${escapeHtml(tool)}<small>${escapeHtml(toolDescription(tool))}</small></span>`).join("")}${tools.length > 3 ? `<span class="tool-chip">+${tools.length - 3}<small>其他工具</small></span>` : ""}</div>`
    : `<div class="context-content ${content ? "" : "is-empty"}">${escapeHtml(content || "未记录").replace(/\n/g, "<br>")}</div>`;
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

  const selectedNodeId = state.selectedItem?.type === "node"
    ? state.selectedItem.value.id
    : state.selectedItem ? "" : graph.selectedNodeId;
  const selectedEdgeId = state.selectedItem?.type === "edge" ? state.selectedItem.value.id : "";
  semanticGraph.setGraph(graph, { selectedNodeId, selectedEdgeId, preserveTransform: true });
  semanticGraph.setPathFocus(state.pathFocus);
  syncGraphPlayback();
}

function handleGraphSelection(item) {
  state.selectedItem = item;
  renderInspector(item);
  renderIncidentSummary();
  $("inspector").classList.toggle("open", Boolean(item));
  $("incidentConsole").classList.remove("inspector-collapsed");
  renderIcons();
}

function renderInspector(item) {
  const session = currentSession();
  const body = $("inspectorBody");
  if (!session) {
    body.innerHTML = emptyInspector("等待会话", "新的行为事件会在这里还原当前节点和因果关系");
    return;
  }

  if (!item) {
    body.innerHTML = emptyInspector("选择一个节点或边", "查看此处发生了什么、输入输出和关联审计记录");
    return;
  }
  const selection = item;
  state.selectedItem = selection;
  const evidence = buildSelectionEvidence(session, selection);
  if (!evidence) {
    body.innerHTML = emptyInspector("没有可展示的证据", "该图元素未关联到当前会话");
    return;
  }
  const meta = [
    evidence.occurredAt ? ["发生时间", formatDateTime(evidence.occurredAt)] : null,
    session.metadata?.incidentId ? ["事件记录", session.metadata.incidentId] : null,
    session.metadata?.sessionId ? ["会话 ID", session.metadata.sessionId] : null,
    session.metadata?.source ? ["数据来源", session.metadata.source] : null,
    session.metadata?.ip ? ["IP 地址", session.metadata.ip] : null,
  ].filter(Boolean);

  body.innerHTML = `
    <div class="inspector-selection">
      <span>当前${evidence.type === "edge" ? "关系" : "节点"}</span>
      <strong>${escapeHtml(evidence.id)}</strong>
      <i data-lucide="${evidence.type === "edge" ? "git-branch" : "mouse-pointer-click"}"></i>
    </div>

    <section class="selection-hero tone-${escapeHtml(evidence.tone)}">
      <span class="selection-hero-icon"><i data-lucide="${selectionIcon(evidence)}"></i></span>
      <div>
        <small>${escapeHtml(evidence.kindLabel)}</small>
        <h3>${escapeHtml(evidence.title)}</h3>
        <p>${escapeHtml(evidence.subtitle || "未记录")}</p>
      </div>
      ${evidence.state ? `<span class="selection-state">${escapeHtml(evidence.state)}</span>` : ""}
    </section>

    <section class="inspector-section current-event-section">
      <h4><i data-lucide="activity"></i>这里发生了什么</h4>
      <p>${escapeHtml(evidence.description)}</p>
      ${evidence.occurredAt ? `<time>${escapeHtml(formatDateTime(evidence.occurredAt))}</time>` : `<time>时间未记录</time>`}
    </section>

    ${renderInspectorFacts(evidence.facts)}
    ${renderInspectorObservations(evidence.observations)}
    ${renderInspectorRelations(evidence.relations)}
    ${renderInspectorPolicies(evidence.policies)}
    ${renderDownstreamDecision(evidence.downstreamDecision)}
    ${renderEvidenceRecords(evidence.records)}

    ${meta.length ? `<div class="inspector-meta">${meta.map(([label, value]) => `<span>${escapeHtml(label)} <b title="${escapeHtml(value)}">${escapeHtml(value)}</b></span>`).join("")}</div>` : ""}

    <details class="raw-evidence">
      <summary><span>原始脱敏证据</span><i data-lucide="chevron-down"></i></summary>
      <pre>${escapeHtml(JSON.stringify({ selection: selection.value, records: evidence.records }, null, 2))}</pre>
    </details>`;

  bindInspectorLinks();
}

function renderInspectorFacts(facts = []) {
  if (!facts.length) return "";
  return `<section class="inspector-section">
    <h4><i data-lucide="list-tree"></i>当前节点</h4>
    <dl class="selection-facts">${facts.map((fact) => `<div><dt>${escapeHtml(fact.label)}</dt><dd>${escapeHtml(fact.value).replace(/\n/g, "<br>")}</dd></div>`).join("")}</dl>
  </section>`;
}

function renderInspectorObservations(observations = []) {
  if (!observations.length) return "";
  return `<section class="inspector-section">
    <h4><i data-lucide="radar"></i>玄鉴观测</h4>
    <div class="observation-list">${observations.map((item) => `<div class="observation-item">
      <span>${escapeHtml(item.label)}</span>
      <p>${escapeHtml(item.value).replace(/\n/g, "<br>")}</p>
      ${item.recordId ? `<small>${escapeHtml(item.recordId)}</small>` : ""}
    </div>`).join("")}</div>
  </section>`;
}

function renderInspectorRelations(relations = []) {
  if (!relations.length) return "";
  return `<section class="inspector-section">
    <h4><i data-lucide="git-branch"></i>输入 / 输出</h4>
    <div class="relation-list">${relations.map((relation) => `<button type="button" class="relation-item direction-${escapeHtml(relation.direction)}" data-related-edge="${escapeHtml(relation.edgeId)}">
      <i data-lucide="${relation.direction === "in" ? "corner-down-right" : "corner-right-down"}"></i>
      <span><small>${relation.direction === "in" ? "输入" : "输出"} · ${escapeHtml(relation.label)}</small><strong>${escapeHtml(relation.nodeTitle)}</strong></span>
      <i data-lucide="chevron-right"></i>
    </button>`).join("")}</div>
  </section>`;
}

function renderInspectorPolicies(policies = []) {
  if (!policies.length) return "";
  return `<section class="inspector-section">
    <h4><i data-lucide="shield-alert"></i>与此处直接相关的策略</h4>
    <div class="selection-policy-list">${policies.map((policy) => `<code>${escapeHtml(policy)}</code>`).join("")}</div>
  </section>`;
}

function renderDownstreamDecision(decision) {
  if (!decision?.id) return "";
  return `<section class="inspector-section">
    <h4><i data-lucide="gavel"></i>下游裁决</h4>
    <button type="button" class="downstream-decision" data-related-node="${escapeHtml(decision.id)}">
      <span><small>沿当前因果链到达</small><strong>${escapeHtml(decision.title || "安全裁决")}</strong></span>
      <b>${escapeHtml(decision.state || "未记录")}</b>
      <i data-lucide="chevron-right"></i>
    </button>
  </section>`;
}

function renderEvidenceRecords(records = []) {
  if (!records.length) return `<section class="inspector-section evidence-records-section">
    <h4><i data-lucide="notebook-tabs"></i>关联审计记录</h4>
    <p class="section-empty">该图元素没有独立记录；其关系来自后端因果图投影。</p>
  </section>`;
  return `<section class="inspector-section evidence-records-section">
    <h4><i data-lucide="notebook-tabs"></i>关联审计记录 <span>${records.length}</span></h4>
    <div class="evidence-record-list">${records.map((record) => `<button type="button" class="evidence-record" data-record-id="${escapeHtml(record.id)}">
      <span class="record-tone tone-${escapeHtml(record.severity)}"></span>
      <span><small>${escapeHtml(record.layer || record.type)} · ${escapeHtml(formatDateTime(record.time))}</small><strong>${escapeHtml(record.title || record.type)}</strong>${record.summary ? `<p>${escapeHtml(record.summary)}</p>` : ""}</span>
      <i data-lucide="clock-3"></i>
    </button>`).join("")}</div>
  </section>`;
}

function bindInspectorLinks() {
  for (const button of $("inspectorBody").querySelectorAll("[data-related-edge]")) {
    button.addEventListener("click", () => selectGraphItem("edge", button.dataset.relatedEdge));
  }
  for (const button of $("inspectorBody").querySelectorAll("[data-related-node]")) {
    button.addEventListener("click", () => selectGraphItem("node", button.dataset.relatedNode));
  }
  for (const button of $("inspectorBody").querySelectorAll("[data-record-id]")) {
    button.addEventListener("click", () => {
      const index = currentSession()?.timeline.findIndex((event) => event.id === button.dataset.recordId) ?? -1;
      if (index >= 0) setPlayhead(index, { live: false, select: true });
    });
  }
}

function selectionIcon(evidence) {
  if (evidence.type === "edge") return "git-branch";
  return ({
    intent: "user-round",
    capability: "badge-check",
    agent: "bot",
    action: "wrench",
    data: "database",
    taint: "shield-alert",
    secret: "lock-keyhole",
    sink: "send",
    guard: "shield-check",
    judge: "scale",
    decision: "gavel",
    collapsed: "ellipsis",
  })[evidence.kind] || "circle";
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
  const pathEdges = (session.graph.pathEdgeIds || [])
    .map((id) => session.graph.edges.find((edge) => edge.id === id))
    .filter(Boolean);
  const observedPathEdges = pathEdges.filter((edge) => !edge.displayOnly);
  const pathSelection = observedPathEdges[Math.floor(observedPathEdges.length / 2)] || pathEdges[0] || null;
  const guardNode = session.graph.nodes.find((node) => node.kind === "guard");
  const impactNode = session.graph.nodes.find((node) => node.kind === "secret")
    || session.graph.nodes.find((node) => node.kind === "capability" && node.authorized === false)
    || session.graph.nodes.find((node) => node.kind === "sink");
  const decisionNode = [...session.graph.nodes].reverse().find((node) => node.kind === "decision");
  const result = session.decision === "deny" ? "已阻断" : session.decision === "ask" ? "待确认" : "已放行";
  const items = [
    {
      label: session.decision === "allow" ? "授权路径" : "攻击路径",
      value: `${observedPathEdges.length || pathEdges.length} 条因果边`,
      tone: session.decision === "allow" ? "green" : "danger",
      type: "edge",
      id: pathSelection?.id,
    },
    { label: "执行边界", value: guardNode?.title || "未记录", tone: session.decision === "ask" ? "amber" : "green", type: "node", id: guardNode?.id },
    { label: "影响对象", value: impactNode?.title || "未记录", tone: tone === "safe" ? "green" : "amber", type: "node", id: impactNode?.id },
    { label: "处理结果", value: result, tone: session.decision === "ask" ? "amber" : "green", type: "node", id: decisionNode?.id },
  ];
  metrics.innerHTML = items.map((entry) => {
    const selected = state.selectedItem?.type === entry.type && state.selectedItem?.value?.id === entry.id;
    return `<button class="summary-metric tone-${entry.tone} ${selected ? "selected" : ""}" type="button" ${entry.id ? `data-summary-type="${entry.type}" data-summary-id="${escapeHtml(entry.id)}"` : "disabled"}>
      <span>${escapeHtml(entry.label)}</span><strong>${escapeHtml(entry.value)}</strong><i data-lucide="chevron-right"></i>
    </button>`;
  }).join("");
  for (const button of metrics.querySelectorAll("[data-summary-id]")) {
    button.addEventListener("click", () => selectGraphItem(button.dataset.summaryType, button.dataset.summaryId));
  }
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
    return `<button class="timeline-tick tone-${tone} ${index <= state.playhead ? "reached" : ""} ${index === state.playhead ? "current" : ""}" type="button" style="left:${left}%" data-step="${index}" title="${escapeHtml(`${formatDateTime(event.time)} · ${event.title}`)}" aria-label="跳转到 ${escapeHtml(event.title)}"><span></span><small>${escapeHtml(timelineStageLabel(event, index, events))}<time>${escapeHtml(formatClock(event.time))}</time></small></button>`;
  }).join("");

  for (const tick of $("timelineTicks").querySelectorAll("[data-step]")) {
    tick.addEventListener("click", () => setPlayhead(Number(tick.dataset.step), { live: false, select: true }));
  }

  const event = events[state.playhead];
  $("timelineCurrent").textContent = event?.time ? formatDateTime(event.time) : "时间未记录";
  $("timelineEvent").textContent = event ? `${event.stage || timelineStageLabel(event, state.playhead, events)} · ${event.title}` : "等待事件";
  $("timelineEvent").title = event?.detail || event?.title || "";
  $("liveBtn").classList.toggle("active", state.live);
  $("playbackBadge").classList.toggle("paused", !state.live);
  $("playbackBadge").innerHTML = state.live ? `<span class="live-dot"></span> LIVE` : `<i data-lucide="history"></i> REPLAY ${state.playhead + 1}/${Math.max(1, events.length)}`;
  updatePlaybackButton();
  syncGraphPlayback();
}

function setPlayhead(value, { live = false, select = true } = {}) {
  const session = currentSession();
  const max = Math.max(0, (session?.timeline.length || 1) - 1);
  state.playhead = Math.max(0, Math.min(max, Number(value) || 0));
  state.live = live && state.playhead === max;
  if (!state.live) stopPlayback();
  if (select) applyTimelineSelection(session?.timeline[state.playhead]);
  renderTimeline();
  renderIcons();
}

function syncGraphPlayback() {
  const session = currentSession();
  if (!session) return;
  const event = session.timeline[state.playhead];
  semanticGraph.setRevealSequence(state.live ? Number.POSITIVE_INFINITY : Number(event?.revealSequence || 0));
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
    applyTimelineSelection(latestEvents[state.playhead]);
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
  applyTimelineSelection(events[state.playhead]);
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

function selectGraphItem(type, id) {
  const session = currentSession();
  const list = type === "edge" ? session?.graph?.edges : session?.graph?.nodes;
  const value = list?.find((item) => item.id === id);
  if (!value) return;
  if (type === "edge") semanticGraph.selectEdge(id);
  else semanticGraph.selectNode(id);
}

function applyTimelineSelection(event) {
  if (!event) return;
  if (event.nodeId) selectGraphItem("node", event.nodeId);
  else if (event.edgeId) selectGraphItem("edge", event.edgeId);
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
  if (event?.stage) return event.stage;
  const text = String(event?.title || "事件");
  const type = String(event?.type || "");
  const payload = event?.record?.payload || {};
  if (index === events.length - 1 && type === "tool_result" && (payload.blocked || event.decision === "deny")) return "响应返回";
  if (["lab_command", "user_message", "command"].includes(type)) return "用户输入";
  if (type === "task_spec") return "意图解析";
  if (type === "tool_result" && (payload.preview || payload.adversarial_input)) return "Prompt 注入";
  if (type === "tool_call") return "工具调用";
  if (type === "tool_decision" && event.decision === "deny") return "系统/配置访问";
  if (type === "alert" && event.decision === "deny") return "玄鉴拦截";
  if (/用户|user|command/i.test(text)) return "用户输入";
  if (/intent|意图|任务/i.test(text)) return "意图解析";
  if (/prompt|注入|taint|污染/i.test(text)) return "Prompt 注入";
  if (/tool|工具|调用/i.test(text)) return "工具调用";
  if (/系统|配置|secret|密钥|敏感/i.test(text)) return "系统/配置访问";
  if (/拦截|阻断|deny|block/i.test(text)) return "玄鉴拦截";
  if (/返回|result|response/i.test(text)) return "响应返回";
  return shortEventLabel(text);
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
  return String(session?.metadata?.incidentId || session?.alert?.id || session?.records?.at(-1)?.id || session?.id || "未记录");
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
  anchor.download = `${incidentId(session).replace(/[^a-zA-Z0-9._-]+/g, "_")}.json`;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
  showToast("事件报告已导出");
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
