import {
  buildDashboardModel,
  buildIncidentConclusion,
  buildSelectionEvidence,
  decisionCode,
  primaryPathGraph,
} from "/graph-adapter.js?v=20260809-2";
import { SemanticGraph } from "/semantic-graph.js?v=20260809-2";

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
    setConnection(state.model.source.available === false ? "warning" : "live", state.model.source.available === false ? "降级" : "实时");
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
  renderIncidentConclusion();
  renderRequestContext();
  renderGraph();
  renderInspector(state.selectedItem);
  renderIncidentSummary();
  renderTimeline();
  renderIcons();
}

function renderHeader() {
  const select = $("modeSelect");
  const mode = String(state.enforcement?.mode || "");
  if (select && mode && select.value !== mode) select.value = mode;
  const source = state.model.source || {};
  $("sourceLabel").textContent = brandText(source.label || "玄鉴审计记录").toUpperCase();
  $("sourceMeta").textContent = source.totalRecords
    ? `${formatNumber(source.windowRecords)} / ${formatNumber(source.totalRecords)} 条审计记录`
    : "等待审计数据";
  const alertCount = Math.max(0, Number(source.alertCount) || 0);
  const displayAlertCount = alertCount > 99 ? "99+" : String(alertCount);
  for (const id of ["headerAlertCount", "navAlertCount"]) {
    const target = $(id);
    if (!target) continue;
    target.textContent = displayAlertCount;
    target.hidden = alertCount === 0;
  }
  document.querySelector(".notification-button")?.setAttribute(
    "aria-label",
    alertCount === 0 ? "查看告警" : `查看告警，${displayAlertCount} 条`,
  );
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

function renderIncidentConclusion() {
  const conclusion = buildIncidentConclusion(currentSession());
  const severity = $("conclusionSeverity");
  const severityTone = conclusion.severity === "高危" ? "danger" : conclusion.severity === "中危" ? "warning" : "safe";
  severity.className = `severity-badge tone-${severityTone}`;
  severity.textContent = conclusion.severity;
  $("conclusionType").textContent = conclusion.attackType;
  $("conclusionSummary").textContent = brandText(conclusion.summary);
  const outcome = $("conclusionOutcome");
  outcome.className = `conclusion-outcome tone-${escapeHtml(conclusion.tone)}`;
  outcome.innerHTML = `<i data-lucide="${conclusion.tone === "safe" ? "shield-check" : conclusion.tone === "warning" ? "clock-alert" : conclusion.tone === "danger" ? "triangle-alert" : "activity"}"></i>
    <span><small>结果</small><strong>${escapeHtml(conclusion.result)}</strong></span>`;
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
  const conclusion = buildIncidentConclusion(session);
  const tools = (context.tools || []).slice(0, 6);
  const evidenceCodes = Array.from(new Set([
    ...(session.policies || []),
    ...(context.detectionSources || []),
    conclusion.policy,
  ].map((value) => String(value || "").trim()).filter(isPolicyCode))).slice(0, 4);
  const promptInjection = context.promptInjectionDetected === true || conclusion.attackType === "Prompt Injection";
  const detectionActive = context.attackDetected === true;
  const detectionTone = !detectionActive ? "safe" : promptInjection || session.decision === "deny" ? "danger" : "warning";
  const detectionType = detectionActive ? String(context.detectionType || conclusion.attackType || "风险行为") : "未发现攻击信号";
  const detectionStatus = !detectionActive ? "CLEAN" : promptInjection ? "CONFIRMED" : session.decision === "ask" ? "REVIEW" : "CONFIRMED";
  const intentSteps = promptInjection
    ? detectionIntentSteps(context.adversarial)
    : detectionRiskSteps(session, conclusion);

  target.innerHTML = `
    <section class="request-context-item">
      <header><span>用户请求</span>${context.eventTime ? `<time>${escapeHtml(formatDateTime(context.eventTime))}</time>` : ""}</header>
      <p>${escapeHtml(context.input || "未记录").replace(/\n/g, "<br>")}</p>
    </section>
    <section class="request-context-item model-input-item">
      <header><span>模型实际接收</span>${context.channel ? `<small>${escapeHtml(context.channel)}</small>` : ""}</header>
      <p>${escapeHtml(context.originalInput || context.input || "未记录").replace(/\n/g, "<br>")}</p>
    </section>
    <section class="available-tools-row">
      <span>可用工具</span>
      <div>${tools.length ? tools.map((tool) => `<code title="${escapeHtml(toolDescription(tool))}">${escapeHtml(tool)}</code>`).join("") : `<small>未记录</small>`}</div>
    </section>
    <section class="detection-card tone-${detectionTone}">
      <header>
        <span class="detection-icon"><i data-lucide="${detectionActive ? (promptInjection ? "shield-alert" : "triangle-alert") : "shield-check"}"></i></span>
        <span><small>${detectionActive ? "检测到" : "检测结果"}</small><strong>${escapeHtml(detectionType)}</strong></span>
        <b>${detectionStatus}</b>
      </header>
      <blockquote>${escapeHtml(context.adversarial || (detectionActive ? "检测到高风险行为，原始证据片段未单独记录。" : "当前请求未发现独立的攻击输入片段。")).replace(/\n/g, "<br>")}</blockquote>
      ${detectionActive ? `<div class="attack-intent">
        <span>${promptInjection ? "攻击意图" : "风险解释"}</span>
        <div>${intentSteps.map((step, index) => `${index ? `<i data-lucide="arrow-right"></i>` : ""}<strong>${escapeHtml(step)}</strong>`).join("")}</div>
      </div>` : ""}
      <div class="detection-evidence">
        <span>证据</span>
        <div>${evidenceCodes.length ? evidenceCodes.map((code) => `<code>${escapeHtml(code)}</code>`).join("") : `<small>等待更多证据</small>`}</div>
      </div>
      ${context.detectionTime ? `<time>检测时间 ${escapeHtml(formatDateTime(context.detectionTime))}</time>` : ""}
    </section>`;
}

function renderGraph() {
  const session = currentSession();
  if (!session) {
    $("graphContext").innerHTML = `<span>暂无会话</span>`;
    $("graphConfidence").textContent = "等待图证据";
    semanticGraph.setGraph(null);
    return;
  }

  const graph = session.graph;
  const displayGraph = state.pathFocus ? primaryPathGraph(graph) : graph;
  const workspace = document.querySelector(".graph-workspace");
  workspace.classList.remove("tone-danger", "tone-warning", "tone-safe");
  const tone = decisionTone(session);
  const decisionStatusTone = session.decision === "deny"
    && session.graph.traceKind !== "enforcement_bypass"
    && session.graph.risk !== "execution_after_block"
    ? "safe"
    : tone;
  workspace.classList.add(`tone-${tone}`);
  const evidence = graph.derived ? "VIEW PROJECTION" : graph.certainty === "observed" ? "OBSERVED" : String(graph.certainty || "EVIDENCE").toUpperCase();
  const partial = graph.partial ? "局部图" : "完整图";
  $("graphContext").innerHTML = `
    <span class="context-decision tone-${escapeHtml(decisionStatusTone)}">${escapeHtml(decisionCode(session.decision))}</span>
    <span>${escapeHtml(graph.riskLabel)}</span>
    <span>SAG V${escapeHtml(graph.version)}</span>
    <span>${escapeHtml(partial)}</span>`;
  $("graphConfidence").textContent = `${state.pathFocus ? "攻击主路径" : evidence} · ${Math.round(graph.confidence * 100)}% · ${displayGraph.nodes.length}/${Math.max(graph.nodes.length, graph.sourceNodeCount)} 个节点`;
  updateGraphModeButton();

  const selectedNodeId = state.selectedItem?.type === "node" && displayGraph.nodes.some((node) => node.id === state.selectedItem.value.id)
    ? state.selectedItem.value.id
    : state.selectedItem ? "" : displayGraph.selectedNodeId;
  const selectedEdgeId = state.selectedItem?.type === "edge" && displayGraph.edges.some((edge) => edge.id === state.selectedItem.value.id)
    ? state.selectedItem.value.id
    : "";
  semanticGraph.setGraph(displayGraph, { selectedNodeId, selectedEdgeId, preserveTransform: true });
  semanticGraph.setPathFocus(false);
  syncGraphPlayback();
}

function updateGraphModeButton() {
  const button = $("pathFocusBtn");
  button.classList.toggle("active", !state.pathFocus);
  button.setAttribute("aria-expanded", String(!state.pathFocus));
  button.title = state.pathFocus ? "展开全部依赖关系" : "仅展示攻击主路径";
  button.innerHTML = `<i data-lucide="${state.pathFocus ? "network" : "route"}"></i><span>${state.pathFocus ? "完整因果图" : "攻击主路径"}</span>`;
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
  const conclusion = selectionConclusion(evidence, session);
  const keyFacts = selectionKeyFacts(evidence, session);

  body.innerHTML = `
    <div class="inspector-selection">
      <span>当前${evidence.type === "edge" ? "关系" : "节点"}</span>
      <strong>${escapeHtml(evidence.id)}</strong>
      <i data-lucide="${evidence.type === "edge" ? "git-branch" : "mouse-pointer-click"}"></i>
    </div>

    <section class="inspector-conclusion tone-${escapeHtml(conclusion.tone)}">
      <span class="inspector-conclusion-icon"><i data-lucide="${escapeHtml(conclusion.icon)}"></i></span>
      <div>
        <small>这里发生了什么 · ${escapeHtml(evidence.kindLabel)}</small>
        <h3>${escapeHtml(conclusion.title)}</h3>
        <p>${escapeHtml(evidence.description)}</p>
      </div>
    </section>

    <section class="inspector-section key-evidence-section">
      <h4><i data-lucide="list-checks"></i>现场信息</h4>
      <dl class="key-evidence-list">${keyFacts.map((fact) => `<div><dt>${escapeHtml(fact.label)}</dt><dd>${escapeHtml(fact.value).replace(/\n/g, "<br>")}</dd></div>`).join("")}</dl>
    </section>

    <details class="technical-details">
      <summary><span><i data-lucide="braces"></i>技术详情</span><i data-lucide="chevron-down"></i></summary>
      <div class="technical-details-body">
        ${renderInspectorFacts(evidence.facts)}
        ${renderInspectorObservations(evidence.observations)}
        ${renderInspectorRelations(evidence.relations)}
        ${renderInspectorPolicies(evidence.policies)}
        ${renderDownstreamDecision(evidence.downstreamDecision)}
        ${renderEvidenceRecords(evidence.records)}
        ${meta.length ? `<div class="inspector-meta">${meta.map(([label, value]) => `<span>${escapeHtml(label)} <b title="${escapeHtml(value)}">${escapeHtml(value)}</b></span>`).join("")}</div>` : ""}
        <details class="raw-evidence">
          <summary><span>原始日志 / Trace</span><i data-lucide="chevron-down"></i></summary>
          <pre>${escapeHtml(JSON.stringify({ selection: selection.value, records: evidence.records }, null, 2))}</pre>
        </details>
      </div>
    </details>`;

  bindInspectorLinks();
}

function selectionConclusion(evidence, session) {
  const stateValue = String(evidence.state || "").toUpperCase();
  const relation = String(evidence.kind || "").toLowerCase();
  if (evidence.type === "edge") {
    if (["blocked_by", "decides"].includes(relation) && session.decision === "deny") return { title: "安全控制已生效", tone: "safe", icon: "shield-check" };
    if (["taints", "consumes"].includes(relation)) return { title: "攻击传播已确认", tone: "danger", icon: "shield-alert" };
    if (["targets", "invokes", "requests"].includes(relation)) return { title: "高风险调用链已确认", tone: "warning", icon: "route" };
    if (["declares", "authorizes"].includes(relation)) return { title: "任务授权关系已确认", tone: "neutral", icon: "badge-check" };
    if (relation === "produces") return { title: "工具返回已记录", tone: "neutral", icon: "database" };
    if (relation === "derives") return { title: "数据血缘已记录", tone: "neutral", icon: "git-branch" };
    return { title: "因果关系已记录", tone: "neutral", icon: "git-branch" };
  }
  if (evidence.kind === "decision") {
    if (stateValue === "DENY") return { title: "已阻断", tone: "safe", icon: "shield-check" };
    if (stateValue === "ASK") return { title: "等待人工确认", tone: "warning", icon: "clock-alert" };
    return { title: "已放行", tone: "safe", icon: "badge-check" };
  }
  if (evidence.kind === "guard") return { title: session.decision === "deny" ? "执行边界阻断成功" : "执行边界校验完成", tone: "safe", icon: "shield-check" };
  if (evidence.kind === "taint") return { title: "确认 Prompt Injection", tone: "danger", icon: "shield-alert" };
  if (evidence.kind === "secret") return { title: "敏感数据已标记", tone: "warning", icon: "lock-keyhole" };
  if (evidence.kind === "sink") return { title: session.decision === "deny" ? "外发在执行前被阻断" : "已识别外部目标", tone: session.decision === "deny" ? "safe" : "warning", icon: session.decision === "deny" ? "shield-check" : "send" };
  if (evidence.kind === "capability") {
    if (/未授权|UNSCOPED|DENY|BLOCK/.test(`${evidence.title} ${evidence.state}`)) return { title: "超出任务授权", tone: "warning", icon: "shield-alert" };
    return { title: "任务授权已确认", tone: "neutral", icon: "badge-check" };
  }
  if (evidence.kind === "action" && /BLOCK|DENY|UNSCOPED|REJECT/.test(stateValue)) return { title: "危险工具调用已阻断", tone: "safe", icon: "shield-check" };
  if (evidence.kind === "action") return { title: /SUCCEEDED|COMPLETED|ALLOW/.test(stateValue) ? "工具调用已完成" : "工具调用已记录", tone: "neutral", icon: "wrench" };
  if (evidence.kind === "data") return { title: "工具返回已记录", tone: "neutral", icon: "database" };
  if (evidence.kind === "intent") return { title: "用户请求已解析", tone: "neutral", icon: "message-square-text" };
  if (evidence.kind === "agent") return { title: "Agent 已形成执行计划", tone: "neutral", icon: "bot" };
  return { title: "当前行为已记录", tone: evidence.tone === "warning" ? "warning" : "neutral", icon: selectionIcon(evidence) };
}

function selectionKeyFacts(evidence, session) {
  const conclusion = buildIncidentConclusion(session);
  const fact = (...labels) => evidence.facts?.find((item) => labels.includes(item.label))?.value || "";
  const observation = (...labels) => evidence.observations?.find((item) => labels.includes(item.label))?.value || "";
  const rows = [];
  const add = (label, value) => {
    const text = String(value || "").trim();
    if (text && !rows.some((item) => item.label === label)) rows.push({ label, value: text });
  };

  if (evidence.type === "edge") {
    add("语义关系", evidence.title);
    add("来源节点", fact("来源节点"));
    add("目标节点", fact("目标节点"));
    add("目标参数", fact("目标参数"));
    add("发生时间", evidence.occurredAt ? formatDateTime(evidence.occurredAt) : "");
  } else {
    add("当前阶段", evidence.title);
    add("发生时间", evidence.occurredAt ? formatDateTime(evidence.occurredAt) : "");
    add("用户请求", observation("用户请求"));
    add("工具", fact("工具"));
    add("工具参数", observation("工具参数"));
    add("返回结果", observation("返回预览"));
    add("当前状态", fact("当前状态") || evidence.state);
    add("字段路径", fact("字段路径"));
    add("数据来源", fact("数据来源") || observation("数据来源"));
    add("外部目标", fact("目标"));
  }

  const riskyRelations = new Set(["constrains", "taints", "consumes", "targets", "blocked_by", "reviewed_by", "approved_by", "decides"]);
  const riskSelection = evidence.type === "edge"
    ? riskyRelations.has(String(evidence.kind || "").toLowerCase())
    : ["taint", "secret", "sink", "guard", "decision"].includes(evidence.kind)
      || evidence.kind === "capability" && /未授权|UNSCOPED|DENY|BLOCK/.test(`${evidence.title} ${evidence.state}`)
      || evidence.kind === "action" && /BLOCK|DENY|UNSCOPED|REJECT/.test(String(evidence.state || "").toUpperCase());
  if (riskSelection) {
    add("攻击类型", conclusion.attackType);
    add("执行边界", evidence.policies?.find(isPolicyCode) || conclusion.policy);
    add("处理结果", conclusion.result);
    add("外发目标", conclusion.target);
  } else if (evidence.type === "edge") {
    add("证据依据", fact("证据依据"));
  }
  add("置信度", fact("置信度") || `${Math.round(Number(session.graph?.confidence || 0) * 100)}%`);
  return rows.slice(0, 8);
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

function renderIncidentSummary() {
  const session = currentSession();
  const text = $("resultSummary");
  const outcomeTitle = $("outcomeTitle");
  const actions = $("outcomeActions");
  if (!session) {
    text.textContent = "等待真实审计事件";
    outcomeTitle.textContent = "等待裁决";
    actions.innerHTML = "";
    return;
  }

  const conclusion = buildIncidentConclusion(session);
  text.textContent = brandText(conclusion.summary);
  outcomeTitle.textContent = brandText(conclusion.result);
  const guardNode = session.graph.nodes.find((node) => node.kind === "guard");
  const secretNode = session.graph.nodes.find((node) => node.kind === "secret");
  const sinkNode = session.graph.nodes.find((node) => node.kind === "sink");
  const riskyAction = [...session.graph.nodes].reverse().find((node) => node.kind === "action" && (node.authorized === false || /BLOCK|DENY|UNSCOPED|REJECT/i.test(String(node.state || ""))))
    || [...session.graph.nodes].reverse().find((node) => node.kind === "action");
  const decisionNode = [...session.graph.nodes].reverse().find((node) => node.kind === "decision");
  const bypass = session.graph.traceKind === "enforcement_bypass" || session.graph.risk === "execution_after_block";
  const items = [
    {
      icon: bypass ? "triangle-alert" : "shield-check",
      label: bypass ? "需要进一步处置" : session.decision === "deny" ? "攻击已阻断" : session.decision === "ask" ? "攻击链已暂停" : "授权路径已完成",
      detail: guardNode?.title || conclusion.policy,
      tone: bypass ? "danger" : session.decision === "ask" ? "warning" : "safe",
      id: decisionNode?.id || guardNode?.id,
    },
    {
      icon: "lock-keyhole",
      label: bypass ? "敏感数据状态待核查" : session.decision === "deny" ? "敏感数据未发送" : session.decision === "ask" ? "敏感数据流已冻结" : "未发现越权数据流",
      detail: secretNode?.title || "未记录敏感字段",
      tone: bypass ? "danger" : session.decision === "ask" ? "warning" : "safe",
      id: secretNode?.id || guardNode?.id,
    },
    {
      icon: "send",
      label: bypass ? "外部副作用待确认" : session.decision === "deny" ? "外部工具未成功执行" : session.decision === "ask" ? "外部工具等待审批" : "授权工具执行完成",
      detail: conclusion.target || riskyAction?.title || "未记录外部目标",
      tone: bypass ? "danger" : session.decision === "ask" ? "warning" : "safe",
      id: sinkNode?.id || riskyAction?.id || guardNode?.id,
    },
  ];
  actions.innerHTML = items.map((entry) => {
    const selected = state.selectedItem?.type === "node" && state.selectedItem?.value?.id === entry.id;
    return `<button class="outcome-action tone-${entry.tone} ${selected ? "selected" : ""}" type="button" ${entry.id ? `data-summary-id="${escapeHtml(entry.id)}"` : "disabled"}>
      <i data-lucide="${escapeHtml(entry.icon)}"></i><span><strong>${escapeHtml(entry.label)}</strong><small>${escapeHtml(entry.detail)}</small></span><i data-lucide="chevron-right"></i>
    </button>`;
  }).join("");
  for (const button of actions.querySelectorAll("[data-summary-id]")) {
    button.addEventListener("click", () => selectGraphItem("node", button.dataset.summaryId));
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
    const stage = timelineStageLabel(event, index, events);
    const tone = /Prompt|注入|污染/i.test(stage)
      ? "danger"
      : /拦截|阻断|裁决|响应返回/i.test(stage) && event.decision === "deny"
        ? "safe"
        : /外发|目标|工具调用|系统|配置|敏感/i.test(stage) || event.decision === "ask" || event.severity === "medium"
          ? "warning"
          : event.decision === "allow" ? "safe" : "info";
    const stageLabel = timelineStageLabel(event, index, events);
    const clock = formatClock(event.time);
    return `<button class="timeline-tick tone-${tone} ${index <= state.playhead ? "reached" : ""} ${index === state.playhead ? "current" : ""}" type="button" style="left:${left}%" data-step="${index}" title="${escapeHtml(`${formatDateTime(event.time)} · ${event.title}`)}" aria-label="${escapeHtml(`${stageLabel} ${clock}，${event.title}`)}"><span></span><small>${escapeHtml(stageLabel)}<time>${escapeHtml(clock)}</time></small></button>`;
  }).join("");

  for (const tick of $("timelineTicks").querySelectorAll("[data-step]")) {
    tick.addEventListener("click", () => setPlayhead(Number(tick.dataset.step), { live: false, select: true }));
  }

  const event = events[state.playhead];
  $("timelineCurrent").textContent = event?.time ? formatDateTime(event.time) : "时间未记录";
  $("timelineEvent").textContent = event ? brandText(`${event.stage || timelineStageLabel(event, state.playhead, events)} · ${event.title}`) : "等待事件";
  $("timelineEvent").title = brandText(event?.detail || event?.title || "");
  $("liveBtn").classList.toggle("active", state.live);
  $("playbackBadge").classList.toggle("paused", !state.live);
  $("playbackBadge").innerHTML = state.live ? `<span class="live-dot"></span> 实时` : `<i data-lucide="history"></i> 回放 ${state.playhead + 1}/${Math.max(1, events.length)}`;
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
  button.innerHTML = `<i data-lucide="${state.playing ? "pause" : "play"}"></i><span>${state.playing ? "暂停回放" : "查看会话回放"}</span>`;
  button.title = state.playing ? "暂停回放" : "查看会话回放";
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
    renderGraph();
    renderIcons();
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
  $("openTraceBtn").addEventListener("click", openSelectedTrace);
  $("createRuleBtn").addEventListener("click", () => {
    window.location.href = "/security-screen#policies";
  });
  $("moreActionsBtn").addEventListener("click", (event) => {
    event.stopPropagation();
    const menu = $("moreActionsMenu");
    menu.hidden = !menu.hidden;
    $("moreActionsBtn").setAttribute("aria-expanded", String(!menu.hidden));
  });
  $("moreActionsMenu").addEventListener("click", (event) => event.stopPropagation());
  $("allowlistBtn").addEventListener("click", () => {
    $("moreActionsMenu").hidden = true;
    $("moreActionsBtn").setAttribute("aria-expanded", "false");
    $("allowlistDialog").showModal();
  });
  $("cancelAllowlistBtn").addEventListener("click", () => $("allowlistDialog").close("cancel"));
  $("confirmAllowlistBtn").addEventListener("click", () => {
    $("allowlistDialog").close("confirm");
    showToast("已生成白名单复核草案，当前策略未发生变化");
  });
  document.addEventListener("click", () => {
    $("moreActionsMenu").hidden = true;
    $("moreActionsBtn").setAttribute("aria-expanded", "false");
  });
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

function openSelectedTrace() {
  if (!state.selectedItem) state.selectedItem = defaultSelection(currentSession());
  $("inspector").classList.add("open");
  $("incidentConsole").classList.remove("inspector-collapsed");
  renderInspector(state.selectedItem);
  renderIcons();
  const technical = $("inspectorBody").querySelector(".technical-details");
  const raw = $("inspectorBody").querySelector(".raw-evidence");
  if (technical) technical.open = true;
  if (raw) raw.open = true;
  raw?.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function currentSession() {
  return state.model.sessions.find((session) => session.id === state.selectedSessionId) || null;
}

function preferredSession(sessions) {
  const requestedSession = new URLSearchParams(window.location.search).get("session");
  return sessions.find((session) => requestedSession && session.id === requestedSession)
    || sessions.find((session) => session.graph?.traceKind === "enforcement_bypass")
    || sessions.find((session) => session.decision === "deny" && !session.graph?.derived)
    || sessions.find((session) => session.decision === "ask")
    || sessions.find((session) => !session.graph?.derived)
    || sessions[0]
    || null;
}

function defaultSelection(session) {
  const id = [...(session?.graph?.nodes || [])].reverse().find((node) => node.kind === "decision")?.id
    || [...(session?.graph?.nodes || [])].reverse().find((node) => node.kind === "guard")?.id
    || session?.graph?.selectedNodeId
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

function detectionIntentSteps(value) {
  const text = String(value || "").toLowerCase();
  const steps = [];
  if (/ignore|忽略|override|覆盖|bypass|绕过/.test(text)) steps.push("忽略系统指令");
  if (/credential|secret|token|key|password|凭证|密钥|敏感/.test(text)) steps.push("获取敏感凭证");
  if (/forward|send|upload|post|exfiltrat|发送|转发|上传|外传/.test(text)) steps.push("发送到外部");
  if (!steps.length) steps.push("操纵 Agent 行为", "触发越权动作");
  return steps.slice(0, 3);
}

function detectionRiskSteps(session, conclusion) {
  if (session?.decision === "ask") return ["目标超出当前任务范围", "外部副作用需要人工确认"];
  if (session?.decision === "deny") return [
    conclusion?.policy || "执行边界策略",
    conclusion?.target ? `目标：${conclusion.target}` : "高风险工具动作",
    "执行前被玄鉴阻断",
  ];
  return ["行为正在接受玄鉴复核"];
}

function isPolicyCode(value) {
  return /^[A-Z][A-Z0-9_:-]{3,}$/.test(String(value || "").trim());
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
  return brandText(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[character]);
}

function brandText(value) {
  return String(value ?? "")
    .replace(/showing latest\s+(\d+)\s+of\s+(\d+)\s+(?:AgentSentry|OpenClaw)\s+plugin\s+records/gi, "最近 $1 / $2 条玄鉴审计记录")
    .replace(/\b(?:AgentSentry|OpenClaw)\s+plugin\s+records\b/gi, "玄鉴审计记录")
    .replace(/\b(?:AgentSentry|OpenClaw)\b/gi, "玄鉴");
}
