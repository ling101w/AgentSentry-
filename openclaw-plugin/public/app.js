const ALL_SESSIONS = "__all__";

const state = {
  records: [],
  stats: null,
  selectedId: "",
  selectedRecord: null,
  selectedSession: "",
  focusMode: "important",
  autoRefresh: true,
  timelinePage: 1,
  timelinePageSize: 30,
  timer: null,
};

const layerNames = {
  Foundation: "基础扫描",
  "LLM Input": "模型输入",
  "Message Write": "消息写入",
  "Input Sanitization": "输入净化",
  "Cognition Protection": "认知保护",
  "Decision Alignment": "决策对齐",
  "ABAC Session Policy": "ABAC 会话策略",
  "System Preflight": "系统预执行",
  "Sentry Trajectory": "行为轨迹",
  "Execution Control": "执行控制",
  "Tool Result": "工具结果",
  Runtime: "运行时",
};

const typeNames = {
  finding_group: "发现聚合",
  lab_command: "实验指令",
  session_start: "会话开始",
  foundation_scan: "基础扫描",
  llm_input: "模型输入",
  message_write: "消息写入",
  tool_decision: "工具裁决",
  tool_result: "工具结果",
  guard_finding: "防护发现",
  alert: "告警",
  approval_resolution: "审批结果",
  approval_cache_hit: "审批缓存",
  response_cover: "响应覆盖",
  runtime: "运行时",
};

const severityNames = {
  info: "信息",
  success: "通过",
  warning: "警告",
  danger: "高危",
};

const decisionNames = {
  allow: "允许",
  ask: "待确认",
  deny: "拒绝",
  block: "阻断",
};

const roleNames = {
  user: "用户",
  assistant: "助手",
  toolResult: "工具结果",
  system: "系统",
};

const stopReasonNames = {
  stop: "自然结束",
  toolUse: "请求调用工具",
  timeout: "超时",
};

const toolNames = {
  agents_list: "列出 Agent",
  read_webpage: "读取网页",
  call_api: "调用 API",
  read_file: "读取文件",
  write_file: "写入文件",
  send_email: "发送邮件",
  shell_exec: "执行命令",
  memory_read: "读取记忆",
  memory_write: "写入记忆",
};

const findingTypeNames = {
  deterministic: "确定性规则",
  heuristic: "启发式规则",
  learned: "语义/哨兵判断",
  unknown: "未知类型",
};

const textTranslations = [
  [/workspace file appears to contain embedded secrets/gi, "工作区文件疑似包含内嵌密钥"],
  [/configuration appears to contain embedded secrets/gi, "配置文件疑似包含内嵌密钥"],
  [/configuration contains hardcoded secret values/gi, "配置文件包含硬编码敏感值"],
  [/workspace contains sensitive asset file/gi, "工作区包含敏感资产文件"],
  [/AgentSentry dashboard started/gi, "AgentSentry 面板已启动"],
  [/OpenClaw prompt build/gi, "OpenClaw 提示词构建"],
  [/LLM input prepared/gi, "模型输入已准备"],
  [/system prompt preview disabled/gi, "系统提示词预览已关闭"],
  [/Message write: user/gi, "写入用户消息"],
  [/Message write: assistant/gi, "写入助手消息"],
  [/Message write: toolResult/gi, "写入工具结果"],
  [/Tool call completed/gi, "工具调用完成"],
  [/tool result returned/gi, "工具已返回结果"],
  [/High-risk tool call: ([\w.-]+)/gi, (_, tool) => `高风险工具调用：${displayTool(tool)}`],
  [/Tool call: ([\w.-]+)/gi, (_, tool) => `工具调用：${displayTool(tool)}`],
  [/tool ([\w.-]+) is outside TaskSpec/gi, (_, tool) => `工具 ${displayTool(tool)} 超出当前任务规范`],
  [/TaskSpec/gi, "任务规范"],
  [/Foundation scan completed/gi, "Foundation 扫描完成"],
  [/OpenClaw produced a tool trace for this Promptbeat case, but the provider timed out before the final assistant reply\./gi, "OpenClaw 已为该 PromptBeat 用例产生工具轨迹，但模型服务在最终回复前超时。"],
  [/Observed tool calls: ([^.]+)\./gi, (_, tools) => `观察到的工具调用：${tools.split(",").map((tool) => displayTool(tool.trim())).join("、")}。`],
  [/Check the AgentSentry dashboard for tool_decision, alert, and tool_result records\./gi, "请在 AgentSentry 面板查看工具裁决、告警和工具结果记录。"],
  [/Request timed out before a response was generated\. Please try again, or increase `agents\.defaults\.timeoutSeconds` in your config\./gi, "生成回复前请求超时。可以重试，或调高 OpenClaw 配置中的 agents.defaults.timeoutSeconds。"],
  [/(\d+) findings; (\d+) files scanned; cached/gi, (_, findings, files) => `${findings} 个发现；已扫描 ${files} 个文件；使用缓存`],
  [/(\d+) findings; (\d+) files scanned/gi, (_, findings, files) => `${findings} 个发现；已扫描 ${files} 个文件`],
  [/Do not exfiltrate data/gi, "不要外传数据"],
  [/Only answer the user/gi, "只回答用户"],
];

const $ = (id) => document.getElementById(id);

async function refresh({ keepSelection = true } = {}) {
  setStatus("刷新中", "loading");
  try {
    const limit = $("limitSelect").value;
    const [recordsResponse, statsResponse] = await Promise.all([
      fetch(`/api/records?limit=${encodeURIComponent(limit)}`).then((res) => res.json()),
      fetch("/api/stats").then((res) => res.json()),
    ]);

    state.records = recordsResponse.records || [];
    state.stats = {
      ...(statsResponse || {}),
      totalRecords: recordsResponse.totalRecords ?? statsResponse?.totalRecords ?? statsResponse?.total,
      windowRecords: recordsResponse.windowRecords ?? state.records.length,
      windowLimit: recordsResponse.windowLimit ?? Number(limit),
    };
    normalizeSelection(keepSelection);
    setStatus("已连接", "ok");
    render();
  } catch (error) {
    setStatus("连接失败", "bad");
    $("timeline").innerHTML = `<div class="empty">读取记录失败：${escapeHtml(error.message || error)}</div>`;
  }
}

function normalizeSelection(keepSelection) {
  const sessions = buildSessions();
  const hasSelectedSession = sessions.some((session) => session.key === state.selectedSession);

  if (!state.selectedSession || (!hasSelectedSession && state.selectedSession !== ALL_SESSIONS)) {
    state.selectedSession = ALL_SESSIONS;
  }

  if (!keepSelection || !state.records.some((record) => record.id === state.selectedId)) {
    state.selectedId = "";
  }
}

function render() {
  renderStats();
  renderFilterOptions("layerFilter", state.records.map((record) => record.layer).filter(Boolean), layerNames);
  renderFilterOptions("typeFilter", state.records.map((record) => record.type).filter(Boolean), typeNames);
  renderFocusMode();
  renderSessions();
  renderSessionSummary();

  const records = groupTimelineRecords(filteredRecords());
  const paged = paginate(records, state.timelinePage, state.timelinePageSize);
  state.timelinePage = paged.page;
  if (!state.selectedId || !paged.items.some((record) => record.id === state.selectedId)) {
    state.selectedId = paged.items[0]?.id || records[0]?.id || "";
  }

  $("recordCount").textContent = `${records.length} 条 · 第 ${paged.page}/${paged.pages} 页`;
  $("timeline").innerHTML = records.length
    ? `${paged.items.map(eventHtml).join("")}${paginationHtml("timeline", paged)}`
    : '<div class="empty">暂无记录</div>';
  bindTimeline(records);
  bindPagination("timeline", (page) => {
    state.timelinePage = page;
    render();
  });

  const selected = records.find((record) => record.id === state.selectedId) || state.records.find((record) => record.id === state.selectedId);
  if (selected) renderDetail(selected);
  else renderEmptyDetail();
}

function renderStats() {
  const stats = state.stats || {};
  const records = state.records;
  const severity = stats.bySeverity || {};
  const toolDecisions = records.filter((record) => record.type === "tool_decision").length;
  const alerts = records.filter((record) => record.type === "alert").length;
  const blocked = records.filter((record) => isBlocked(record)).length;
  const cacheHits = records.filter((record) => record.type === "approval_cache_hit" || record.payload?.approval_cache_hit).length;

  $("recordsPath").textContent = stats.recordsPath || "~/.openclaw/agentsentry/records.jsonl";
  $("statsGrid").innerHTML = [
    statCard("总记录", stats.totalRecords ?? stats.total ?? records.length ?? 0, `最近展示 ${stats.windowRecords ?? records.length} / ${stats.windowLimit ?? $("limitSelect").value}`),
    statCard("会话", stats.sessions || buildSessions().length || 0, "OpenClaw sessions"),
    statCard("高危", severity.danger || 0, "danger", "danger"),
    statCard("警告", severity.warning || 0, "warning", "warning"),
    statCard("工具裁决", toolDecisions, "tool_decision"),
    statCard("告警", alerts, "alert", "danger"),
    statCard("阻断/拒绝", blocked, "block", "danger"),
    statCard("缓存命中", cacheHits, "approval cache"),
  ].join("");
}

function statCard(label, value, caption, tone = "") {
  return `
    <article class="stat ${escapeHtml(tone)}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
      <em>${escapeHtml(caption)}</em>
    </article>
  `;
}

function renderFilterOptions(id, values, labels) {
  const select = $(id);
  const current = select.value;
  const unique = Array.from(new Set(values)).sort();
  select.innerHTML = '<option value="">全部</option>' + unique.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(labels[value] || value)}</option>`).join("");
  select.value = unique.includes(current) ? current : "";
}

function renderSessions() {
  const sessions = buildSessions();
  $("sessionCount").textContent = `${sessions.length}`;

  const allActive = state.selectedSession === ALL_SESSIONS ? "active" : "";
  const allItem = `
    <button class="session-item ${allActive}" data-session="${ALL_SESSIONS}" type="button">
      <span class="session-main">全部会话</span>
      <span class="session-meta">${state.records.length} 条记录</span>
    </button>
  `;

  const items = sessions
    .map((session) => {
      const active = session.key === state.selectedSession ? "active" : "";
      return `
        <button class="session-item ${active}" data-session="${escapeHtml(session.key)}" type="button">
          <span class="session-main">${escapeHtml(compactSession(session.key))}</span>
          <span class="session-meta">${escapeHtml(formatTime(session.latest))} · ${session.count} 条 · ${session.toolCalls} 工具</span>
          <span class="risk-strip">
            ${session.danger ? `<i class="risk danger">${session.danger}</i>` : ""}
            ${session.warning ? `<i class="risk warning">${session.warning}</i>` : ""}
            ${session.alerts ? `<i class="risk danger">告警 ${session.alerts}</i>` : ""}
          </span>
        </button>
      `;
    })
    .join("");

  $("sessionList").innerHTML = allItem + (items || '<div class="empty">暂无会话</div>');

  for (const node of document.querySelectorAll(".session-item")) {
    node.addEventListener("click", () => {
      state.selectedSession = node.dataset.session || ALL_SESSIONS;
      state.selectedId = "";
      resetTimelinePage();
      render();
    });
  }
}

function renderSessionSummary() {
  const records = sessionRecords();
  const title = state.selectedSession === ALL_SESSIONS ? "全部会话" : compactSession(state.selectedSession);
  const first = records.at(-1);
  const latest = records[0];
  const tools = records.filter((record) => record.type === "tool_decision" || record.type === "tool_result");
  const danger = records.filter((record) => record.severity === "danger").length;
  const warning = records.filter((record) => record.severity === "warning").length;
  const blocked = records.filter((record) => isBlocked(record)).length;
  const duration = first && latest ? durationText(first.created_at, latest.created_at) : "-";
  const insight = sessionInsight(records);

  $("sessionSummary").innerHTML = `
    <div class="session-head">
      <div>
        <p class="section-kicker">当前视图</p>
        <h2>${escapeHtml(title || "暂无会话")}</h2>
        <p>${escapeHtml(latest ? latest.session_key : "等待 OpenClaw 运行后产生记录。")}</p>
      </div>
      <div class="session-facts">
        ${fact("事件", records.length)}
        ${fact("工具", tools.length)}
        ${fact("高危", danger, "danger")}
        ${fact("警告", warning, "warning")}
        ${fact("阻断", blocked, "danger")}
        ${fact("跨度", duration)}
      </div>
    </div>
    <div class="insight-card ${escapeHtml(insight.tone)}">
      <strong>${escapeHtml(insight.title)}</strong>
      <span>${escapeHtml(insight.body)}</span>
    </div>
    ${stageRail(records)}
    ${issueDigest(records)}
  `;
}

function fact(label, value, tone = "") {
  return `<div class="fact ${escapeHtml(tone)}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function sessionInsight(records) {
  if (!records.length) {
    return { tone: "", title: "等待记录", body: "当前还没有可展示的 OpenClaw 事件。" };
  }

  const alerts = records.filter((record) => record.type === "alert");
  const deniedTools = records.filter((record) => record.type === "tool_decision" && isBlocked(record));
  const hardcodedSecrets = records.filter((record) => {
    const reason = String(record.payload?.reason || record.summary || record.title || "");
    return /hardcoded secret/i.test(reason);
  });
  const timeouts = records.filter((record) => searchableText(record).includes("timed out") || searchableText(record).includes("timeout"));
  const assistantReplies = records.filter((record) => record.type === "message_write" && record.payload?.role === "assistant");

  if (deniedTools.length || alerts.length) {
    const tools = Array.from(new Set(deniedTools.map((record) => displayTool(record.payload?.toolName || record.payload?.normalized_tool)).filter(Boolean))).join("、") || "高风险工具";
    return { tone: "danger", title: "发现并拦截高风险工具行为", body: `${tools} 触发任务规范外调用；共有 ${alerts.length} 条告警、${deniedTools.length} 次阻断。` };
  }
  if (hardcodedSecrets.length) {
    return { tone: "warning", title: "启动前发现硬编码敏感配置", body: `基础扫描发现 ${hardcodedSecrets.length} 个配置敏感值，建议确认是否为测试密钥或生产密钥。` };
  }
  if (timeouts.length) {
    return { tone: "warning", title: "模型响应链路超时", body: "OpenClaw 已写入运行轨迹，但模型服务没有在超时时间内完成最终回复。" };
  }
  if (assistantReplies.length) {
    return { tone: "success", title: "会话已完成回复", body: "本次会话产生了助手回复，未发现高风险工具阻断。" };
  }
  return { tone: "", title: "会话正在形成", body: "已捕获基础扫描和消息输入，等待后续工具调用或回复记录。" };
}

function stageRail(records) {
  const stages = [
    ["基础扫描", records.filter((record) => record.layer === "Foundation" || record.type === "foundation_scan").length],
    ["输入净化", records.filter((record) => record.layer === "Input Sanitization" || record.type === "message_write").length],
    ["认知保护", records.filter((record) => record.layer === "Cognition Protection" || record.layer === "Sentry Trajectory" || /memory|webhook|poison|taint/i.test(searchableText(record))).length],
    ["决策对齐", records.filter((record) => record.layer === "Decision Alignment" || record.layer === "ABAC Session Policy" || /taskspec|intent|scope|drift|abac/i.test(searchableText(record))).length],
    ["执行控制", records.filter((record) => record.layer === "Execution Control" || record.layer === "System Preflight" || record.layer === "Tool Result" || ["tool_decision", "tool_result", "alert", "response_cover"].includes(record.type)).length],
  ];
  return `
    <div class="stage-rail">
      ${stages.map(([label, count]) => `<div class="stage ${count ? "active" : ""}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(count)}</strong></div>`).join("")}
    </div>
  `;
}

function issueDigest(records) {
  const issues = [];
  const hardcoded = records.filter((record) => /hardcoded secret/i.test(String(record.payload?.reason || record.summary || record.title || "")));
  const grouped = records.filter((record) => record.type === "finding_group");
  const denied = records.filter((record) => record.type === "tool_decision" && isBlocked(record));
  const timeouts = records.filter((record) => searchableText(record).includes("timed out") || searchableText(record).includes("timeout"));

  if (hardcoded.length) issues.push(["硬编码敏感值", hardcoded.length, "warning"]);
  if (grouped.length) issues.push(["已折叠扫描噪声", grouped.reduce((sum, record) => sum + Number(record.payload?.count || 0), 0), "warning"]);
  if (denied.length) issues.push(["工具阻断", denied.length, "danger"]);
  if (timeouts.length) issues.push(["超时", timeouts.length, "warning"]);
  if (!issues.length) return "";

  return `<div class="issue-digest">${issues.map(([label, count, tone]) => `<span class="${escapeHtml(tone)}">${escapeHtml(label)} ${escapeHtml(count)}</span>`).join("")}</div>`;
}

function renderFocusMode() {
  for (const node of document.querySelectorAll("[data-focus]")) {
    node.classList.toggle("active", node.dataset.focus === state.focusMode);
  }
}

function filteredRecords() {
  const query = $("searchInput").value.trim().toLowerCase();
  const severity = $("severityFilter").value;
  const layer = $("layerFilter").value;
  const type = $("typeFilter").value;

  let records = sessionRecords();
  records = applyFocusMode(records);
  records = records.filter((record) => {
    if (severity && record.severity !== severity) return false;
    if (layer && record.layer !== layer) return false;
    if (type && record.type !== type) return false;
    if (!query) return true;
    return searchableText(record).includes(query);
  });

  return sortRecordsDesc(records);
}

function resetTimelinePage() {
  state.timelinePage = 1;
}

function applyFocusMode(records) {
  if (state.focusMode === "all") return records;
  if (state.focusMode === "tools") {
    return records.filter((record) => ["tool_decision", "tool_result", "alert", "approval_resolution", "approval_cache_hit"].includes(record.type));
  }
  if (state.focusMode === "foundation") {
    return records.filter((record) => record.layer === "Foundation" || record.type === "foundation_scan");
  }
  return records.filter((record) => isImportantRecord(record));
}

function isImportantRecord(record) {
  if (record.severity === "danger") return true;
  if (["tool_decision", "tool_result", "alert", "response_cover", "approval_resolution", "approval_cache_hit"].includes(record.type)) return true;
  if (record.type === "message_write") {
    const role = record.payload?.role;
    return role === "user" || role === "assistant";
  }
  if (record.type === "guard_finding") {
    const reason = String(record.payload?.reason || record.summary || record.title || "");
    return /hardcoded secret|embedded secrets|sensitive asset/i.test(reason);
  }
  if (record.type === "finding_group") return true;
  if (record.type === "foundation_scan") return Number(record.payload?.findingCount || record.payload?.findings || 0) > 0;
  return ["session_start", "llm_input"].includes(record.type);
}

function sessionRecords() {
  if (state.selectedSession && state.selectedSession !== ALL_SESSIONS) {
    return state.records.filter((record) => record.session_key === state.selectedSession);
  }
  return state.records;
}

function groupTimelineRecords(records) {
  const buckets = new Map();
  for (const record of records) {
    if (!isGroupableFoundationFinding(record)) continue;
    const key = foundationFindingKey(record);
    const bucket = buckets.get(key) || [];
    bucket.push(record);
    buckets.set(key, bucket);
  }

  const groupedIds = new Set();
  const firstRecordByKey = new Map();
  for (const [key, bucket] of buckets) {
    if (bucket.length < 3) continue;
    const latest = bucket.slice().sort(compareRecordsDesc)[0];
    firstRecordByKey.set(latest.id, { key, bucket });
    for (const record of bucket) groupedIds.add(record.id);
  }

  const output = [];
  for (const record of sortRecordsDesc(records)) {
    const group = firstRecordByKey.get(record.id);
    if (group) {
      output.push(makeFoundationFindingGroup(group.key, group.bucket));
      continue;
    }
    if (groupedIds.has(record.id)) continue;
    output.push(record);
  }
  return sortRecordsDesc(output);
}

function paginate(items, page, pageSize) {
  const total = items.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.max(1, Math.min(pages, Number(page) || 1));
  const start = (safePage - 1) * pageSize;
  return {
    items: items.slice(start, start + pageSize),
    page: safePage,
    pages,
    total,
    start: total ? start + 1 : 0,
    end: Math.min(total, start + pageSize),
  };
}

function paginationHtml(id, pageInfo) {
  if (pageInfo.pages <= 1) return "";
  return `
    <nav class="pagination" data-pagination="${escapeHtml(id)}">
      <button type="button" data-page="${pageInfo.page - 1}" ${pageInfo.page <= 1 ? "disabled" : ""}>上一页</button>
      <span>${pageInfo.start}-${pageInfo.end} / ${pageInfo.total}</span>
      <button type="button" data-page="${pageInfo.page + 1}" ${pageInfo.page >= pageInfo.pages ? "disabled" : ""}>下一页</button>
    </nav>
  `;
}

function bindPagination(id, onPage) {
  document.querySelectorAll(`[data-pagination="${id}"] [data-page]`).forEach((button) => {
    button.addEventListener("click", () => onPage(Number(button.dataset.page || 1)));
  });
}

function isGroupableFoundationFinding(record) {
  return record.type === "guard_finding"
    && record.layer === "Foundation"
    && record.severity === "warning";
}

function foundationFindingKey(record) {
  const payload = record.payload || {};
  const reason = payload.reason || record.summary || record.title || "foundation finding";
  const confidence = payload.evidence?.confidence || "";
  return [record.session_key || "", record.layer || "", record.severity || "", reason, confidence].join("|");
}

function makeFoundationFindingGroup(key, bucket) {
  const sortedBucket = bucket.slice().sort(compareRecordsDesc);
  const first = sortedBucket[0];
  const payload = first.payload || {};
  const reason = payload.reason || first.summary || first.title || "foundation finding";
  const paths = Array.from(new Set(bucket.map((record) => record.payload?.evidence?.path).filter(Boolean)));
  const confidence = payload.evidence?.confidence || "medium";
  return {
    id: `group:${key}`,
    created_at: first.created_at,
    run_id: first.run_id,
    session_key: first.session_key,
    type: "finding_group",
    layer: first.layer,
    severity: first.severity,
    title: `${translateText(reason)}（${bucket.length} 项）`,
    summary: `已折叠 ${bucket.length} 条同类基础扫描发现，涉及 ${paths.length || bucket.length} 个文件。`,
    payload: {
      grouped: true,
      group_type: "foundation_findings",
      count: bucket.length,
      reason,
      confidence,
      paths: paths.slice(0, 120),
      omitted_paths: Math.max(0, paths.length - 120),
      record_ids: sortedBucket.slice(0, 10).map((record) => record.id),
    },
  };
}

function sortRecordsDesc(records) {
  return records.slice().sort(compareRecordsDesc);
}

function compareRecordsDesc(a, b) {
  const timeA = new Date(a.created_at || 0).getTime();
  const timeB = new Date(b.created_at || 0).getTime();
  if (timeA !== timeB) return timeB - timeA;
  return String(b.id || "").localeCompare(String(a.id || ""));
}

function buildSessions() {
  const groups = new Map();
  for (const record of state.records) {
    const key = record.session_key || "session_unknown";
    const item = groups.get(key) || {
      key,
      count: 0,
      latest: record.created_at,
      danger: 0,
      warning: 0,
      alerts: 0,
      toolCalls: 0,
    };
    item.count += 1;
    if (new Date(record.created_at) > new Date(item.latest)) item.latest = record.created_at;
    if (record.severity === "danger") item.danger += 1;
    if (record.severity === "warning") item.warning += 1;
    if (record.type === "alert") item.alerts += 1;
    if (record.type === "tool_decision" || record.type === "tool_result") item.toolCalls += 1;
    groups.set(key, item);
  }
  return Array.from(groups.values()).sort((a, b) => new Date(b.latest) - new Date(a.latest));
}

function eventHtml(record) {
  const active = record.id === state.selectedId ? "active" : "";
  return `
    <article class="event ${escapeHtml(record.severity)} ${active}" data-id="${escapeHtml(record.id)}">
      <div class="event-pin">
        <span>${escapeHtml(formatTime(record.created_at))}</span>
      </div>
      <div class="event-main">
        <div class="event-title-row">
          <strong>${escapeHtml(titleText(record))}</strong>
          <span>${escapeHtml(typeNames[record.type] || record.type)}</span>
        </div>
        <div class="event-summary">${escapeHtml(summaryText(record))}</div>
        <div class="chips">
          ${chip(severityNames[record.severity] || record.severity, record.severity)}
          ${chip(layerNames[record.layer] || record.layer || "-", "layer")}
          ${chip(compactSession(record.session_key), "session")}
        </div>
      </div>
    </article>
  `;
}

function bindTimeline(records) {
  for (const node of document.querySelectorAll(".event")) {
    node.addEventListener("click", () => {
      state.selectedId = node.dataset.id || "";
      const record = records.find((item) => item.id === state.selectedId);
      if (record) renderDetail(record);
      for (const item of document.querySelectorAll(".event.active")) item.classList.remove("active");
      node.classList.add("active");
    });
  }
}

function renderDetail(record) {
  state.selectedRecord = record;
  $("detailMeta").textContent = `${severityNames[record.severity] || record.severity} · ${formatDate(record.created_at)}`;
  $("copyPayloadBtn").disabled = false;
  $("copyPayloadBtn").dataset.recordId = record.id;

  $("detailBody").innerHTML = `
    <section class="detail-summary ${escapeHtml(record.severity)}">
      <h3>${escapeHtml(titleText(record))}</h3>
      <p>${escapeHtml(summaryText(record))}</p>
    </section>
    ${quickFacts(record)}
    ${decisionSummary(record)}
    ${groupSummary(record)}
    <pre>${escapeHtml(JSON.stringify(record, null, 2))}</pre>
  `;
}

function renderEmptyDetail() {
  state.selectedRecord = null;
  $("detailMeta").textContent = "未选择";
  $("copyPayloadBtn").disabled = true;
  $("copyPayloadBtn").dataset.recordId = "";
  $("detailBody").innerHTML = '<div class="empty">选择一条记录查看摘要和 payload。</div>';
}

function quickFacts(record) {
  const payload = record.payload || {};
  const rows = [
    ["类型", typeNames[record.type] || record.type],
    ["层", layerNames[record.layer] || record.layer || "-"],
    ["会话", record.session_key || "-"],
    ["Run", record.run_id || "-"],
  ];

  if (payload.toolName || payload.normalized_tool) rows.push(["工具", payload.normalized_tool ? `${displayTool(payload.toolName || "-")} -> ${displayTool(payload.normalized_tool)}` : displayTool(payload.toolName)]);
  if (payload.role) rows.push(["消息角色", roleNames[payload.role] || payload.role]);
  if (payload.stopReason) rows.push(["停止原因", stopReasonNames[payload.stopReason] || payload.stopReason]);
  if (payload.decision || payload.original_decision) rows.push(["裁决", `${decisionNames[payload.decision] || payload.decision || "-"} / ${decisionNames[payload.original_decision] || payload.original_decision || "-"}`]);
  if (payload.risk_score !== undefined) rows.push(["风险分", payload.risk_score]);
  if (payload.approval_cache_hit !== undefined) rows.push(["审批缓存", payload.approval_cache_hit ? "命中" : "未命中"]);
  if (payload.grouped) {
    rows.push(["折叠数量", payload.count || "-"]);
    rows.push(["置信度", confidenceLabel(payload.confidence)]);
  }

  return `<section class="fact-table">${rows.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("")}</section>`;
}

function decisionSummary(record) {
  const payload = record.payload || {};
  if (!["tool_decision", "approval_resolution", "approval_cache_hit", "response_cover", "alert"].includes(record.type)) return "";

  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  const rows = [
    ["判定", decisionNames[payload.verdict] || decisionNames[payload.decision] || payload.verdict || payload.decision || "-"],
    ["确定性阻断", payload.deterministic_block ? "是" : "否"],
    ["违规原因", translateText((payload.violations || []).join("; ") || payload.summary || "-")],
    ["允许工具", payload.task_spec?.allowed_tools?.map(displayTool).join(", ") || "-"],
    ["发现类型", findingTypeSummary(findings)],
  ];

  return `<section class="decision-summary">${rows.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("")}</section>`;
}

function groupSummary(record) {
  const payload = record.payload || {};
  if (!payload.grouped) return "";
  const paths = Array.isArray(payload.paths) ? payload.paths : [];
  const omitted = payload.omitted_paths ? `<p>另有 ${escapeHtml(payload.omitted_paths)} 个路径未展开。</p>` : "";
  return `
    <section class="path-list">
      <h3>涉及文件</h3>
      <p>${escapeHtml(translateText(payload.reason || record.summary || ""))} · ${escapeHtml(confidenceLabel(payload.confidence))}</p>
      <ul>
        ${paths.slice(0, 40).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
      </ul>
      ${omitted}
    </section>
  `;
}

function findingTypeSummary(findings) {
  if (!Array.isArray(findings) || !findings.length) return "-";
  const counts = findings.reduce((acc, finding) => {
    const key = finding.finding_type || "unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  return Object.entries(counts).map(([key, value]) => `${findingTypeNames[key] || key}:${value}`).join(", ");
}

function titleText(record) {
  const raw = record.title || typeNames[record.type] || record.type || "";
  return translateText(raw);
}

function displayTool(value) {
  const key = String(value || "").trim();
  return toolNames[key] || key || "-";
}

function confidenceLabel(value) {
  return {
    high: "高置信",
    medium: "中置信",
    low: "低置信",
  }[value] || value || "-";
}

function translateText(value) {
  let text = compactText(value);
  for (const [pattern, replacement] of textTranslations) {
    text = text.replace(pattern, replacement);
  }
  return text;
}

function summaryText(record) {
  const payload = record.payload || {};

  if (record.type === "finding_group") {
    return `${record.summary || ""} ${translateText(payload.reason || "")}`.trim();
  }
  if (record.type === "tool_decision") {
    return translateText((payload.violations || []).join("; ") || payload.summary || `${displayTool(payload.toolName || "tool")} -> ${decisionNames[payload.decision] || payload.decision || payload.verdict || "裁决"}`);
  }
  if (record.type === "guard_finding") {
    return translateText(payload.reason || record.summary || "");
  }
  if (record.type === "message_write") {
    const preview = previewText(payload.preview);
    if (preview) return `${roleNames[payload.role] || payload.role || "消息"}：${preview}`;
  }
  if (record.type === "tool_result") {
    return payload.error ? translateText(payload.error) : "工具返回完成";
  }
  return translateText(compactText(record.summary || payload.summary || JSON.stringify(payload).slice(0, 220)));
}

function previewText(value) {
  if (!value) return "";
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) {
      return parsed
        .map((item) => {
          if (item.type === "toolCall") return `调用工具 ${displayTool(item.name || "-")}`;
          if (item.type === "text") return translateText(item.text || "");
          return item.type || "";
        })
        .filter(Boolean)
        .join(" ");
    }
  } catch {
    return translateText(compactText(value));
  }
  return translateText(compactText(value));
}

function chip(label, kind) {
  return `<span class="chip ${escapeHtml(kind)}">${escapeHtml(label || "-")}</span>`;
}

function isBlocked(record) {
  const payload = record.payload || {};
  return record.severity === "danger" || payload.verdict === "block" || payload.decision === "deny" || payload.original_decision === "deny";
}

function searchableText(record) {
  return `${record.title} ${record.summary} ${record.type} ${record.layer} ${record.session_key} ${record.run_id} ${JSON.stringify(record.payload)}`.toLowerCase();
}

function compactSession(value) {
  const text = String(value || "-").replace(/^agent:main:/, "");
  if (text.length <= 34) return text;
  return `${text.slice(0, 22)}...${text.slice(-8)}`;
}

function compactText(value, max = 420) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function formatTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleTimeString("zh-CN", { hour12: false });
}

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function durationText(start, end) {
  const diff = Math.max(0, new Date(end) - new Date(start));
  if (diff < 1000) return `${diff} ms`;
  if (diff < 60_000) return `${Math.round(diff / 1000)} s`;
  return `${Math.round(diff / 60_000)} min`;
}

function setStatus(text, tone) {
  const node = $("status");
  node.textContent = text;
  node.className = `pill ${tone || ""}`;
}

function downloadExport(format) {
  const limit = $("limitSelect").value;
  window.location.href = `/api/export?format=${encodeURIComponent(format)}&limit=${encodeURIComponent(limit)}`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[char]);
}

async function copySelectedPayload() {
  const id = $("copyPayloadBtn").dataset.recordId;
  const record = state.selectedRecord?.id === id ? state.selectedRecord : state.records.find((item) => item.id === id);
  if (!record) return;
  const text = JSON.stringify(record, null, 2);
  try {
    await navigator.clipboard.writeText(text);
    $("copyPayloadBtn").textContent = "已复制";
    setTimeout(() => ($("copyPayloadBtn").textContent = "复制 JSON"), 1200);
  } catch {
    $("copyPayloadBtn").textContent = "复制失败";
    setTimeout(() => ($("copyPayloadBtn").textContent = "复制 JSON"), 1200);
  }
}

function scheduleAutoRefresh() {
  if (state.timer) clearInterval(state.timer);
  state.timer = state.autoRefresh ? setInterval(() => refresh({ keepSelection: true }), 5000) : null;
  $("autoRefreshBtn").textContent = `自动刷新：${state.autoRefresh ? "开" : "关"}`;
}

$("refreshBtn").addEventListener("click", () => refresh({ keepSelection: true }));
$("autoRefreshBtn").addEventListener("click", () => {
  state.autoRefresh = !state.autoRefresh;
  scheduleAutoRefresh();
});
$("focusModeGroup").addEventListener("click", (event) => {
  const target = event.target.closest("[data-focus]");
  if (!target) return;
  state.focusMode = target.dataset.focus || "important";
  state.selectedId = "";
  resetTimelinePage();
  render();
});
$("exportJsonBtn").addEventListener("click", () => downloadExport("json"));
$("exportCsvBtn").addEventListener("click", () => downloadExport("csv"));
$("copyPayloadBtn").addEventListener("click", copySelectedPayload);
$("resetBtn").addEventListener("click", async () => {
  if (!confirm("确认清空 AgentSentry 本地记录？")) return;
  await fetch("/api/reset", { method: "POST" });
  state.selectedId = "";
  state.selectedSession = "";
  await refresh({ keepSelection: false });
});

for (const id of ["searchInput", "severityFilter", "layerFilter", "typeFilter"]) {
  $(id).addEventListener("input", () => {
    resetTimelinePage();
    render();
  });
  $(id).addEventListener("change", () => {
    resetTimelinePage();
    render();
  });
}

$("limitSelect").addEventListener("change", () => {
  resetTimelinePage();
  refresh({ keepSelection: true });
});

scheduleAutoRefresh();
refresh({ keepSelection: false });
