import { normalizeVerdict, verdictLabel, verdictMeta } from "/verdict.js?v=20260809-1";

const $ = (id) => document.getElementById(id);

const PAGE_BY_PATH = new Map([
  ["/overview", "overview"],
  ["/agents", "agents"],
  ["/policies", "policies"],
  ["/tools", "tools"],
  ["/alerts", "alerts"],
  ["/audit", "audit"],
  ["/settings", "settings"],
]);

const PAGE_META = {
  overview: {
    title: "安全总览",
    eyebrow: "实时安全态势",
    description: "先看当前是否安全，再处理高风险事件与待审批动作。",
  },
  agents: {
    title: "智能体资产",
    eyebrow: "身份与授权边界",
    description: "核对智能体身份、委托边界、信任等级与最近活动。",
  },
  policies: {
    title: "策略管理",
    eyebrow: "执行边界",
    description: "管理确定性裁决、语义复核、污点回流与资源边界。",
  },
  tools: {
    title: "工具管理",
    eyebrow: "工具信任清单",
    description: "检查工具签名、数据来源、副作用、外泄能力与吊销状态。",
  },
  alerts: {
    title: "告警中心",
    eyebrow: "安全调查队列",
    description: "按处置优先级调查行为链、越界位置与玄鉴裁决。",
  },
  audit: {
    title: "审计日志",
    eyebrow: "完整审计链路",
    description: "检索玄鉴产生的工具调用、策略裁决、审批与执行结果。",
  },
  settings: {
    title: "系统设置",
    eyebrow: "运行控制",
    description: "查看执行模式、安全栈、运行隔离、监控状态与回滚检查点。",
  },
};

const POLICY_TOGGLES = [
  ["deterministic", "scale", "确定性策略", "在执行前应用 TaskSpec、目标范围与敏感资源硬规则。"],
  ["taintFeedback", "git-branch", "污点与证据回流", "持续记录不可信数据来源、传播字段与外部 Sink。"],
  ["semantic", "brain-circuit", "语义复核", "对高风险或边界不清晰的动作执行语义判断。"],
  ["runtimeAudit", "activity", "执行后审计", "将工具结果与运行时反馈写回审计链路。"],
  ["strictShellNetworkIsolation", "network", "Shell 网络隔离", "要求 Shell 网络访问运行在受控命名空间。"],
  ["initializationDefense", "shield-ellipsis", "初始化防线", "盘点 Skill、配置和启动组件的完整性与权限。"],
  ["rollback", "history", "Checkpoint 回滚", "在高影响写操作前保留可恢复快照。"],
  ["multiAgentSecurity", "network", "多 Agent 身份链", "约束委托、跨 Agent 消息和敏感能力授权。"],
  ["responseCover", "scan-text", "污染响应覆盖", "对已污染响应应用安全覆盖与降级输出。"],
];

const POLICY_LISTS = [
  ["allowlistedRecipients", "允许的外部目标", "邮箱", "填写域名、邮箱或目标标识"],
  ["allowlistedApiHosts", "允许的 API 主机", "API Host", "填写域名或主机"],
  ["allowedWriteRoots", "允许写入的根目录", "目录", "填写工作区内的目录"],
  ["sensitiveAssets", "敏感资产特征", "敏感特征", "填写文件名、密钥或关键词"],
];

const POLICY_GROUPS = [
  {
    key: "execution",
    label: "执行控制",
    description: "约束工具在调用前后的执行边界。",
    toggles: ["deterministic", "runtimeAudit", "strictShellNetworkIsolation", "rollback"],
  },
  {
    key: "data",
    label: "数据安全",
    description: "追踪不可信内容与敏感数据的传播。",
    toggles: ["taintFeedback", "responseCover"],
  },
  {
    key: "agent",
    label: "Agent 安全",
    description: "控制身份链、初始化组件与语义复核。",
    toggles: ["multiAgentSecurity", "initializationDefense", "semantic"],
  },
];

const AUDIT_QUERY_STORAGE_KEY = "agentsentry-audit-saved-query";

const state = {
  page: PAGE_BY_PATH.get(normalizePath(window.location.pathname)) || "overview",
  data: {},
  loading: false,
  alertPage: 1,
  auditPage: 1,
  auditPageSize: 40,
  dirty: false,
  refreshTimer: null,
  dialogConfirm: null,
  filters: {
    agentSearch: "",
    toolSearch: "",
    toolTrust: "all",
    alertSearch: "",
    alertSeverity: "all",
    alertAction: "all",
    auditSearch: "",
    auditType: "all",
    auditSeverity: "all",
    auditTool: "all",
    auditVerdict: "all",
    auditTime: "all",
  },
  policyChanges: new Set(),
  savedAuditQuery: null,
};

initialize();

async function initialize() {
  state.savedAuditQuery = readSavedAuditQuery();
  bindInteractions();
  renderChrome();
  renderIcons();
  await refreshData();
  if (["overview", "alerts", "audit"].includes(state.page)) {
    state.refreshTimer = window.setInterval(() => {
      if (!document.hidden && !state.loading && !state.dirty) void refreshData({ quiet: true });
    }, 15000);
  }
}

function normalizePath(pathname) {
  const path = String(pathname || "/").replace(/\/+$/, "");
  return path || "/";
}

function renderChrome() {
  const meta = PAGE_META[state.page];
  document.title = `玄鉴 · ${meta.title}`;
  $("workspaceTitle").textContent = meta.title;
  $("workspacePageTitle").textContent = meta.title;
  $("workspaceEyebrow").textContent = meta.eyebrow;
  $("workspaceDescription").textContent = meta.description;
  for (const link of document.querySelectorAll("[data-nav]")) {
    const active = link.dataset.nav === state.page;
    link.classList.toggle("active", active);
    if (active) {
      link.setAttribute("aria-current", "page");
      if (!link.querySelector(".nav-active-marker")) {
        link.insertAdjacentHTML("beforeend", '<i class="nav-active-marker" data-lucide="chevron-right"></i>');
      }
    } else {
      link.removeAttribute("aria-current");
      link.querySelector(".nav-active-marker")?.remove();
    }
  }
  renderWorkspaceActions();
}

function renderWorkspaceActions() {
  const actions = $("workspaceActions");
  const byPage = {
    overview: '<a class="workspace-secondary" href="/"><i data-lucide="siren"></i><span>进入攻击监控</span></a>',
    agents: '<button class="workspace-secondary" type="button" data-action="refresh"><i data-lucide="refresh-cw"></i><span>刷新资产</span></button>',
    policies: '<span class="workspace-action-state"><i data-lucide="shield-check"></i>策略实时生效</span>',
    tools: '<button class="workspace-primary" type="button" data-action="register-tool"><i data-lucide="badge-plus"></i><span>登记工具</span></button>',
    alerts: '<a class="workspace-secondary" href="/"><i data-lucide="waypoints"></i><span>查看因果图</span></a>',
    audit: '<a class="workspace-secondary" href="/api/export?format=csv"><i data-lucide="sheet"></i><span>导出 CSV</span></a><a class="workspace-primary" href="/api/export?format=json"><i data-lucide="download"></i><span>导出审计</span></a>',
    settings: '<button class="workspace-secondary" type="button" data-action="refresh"><i data-lucide="refresh-cw"></i><span>刷新状态</span></button>',
  };
  actions.innerHTML = byPage[state.page] || "";
}

async function refreshData({ quiet = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  if (!quiet) renderLoading();
  $("refreshBtn").classList.add("spinning");
  setConnection("connecting", "同步中");

  try {
    const [overview, enforcement, pageData] = await Promise.all([
      fetchJson("/api/security/overview?limit=1000"),
      fetchJson("/api/settings/enforcement"),
      loadPageData(),
    ]);
    state.data = { ...pageData, overview, enforcement };
    renderHeaderData();
    renderPage();
    setConnection(overview?.source?.openclaw_available === false ? "warning" : "live", overview?.source?.openclaw_available === false ? "降级" : "实时");
  } catch (error) {
    setConnection("error", "连接失败");
    renderError(error);
    showToast(`无法读取运营数据：${error?.message || error}`, "error");
  } finally {
    state.loading = false;
    $("refreshBtn").classList.remove("spinning");
  }
}

async function loadPageData() {
  switch (state.page) {
    case "agents": {
      const [policy, records] = await Promise.all([
        fetchJson("/api/policy/config"),
        fetchJson("/api/records?limit=1000&compact=1"),
      ]);
      return { policy, records };
    }
    case "policies":
      return { policy: await fetchJson("/api/policy/config") };
    case "tools": {
      const [tools, policy] = await Promise.all([
        fetchJson("/api/tools/manifests"),
        fetchJson("/api/policy/config"),
      ]);
      return { tools, policy };
    }
    case "alerts":
      return { alerts: await fetchJson(`/api/security/alerts?page=${state.alertPage}&pageSize=25`) };
    case "audit": {
      const [records, stats] = await Promise.all([
        fetchJson("/api/records?limit=2000"),
        fetchJson("/api/stats?limit=5000"),
      ]);
      return { records, stats };
    }
    case "settings": {
      const [health, checkpoints, policy] = await Promise.all([
        fetchJson("/api/health"),
        fetchJson("/api/checkpoints?limit=100"),
        fetchJson("/api/policy/config"),
      ]);
      return { health, checkpoints, policy };
    }
    default:
      return {};
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

function renderHeaderData() {
  const { overview = {}, enforcement = {} } = state.data;
  const modeSelect = $("modeSelect");
  if (enforcement.mode && modeSelect.value !== enforcement.mode) modeSelect.value = enforcement.mode;
  $("runtimeProfile").textContent = brandText([enforcement.profile, enforcement.mode].filter(Boolean).join(" · ") || "未记录");
  const total = overview?.source?.window_records ?? overview?.metrics?.find((item) => item.key === "total")?.num ?? 0;
  $("workspaceHeaderMeta").textContent = `${formatNumber(total)} 条事件 · ${formatClock(overview.generated_at)}`;
  const count = Math.max(0, Number(overview.alertCount) || 0);
  const display = count > 99 ? "99+" : String(count);
  for (const id of ["headerAlertCount", "navAlertCount"]) {
    const badge = $(id);
    badge.textContent = display;
    badge.hidden = count === 0;
  }
  const notificationLink = document.querySelector(".notification-button");
  notificationLink?.setAttribute("aria-label", count ? `查看告警，${display} 条` : "查看告警");
}

function renderPage() {
  switch (state.page) {
    case "overview": renderOverview(); break;
    case "agents": renderAgents(); break;
    case "policies": renderPolicies(); break;
    case "tools": renderTools(); break;
    case "alerts": renderAlerts(); break;
    case "audit": renderAudit(); break;
    case "settings": renderSettings(); break;
    default: renderOverview();
  }
  renderIcons();
}

function renderOverview() {
  const overview = state.data.overview || {};
  const metrics = Array.isArray(overview.metrics) ? overview.metrics : [];
  const lifecycle = Array.isArray(overview.lifecycle) ? overview.lifecycle : [];
  const rules = Array.isArray(overview.rules) ? overview.rules.slice(0, 6) : [];
  const operations = Array.isArray(overview.recentOperations) ? overview.recentOperations.slice(0, 10) : [];
  const metricByKey = new Map(metrics.map((metric) => [String(metric.key), metric]));
  const secondaryMetrics = ["total", "tools", "taint", "drift"]
    .map((key) => metricByKey.get(key))
    .filter(Boolean);
  const primaryRisks = [...lifecycle]
    .filter((item) => (Number(item?.[2]) || 0) > 0)
    .sort((left, right) => (Number(left?.[1]) || 0) - (Number(right?.[1]) || 0))
    .slice(0, 3);
  const protection = protectionStatus(overview.protectionIndex);
  const blocked = Number(metricByKey.get("blocks")?.num ?? overview.blockedHighRisk) || 0;
  const pending = Number(metricByKey.get("pending")?.num) || 0;
  const allowed = Number(metricByKey.get("allowed")?.num) || 0;
  const windowRecords = Number(overview?.source?.window_records ?? metricByKey.get("total")?.num) || 0;
  const riskDimensions = completeRiskDimensions(primaryRisks, metricByKey, windowRecords);
  const contributors = riskContributions(riskDimensions, overview.protectionIndex);
  const blockTrend = metricTrendLabel(metricByKey.get("blocks")?.trend);

  $("workspaceContent").innerHTML = `
    <section class="overview-command-center" aria-label="当前安全状态">
      <div class="posture-primary">
        <div class="overview-block-heading"><i data-lucide="shield-check"></i><span>安全态势评分</span></div>
        <div class="posture-value"><strong>${formatNumber(overview.protectionIndex)}</strong><span>/100</span></div>
        <div class="posture-status-line"><span class="posture-state tone-${protection.tone}">${escapeHtml(protection.label)}</span><span class="posture-trend"><i data-lucide="trending-up"></i>${escapeHtml(blockTrend)}</span></div>
        <div class="risk-contributors" aria-label="安全分风险贡献">
          ${contributors.map((item) => `<span><b>${escapeHtml(item.label)}</b><strong>+${formatNumber(item.points)}</strong></span>`).join("") || `<span><b>当前窗口</b><strong>稳定</strong></span>`}
        </div>
        <p class="posture-proof"><strong>${formatNumber(blocked)}</strong> 个高危行为已在执行前阻断</p>
      </div>

      <div class="posture-risk">
        <header class="overview-block-header"><div><h3>主要风险</h3><small>${formatNumber(windowRecords)} 条实时记录</small></div></header>
        <div class="lifecycle-list">
          ${riskDimensions.map((item) => {
            const containment = Number(item?.[1]) || 0;
            const exposure = Math.max(0, Math.min(100, 100 - containment));
            const total = Number(item?.[2]) || 0;
            const tone = exposure >= 55 ? "danger" : exposure >= 25 ? "warning" : "safe";
            return `<div class="lifecycle-row tone-${tone}">
              <div class="lifecycle-label"><span>${escapeHtml(item?.[0] || "未分类")}</span><small>${formatNumber(total)} 条相关事件</small></div>
              <div class="metric-track" style="--value:${exposure}%"><span></span></div>
              <b>${formatNumber(exposure)}%</b>
            </div>`;
          }).join("") || emptyInline("暂无风险数据")}
        </div>
      </div>

      <div class="posture-queue">
        <header class="overview-block-header"><div><h3>需要处理</h3><small>按处置优先级排列</small></div></header>
        <nav class="attention-list" aria-label="待处理事项">
          ${attentionRow("高危事件", blocked, "立即复核", "danger", "/alerts")}
          ${attentionRow("待审批", pending, pending ? "需要人工裁决" : "当前无积压", "warning", "/alerts")}
          ${attentionRow("策略放行", allowed, allowed ? "检查例外范围" : "当前无例外", "neutral", "/audit")}
        </nav>
      </div>
    </section>

    <section class="overview-metric-strip" aria-label="运行指标">
      ${secondaryMetrics.map((metric) => `
        <article class="overview-metric tone-${metricTone(metric.type, metric.num)}">
          <span class="metric-icon"><i data-lucide="${metricIcon(metric.key)}"></i></span>
          <small>${escapeHtml(metric.cn || metric.key)}</small>
          <strong>${formatNumber(metric.num)}</strong>
          <span>${escapeHtml(metricTrendLabel(metric.trend))}</span>
        </article>
      `).join("") || emptyInline("暂无指标")}
    </section>

    <div class="workspace-grid-two overview-investigation-grid">
      <section class="workspace-section operation-stream-section">
        ${sectionHeader("activity", "最近运行事件", `${operations.length} 条`)}
        <div class="operation-feed">
          ${operations.map((item) => {
            const record = findRecordForOperation(item);
            return `<button class="operation-row" type="button" ${record ? `data-record-id="${escapeHtml(record.id)}"` : ""}>
              <time>${escapeHtml(item.time || "--:--:--")}</time>
              <span class="operation-kind">${escapeHtml(typeLabel(item.type))}</span>
              <div><strong>${escapeHtml(item.reason || "未记录事件")}</strong><small><code>${escapeHtml(item.tool || "agent")}</code> · ${escapeHtml(sourceLabel(item.source))}</small></div>
              ${decisionBadge(item.decision)}
              <i data-lucide="chevron-right"></i>
            </button>`;
          }).join("") || emptyInline("暂无运行事件")}
        </div>
      </section>

      <section class="workspace-section top-rules-section">
        ${sectionHeader("list-checks", "Top Rules", `${rules.length} 条规则`)}
        <div class="rule-list">
          ${rules.map((item, index) => `<div class="rule-row"><span>${index + 1}</span><code title="${escapeHtml(item?.[0])}">${escapeHtml(item?.[0] || "未命名规则")}</code><b>${formatNumber(item?.[1])}</b><small>${formatNumber(item?.[2])}%</small></div>`).join("") || emptyInline("暂无策略命中")}
        </div>
        <a class="section-text-link" href="/audit">查看完整审计<i data-lucide="arrow-right"></i></a>
      </section>
    </div>`;
}

function renderAgents() {
  const agents = Array.isArray(state.data.policy?.agents) ? state.data.policy.agents : [];
  const records = recordList();
  const search = state.filters.agentSearch.trim().toLowerCase();
  const filtered = agents.filter((agent) => !search || JSON.stringify(agent).toLowerCase().includes(search));
  const delegators = agents.filter((agent) => agent.mayDelegate).length;
  const sensitive = agents.filter((agent) => agent.mayAuthorizeSensitiveTools).length;
  const untrustedReceivers = agents.filter((agent) => agent.mayReceiveUntrustedData).length;
  const runs = Array.isArray(state.data.overview?.runs) ? state.data.overview.runs : [];
  const owner = filtered.find((agent) => agent.level === "owner") || filtered[0];
  const delegates = filtered.filter((agent) => agent !== owner);

  $("workspaceContent").innerHTML = `
    <section class="workspace-section inventory-toolbar-section">
      <div class="workspace-toolbar identity-toolbar">
        <label class="workspace-search"><i data-lucide="search"></i><input class="workspace-input" name="agentSearch" data-filter="agentSearch" value="${escapeHtml(state.filters.agentSearch)}" placeholder="搜索名称、ID、租户或命名空间" aria-label="搜索智能体" /></label>
        <span class="toolbar-spacer"></span>
        <div class="inline-stats" aria-label="智能体资产摘要">
          <span><strong>${formatNumber(agents.length)}</strong> 个身份</span>
          <span><strong>${formatNumber(delegators)}</strong> 可委托</span>
          <span><strong>${formatNumber(sensitive)}</strong> 可授权敏感工具</span>
          <span class="${untrustedReceivers ? "tone-warning" : ""}"><strong>${formatNumber(untrustedReceivers)}</strong> 接收不可信数据</span>
        </div>
      </div>
    </section>

    <section class="agent-card-grid" aria-label="智能体身份清单">
      ${filtered.map((agent) => {
        const latest = latestAgentRecord(agent, records);
        const score = Math.max(0, Math.min(100, Number(agent.score) || 0));
        const tone = score >= 80 ? "safe" : score >= 55 ? "warning" : "danger";
        return `<button class="agent-card tone-${tone}" type="button" data-select="agent" data-id="${escapeHtml(agent.id)}">
          <header>
            <span class="agent-card-icon"><i data-lucide="${agent.level === "owner" ? "user-round-check" : agent.level === "trusted_agent" ? "wrench" : "bot"}"></i></span>
            <span class="agent-card-title"><strong>${escapeHtml(agent.label || agent.id)}</strong><code>${escapeHtml(agent.id)}</code></span>
            ${trustBadge(agent.level)}
          </header>
          <div class="agent-trust-score">
            <div><strong>${formatNumber(score)}</strong><span>/100</span></div>
            <b>${escapeHtml(trustSummary(score))}</b>
            <i><span style="--trust:${score}%"></span></i>
          </div>
          <div class="agent-scope"><span>${escapeHtml(agent.tenant || "default")}</span><i data-lucide="slash"></i><span>${escapeHtml(agent.namespace || "-")}</span></div>
          <ul class="agent-capabilities">
            ${agentCapability("可继续委托", agent.mayDelegate)}
            ${agentCapability("可授权敏感工具", agent.mayAuthorizeSensitiveTools)}
            ${agentCapability("可接收不可信数据", agent.mayReceiveUntrustedData, true)}
          </ul>
          <footer><span>最近活动</span><time>${latest ? escapeHtml(formatDateTime(latest.created_at)) : "未观测"}</time><i data-lucide="arrow-up-right"></i></footer>
        </button>`;
      }).join("") || emptyInline("没有匹配的智能体")}
    </section>

    <div class="workspace-grid-two agent-insight-grid">
      <section class="workspace-section activity-timeline-section">
        ${sectionHeader("workflow", "会话活动", `${runs.length} 个真实会话`)}
        <div class="activity-timeline">
          ${runs.slice(0, 8).map((run, index) => `<a class="activity-timeline-row" href="/?session=${encodeURIComponent(run.id)}">
            <span class="timeline-marker"><i></i>${index < Math.min(runs.length, 8) - 1 ? "<b></b>" : ""}</span>
            <time>${escapeHtml(formatDateTime(run.created_at))}</time>
            <div><strong>${escapeHtml(run.task || run.id)}</strong><small>${escapeHtml(run.id)} · ${escapeHtml(run.defense_mode || "full")}</small></div>
            <span class="event-count">${formatNumber(run.event_count)} 事件</span>
          </a>`).join("") || emptyInline("暂无会话活动")}
        </div>
      </section>
      <section class="workspace-section trust-chain-section">
        ${sectionHeader("network", "身份与信任关系", "当前授权拓扑")}
        <div class="trust-chain-map">
          ${owner ? `<button class="trust-chain-node root" type="button" data-select="agent" data-id="${escapeHtml(owner.id)}"><span><i data-lucide="user-round-check"></i></span><div><strong>${escapeHtml(owner.label || owner.id)}</strong><small>${formatNumber(owner.score)} · ${escapeHtml(trustSummary(owner.score))}</small></div></button>` : ""}
          ${owner && delegates.length ? `<div class="trust-chain-branches">${delegates.map((agent) => {
            const risky = agent.mayReceiveUntrustedData || Number(agent.score) < 60;
            return `<div class="trust-chain-branch tone-${risky ? "warning" : "safe"}">
              <span class="trust-chain-edge"><i></i><b>${agent.level === "delegated_agent" ? "任务委托" : "工具调用"}</b></span>
              <button class="trust-chain-node" type="button" data-select="agent" data-id="${escapeHtml(agent.id)}"><span><i data-lucide="${agent.level === "trusted_agent" ? "wrench" : "bot"}"></i></span><div><strong>${escapeHtml(agent.label || agent.id)}</strong><small>${escapeHtml(agentBoundary(agent))}</small></div>${toneBadge(trustSummary(agent.score), risky ? "warning" : "safe")}</button>
            </div>`;
          }).join("")}</div>` : emptyInline("暂无身份配置")}
        </div>
      </section>
    </div>`;
}

function renderPolicies() {
  const policy = state.data.policy || {};
  const toggles = policy.toggles || {};
  const lists = policy.lists || {};
  const agents = Array.isArray(policy.agents) ? policy.agents : [];
  const toggleByKey = new Map(POLICY_TOGGLES.map((item) => [item[0], item]));

  $("workspaceContent").innerHTML = `
    <form id="policyForm" class="policy-layout">
      <section class="workspace-section">
        ${sectionHeader("sliders-horizontal", "安全能力", `${Object.values(toggles).filter(Boolean).length}/${POLICY_TOGGLES.length} 已启用`)}
        <div class="policy-toggle-groups">
          ${POLICY_GROUPS.map((group) => `<section class="policy-toggle-group">
            <header><div><strong>${escapeHtml(group.label)}</strong><small>${escapeHtml(group.description)}</small></div><span>${group.toggles.filter((key) => toggles[key]).length}/${group.toggles.length}</span></header>
            <div class="policy-toggle-list">${group.toggles.map((key) => toggleByKey.get(key)).filter(Boolean).map(([toggleKey, icon, label, description]) => `<label class="policy-toggle">
              <i data-lucide="${icon}"></i>
              <span><strong>${label}</strong><small>${description}</small></span>
              <b class="policy-toggle-state">${toggles[toggleKey] ? "已启用" : "未启用"}</b>
              <span class="switch-control"><input type="checkbox" name="toggle-${toggleKey}" ${toggles[toggleKey] ? "checked" : ""} /><span></span></span>
            </label>`).join("")}</div>
          </section>`).join("")}
        </div>
      </section>

      <section class="workspace-section">
        ${sectionHeader("list-filter", "资源边界与白名单", "保存后作用于后续裁决")}
        <div class="policy-list-editors structured-boundaries">
          ${POLICY_LISTS.map(([key, label, kind, hint]) => policyRuleEditor(key, label, kind, hint, lists[key] || [])).join("")}
        </div>
      </section>
      <div class="policy-save-bar ${state.dirty ? "is-visible" : ""}" aria-hidden="${state.dirty ? "false" : "true"}">
        <span id="policySaveState">${state.dirty ? `${Math.max(1, state.policyChanges.size)} 项未保存修改` : `配置档案 ${escapeHtml(policy.profile || "default")}`}</span>
        <div><button class="workspace-secondary" type="button" data-action="reset-policy"><i data-lucide="rotate-ccw"></i>重置</button><button class="workspace-primary" type="submit"><i data-lucide="save"></i>保存策略</button></div>
      </div>
    </form>

    <section class="workspace-section">
      ${sectionHeader("users-round", "Agent 授权矩阵", `${agents.length} 个身份`)}
      <div class="workspace-table-wrap">
        <table class="workspace-table">
          <thead><tr><th style="width:220px">身份</th><th style="width:125px">等级</th><th style="width:90px">信任分</th><th style="width:120px">允许委托</th><th style="width:150px">敏感工具授权</th><th>不可信数据接收</th></tr></thead>
          <tbody>${agents.map((agent) => `<tr data-select="agent" data-id="${escapeHtml(agent.id)}"><td><div class="cell-main"><strong>${escapeHtml(agent.label || agent.id)}</strong><small>${escapeHtml(agent.id)}</small></div></td><td>${trustBadge(agent.level)}</td><td class="mono">${formatNumber(agent.score)}</td><td>${plainBoolean(agent.mayDelegate)}</td><td>${plainBoolean(agent.mayAuthorizeSensitiveTools)}</td><td>${plainBoolean(agent.mayReceiveUntrustedData)}</td></tr>`).join("") || tableEmpty(6, "暂无 Agent 授权配置")}</tbody>
        </table>
      </div>
    </section>`;
}

function renderTools() {
  const envelopes = Array.isArray(state.data.tools?.manifests) ? state.data.tools.manifests : [];
  const revocations = Array.isArray(state.data.tools?.revocations) ? state.data.tools.revocations : [];
  const search = state.filters.toolSearch.trim().toLowerCase();
  const trust = state.filters.toolTrust;
  const rows = envelopes.map((envelope) => ({ ...envelope, revoked: findRevocation(envelope.manifest?.toolId, revocations) }))
    .filter((envelope) => {
      const manifest = envelope.manifest || {};
      const matchesSearch = !search || JSON.stringify(envelope).toLowerCase().includes(search);
      const matchesTrust = trust === "all" || manifest.defaultTrust === trust || (trust === "revoked" && envelope.revoked);
      return matchesSearch && matchesTrust;
    });
  const signed = envelopes.filter((item) => Boolean(item.signature)).length;
  const exfiltration = envelopes.filter((item) => item.manifest?.canExfiltrate).length;

  $("workspaceContent").innerHTML = `
    <section class="workspace-section tool-registry-section">
      <div class="workspace-toolbar tool-toolbar">
        <label class="workspace-search"><i data-lucide="search"></i><input class="workspace-input" name="toolSearch" data-filter="toolSearch" value="${escapeHtml(state.filters.toolSearch)}" placeholder="搜索工具、别名、来源或副作用" aria-label="搜索工具" /></label>
        <select class="workspace-select" name="toolTrust" data-filter="toolTrust" aria-label="按信任等级筛选"><option value="all">全部信任等级</option>${["trusted", "workspace", "external", "unknown", "revoked"].map((value) => `<option value="${value}" ${trust === value ? "selected" : ""}>${trustLabel(value)}</option>`).join("")}</select>
        <span class="toolbar-spacer"></span>
        <div class="inline-stats" aria-label="工具摘要">
          <span><strong>${formatNumber(envelopes.length)}</strong> 工具</span>
          <span><strong>${formatNumber(signed)}</strong> 签名有效</span>
          <span class="${exfiltration ? "tone-danger" : ""}"><i data-lucide="triangle-alert"></i><strong>${formatNumber(exfiltration)}</strong> 可外泄</span>
          <span><strong>${formatNumber(revocations.length)}</strong> 已吊销</span>
        </div>
      </div>
      <div class="workspace-table-wrap">
        <table class="workspace-table tool-table">
          <thead><tr><th style="width:250px">工具</th><th style="width:120px">信任等级</th><th>能力</th><th style="width:120px">敏感数据</th><th style="width:120px">可外泄</th><th style="width:140px">状态</th></tr></thead>
          <tbody>${rows.map((envelope) => {
            const manifest = envelope.manifest || {};
            return `<tr data-select="tool" data-id="${escapeHtml(manifest.toolId)}">
              <td><div class="tool-identity"><span><i data-lucide="${toolIcon(manifest.toolId)}"></i></span><div><strong>${escapeHtml(manifest.toolId || "未命名")}</strong><small>${escapeHtml((manifest.aliases || []).join(" · ") || toolCategory(manifest.toolId))}</small></div></div></td>
              <td>${envelope.revoked ? statusBadge("已吊销", "revoked") : plainAttribute(trustLabel(manifest.defaultTrust))}</td>
              <td><div class="tool-capabilities">${(manifest.sideEffects || ["none"]).slice(0, 3).map((item) => `<code>${escapeHtml(item)}</code>`).join("")}<small>${escapeHtml((manifest.dataOrigins || []).join(" · ") || "未知来源")}</small></div></td>
              <td>${plainBoolean(manifest.acceptsSensitiveData)}</td>
              <td><span class="tool-risk-cell ${manifest.canExfiltrate ? "danger" : "safe"}">${manifest.canExfiltrate ? '<i data-lucide="triangle-alert"></i>' : '<i data-lucide="shield-check"></i>'}${plainBoolean(manifest.canExfiltrate, true)}</span></td>
              <td>${envelope.revoked ? statusBadge("已吊销", "revoked") : integrityStatus(Boolean(envelope.signature))}</td>
            </tr>`;
          }).join("") || tableEmpty(6, "没有匹配的工具")}</tbody>
        </table>
      </div>
    </section>`;
}

function renderAlerts() {
  const payload = state.data.alerts || {};
  const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
  const search = state.filters.alertSearch.trim().toLowerCase();
  const severity = state.filters.alertSeverity;
  const action = state.filters.alertAction;
  const filtered = alerts.filter((alert) => {
    const matchesSearch = !search || JSON.stringify(alert).toLowerCase().includes(search);
    const matchesSeverity = severity === "all" || String(alert.severity).toLowerCase() === severity;
    const matchesAction = action === "all" || String(alert.action).toLowerCase() === action;
    return matchesSearch && matchesSeverity && matchesAction;
  });
  const groups = aggregateAlerts(filtered);
  const criticalCount = alerts.filter((alert) => ["critical", "high"].includes(String(alert.severity).toLowerCase())).length;
  const blockedCount = alerts.filter((alert) => normalizeVerdict(alert.action) === "deny").length;
  const collapsedCount = Math.max(0, filtered.length - groups.length);

  $("workspaceContent").innerHTML = `
    <section class="workspace-section alert-center-section">
      <div class="workspace-toolbar alert-toolbar">
        <label class="workspace-search"><i data-lucide="search"></i><input class="workspace-input" name="alertSearch" data-filter="alertSearch" value="${escapeHtml(state.filters.alertSearch)}" placeholder="搜索攻击类型、工具、规则或原因" aria-label="搜索告警" /></label>
        <select class="workspace-select" name="alertSeverity" data-filter="alertSeverity" aria-label="按风险等级筛选"><option value="all">全部风险</option>${["critical", "high", "medium", "low", "info"].map((value) => `<option value="${value}" ${severity === value ? "selected" : ""}>${severityLabel(value)}</option>`).join("")}</select>
        <select class="workspace-select" name="alertAction" data-filter="alertAction" aria-label="按裁决筛选"><option value="all">全部裁决</option>${["block", "ask", "allow"].map((value) => `<option value="${value}" ${action === value ? "selected" : ""}>${decisionLabel(value)}</option>`).join("")}</select>
        <span class="toolbar-spacer"></span>
        <div class="inline-stats alert-inline-stats"><span><strong>${formatNumber(alerts.length)}</strong> 当前页</span><span class="tone-danger"><strong>${formatNumber(criticalCount)}</strong> 高危</span><span><strong>${formatNumber(blockedCount)}</strong> 已阻断</span>${collapsedCount ? `<span><strong>${formatNumber(collapsedCount)}</strong> 已聚合</span>` : ""}</div>
      </div>
      <div class="alert-feed investigation-queue">
        ${groups.map((group) => {
          const alert = group.alert;
          return `<button class="alert-row tone-${escapeHtml(toneFromSeverity(alert.severity))}" type="button" data-select="alert" data-id="${escapeHtml(alert.id)}">
          <span class="alert-severity"><strong>${escapeHtml(severityLabel(alert.severity))}</strong><small>${Number(alert.score) > 0 ? `${formatNumber(alert.score)} 分` : "已分析"}</small></span>
          <div class="alert-identity"><strong>${escapeHtml(alertTitle(alert))}${group.count > 1 ? ` <b>×${formatNumber(group.count)}</b>` : ""}</strong><small><code>${escapeHtml(alert.tool || "agent")}</code> · ${escapeHtml(sourceLabel(alert.source))} · ${escapeHtml(alert.id)}</small>${group.outcomeSummary ? `<em class="alert-aggregate-note">${escapeHtml(group.outcomeSummary)}</em>` : ""}</div>
          <div class="alert-story"><strong>${escapeHtml(alertNarrative(alert))}</strong><small>${escapeHtml(alertPathSummary(alert))}</small></div>
          <span class="alert-resolution">${decisionBadge(alert.action, alert.rule)}<small>${escapeHtml(alert.rule || "行为策略")}</small></span>
          <time>${escapeHtml(group.timeLabel)}</time>
          <i data-lucide="chevron-right"></i>
        </button>`;
        }).join("") || emptyInline("当前筛选条件下没有告警")}
      </div>
      <div class="workspace-pagination"><span>显示 ${formatNumber(payload.start)}-${formatNumber(payload.end)}，共 ${formatNumber(payload.totalAlerts)} 条 · 第 ${formatNumber(payload.page)} / ${formatNumber(payload.pages)} 页</span><button class="workspace-secondary" type="button" title="上一页" aria-label="上一页" data-action="alert-page" data-page="${Math.max(1, Number(payload.page || 1) - 1)}" ${Number(payload.page || 1) <= 1 ? "disabled" : ""}><i data-lucide="chevron-left"></i></button><button class="workspace-secondary" type="button" title="下一页" aria-label="下一页" data-action="alert-page" data-page="${Math.min(Number(payload.pages || 1), Number(payload.page || 1) + 1)}" ${Number(payload.page || 1) >= Number(payload.pages || 1) ? "disabled" : ""}><i data-lucide="chevron-right"></i></button></div>
    </section>`;
}

function renderAudit() {
  const records = recordList();
  const stats = state.data.stats || {};
  const search = state.filters.auditSearch.trim().toLowerCase();
  const type = state.filters.auditType;
  const severity = state.filters.auditSeverity;
  const tool = state.filters.auditTool;
  const verdict = state.filters.auditVerdict;
  const time = state.filters.auditTime;
  const types = [...new Set(records.map((record) => record.type).filter(Boolean))].sort();
  const tools = [...new Set(records.map(recordTool).filter(Boolean))].sort();
  const filtered = records.filter((record) => {
    const matchesSearch = !search || `${record.id} ${record.title} ${record.summary} ${JSON.stringify(record.payload || {})}`.toLowerCase().includes(search);
    const matchesType = type === "all" || record.type === type;
    const matchesSeverity = severity === "all" || toneFromSeverity(record.severity) === severity;
    const matchesTool = tool === "all" || recordTool(record) === tool;
    const matchesVerdict = verdict === "all" || normalizeVerdict(recordDecision(record)) === verdict;
    const matchesTime = recordInTimeWindow(record, time);
    return matchesSearch && matchesType && matchesSeverity && matchesTool && matchesVerdict && matchesTime;
  });
  const pages = Math.max(1, Math.ceil(filtered.length / state.auditPageSize));
  state.auditPage = Math.min(state.auditPage, pages);
  const start = (state.auditPage - 1) * state.auditPageSize;
  const pageRows = filtered.slice(start, start + state.auditPageSize);

  $("workspaceContent").innerHTML = `
    <section class="workspace-section audit-workbench-section">
      <div class="audit-summary-line">
        <span><strong>${formatNumber(stats.totalRecords ?? records.length)}</strong> records</span>
        <i></i><span><strong>${formatNumber(stats.sessions)}</strong> sessions</span>
        <i></i><span><strong>${formatNumber(stats.runs)}</strong> runs</span>
        <span class="toolbar-spacer"></span><small>${formatNumber(filtered.length)} 条匹配记录</small>
      </div>
      <div class="workspace-toolbar audit-toolbar">
        <label class="workspace-search"><i data-lucide="search"></i><input class="workspace-input" name="auditSearch" data-filter="auditSearch" value="${escapeHtml(state.filters.auditSearch)}" placeholder="搜索记录 ID、标题、工具、路径或规则" aria-label="搜索审计记录" /></label>
        <select class="workspace-select" name="auditTime" data-filter="auditTime" aria-label="按时间范围筛选"><option value="all" ${time === "all" ? "selected" : ""}>全部时间</option><option value="24h" ${time === "24h" ? "selected" : ""}>最近 24 小时</option><option value="7d" ${time === "7d" ? "selected" : ""}>最近 7 天</option></select>
        <select class="workspace-select" name="auditType" data-filter="auditType" aria-label="按记录类型筛选"><option value="all">全部类型</option>${types.map((value) => `<option value="${escapeHtml(value)}" ${type === value ? "selected" : ""}>${escapeHtml(typeLabel(value))}</option>`).join("")}</select>
        <select class="workspace-select" name="auditTool" data-filter="auditTool" aria-label="按工具筛选"><option value="all">全部工具</option>${tools.map((value) => `<option value="${escapeHtml(value)}" ${tool === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}</select>
        <select class="workspace-select" name="auditVerdict" data-filter="auditVerdict" aria-label="按裁决筛选"><option value="all">全部裁决</option>${["deny", "review", "allow", "observe"].map((value) => `<option value="${value}" ${verdict === value ? "selected" : ""}>${escapeHtml(verdictMeta(value).label)}</option>`).join("")}</select>
        <select class="workspace-select" name="auditSeverity" data-filter="auditSeverity" aria-label="按风险等级筛选"><option value="all">全部等级</option>${["danger", "warning", "info", "success"].map((value) => `<option value="${value}" ${severity === value ? "selected" : ""}>${severityLabel(value)}</option>`).join("")}</select>
        <button class="workspace-secondary save-query-button" type="button" data-action="save-audit-query"><i data-lucide="bookmark-plus"></i><span>保存查询</span></button>
      </div>
      ${state.savedAuditQuery ? `<div class="saved-query-strip"><span><i data-lucide="bookmark-check"></i>已保存查询</span><button type="button" data-action="load-audit-query">${escapeHtml(state.savedAuditQuery.label || "审计查询")}</button><button type="button" title="删除已保存查询" aria-label="删除已保存查询" data-action="clear-audit-query"><i data-lucide="x"></i></button></div>` : ""}
      <div class="workspace-table-wrap">
        <table class="workspace-table audit-table">
          <thead><tr><th style="width:160px">时间</th><th>事件</th><th style="width:210px">上下文</th><th style="width:135px">工具</th><th style="width:105px">裁决</th><th style="width:90px">等级</th></tr></thead>
          <tbody>${pageRows.map((record) => `<tr data-record-id="${escapeHtml(record.id)}">
            <td class="mono">${escapeHtml(formatDateTime(record.created_at))}</td>
            <td><div class="cell-main audit-event"><strong>${escapeHtml(record.title || record.summary || "未命名事件")}</strong><small>${escapeHtml(record.summary || "事实记录")}</small><code>${escapeHtml(record.id)}</code></div></td>
            <td><div class="cell-main audit-context"><strong>${escapeHtml(typeLabel(record.type))}</strong><small class="mono" title="${escapeHtml(record.session_key || record.run_id)}">${escapeHtml(record.session_key || record.run_id || "-")}</small></div></td>
            <td class="mono">${escapeHtml(recordTool(record) || "-")}</td><td>${decisionBadge(recordDecision(record))}</td><td>${toneBadge(severityLabel(record.severity), toneFromSeverity(record.severity))}</td>
          </tr>`).join("") || tableEmpty(6, "没有匹配的审计记录")}</tbody>
        </table>
      </div>
      <div class="workspace-pagination"><span>第 ${state.auditPage} / ${pages} 页</span><button class="workspace-secondary" type="button" title="上一页" aria-label="上一页" data-action="audit-page" data-page="${Math.max(1, state.auditPage - 1)}" ${state.auditPage <= 1 ? "disabled" : ""}><i data-lucide="chevron-left"></i></button><button class="workspace-secondary" type="button" title="下一页" aria-label="下一页" data-action="audit-page" data-page="${Math.min(pages, state.auditPage + 1)}" ${state.auditPage >= pages ? "disabled" : ""}><i data-lucide="chevron-right"></i></button></div>
    </section>`;
}

function renderSettings() {
  const health = state.data.health || {};
  const enforcement = state.data.enforcement || {};
  const checkpoints = state.data.checkpoints || {};
  const policy = state.data.policy || {};
  const monitor = health.system_monitor || {};
  const stack = Array.isArray(enforcement.securityStack) ? enforcement.securityStack : [];
  const modes = Array.isArray(enforcement.modes) ? enforcement.modes : [];
  const items = Array.isArray(checkpoints.checkpoints) ? checkpoints.checkpoints : [];
  const capabilities = Array.isArray(health.capabilities) ? health.capabilities : [];
  const capabilityGroups = groupCapabilities(capabilities);
  const activeMode = modes.find((mode) => mode.value === enforcement.mode);

  $("workspaceContent").innerHTML = `
    <section class="workspace-section settings-hero">
      <div class="settings-mode-panel">
        <span class="settings-kicker"><i data-lucide="shield-check"></i>当前安全模式</span>
        <div class="mode-segments">
          ${modes.map((mode) => `<label class="mode-option verdict-${escapeHtml(normalizeVerdict(mode.value))} ${mode.value === enforcement.mode ? "selected" : ""}"><input type="radio" name="runtime-mode" value="${escapeHtml(mode.value)}" ${mode.value === enforcement.mode ? "checked" : ""} /><strong>${escapeHtml(mode.label)}</strong></label>`).join("")}
        </div>
        <p><strong>${escapeHtml(activeMode?.label || decisionLabel(enforcement.mode))}：</strong>${escapeHtml(activeMode?.summary || "所有行为按当前安全策略执行。")}</p>
      </div>
      <div class="settings-status-rail">
        <div><span><i data-lucide="layers"></i>安全层</span><strong>${formatNumber(enforcement.enabledSecurityLayers)}<small>/${stack.length}</small></strong></div>
        <div><span><i data-lucide="activity"></i>执行前策略</span>${statusBadge(monitor.pre_exec_policy === "active" ? "ACTIVE" : "INACTIVE", monitor.pre_exec_policy === "active" ? "active" : "unsigned")}</div>
        <div><span><i data-lucide="history"></i>回滚检查点</span><strong>${formatNumber(items.length)}</strong></div>
      </div>
    </section>

    <section class="workspace-section security-stack-section">
      ${sectionHeader("layers", "安全栈", `${stack.filter((item) => item.enabled).length}/${stack.length} 已启用`)}
      <div class="stack-list">${stack.map((item) => `<div class="stack-row ${item.enabled ? "enabled" : "disabled"}"><span class="stack-state-icon"><i data-lucide="${item.enabled ? "check" : "circle"}"></i></span><div><strong>${escapeHtml(item.label)}</strong><span>${escapeHtml(item.key)}</span></div>${item.enabled ? statusBadge("已启用", "active") : toneBadge("未启用", "info")}</div>`).join("") || emptyInline("暂无安全栈状态")}</div>
    </section>

    <div class="workspace-grid-equal">
      <section class="workspace-section">
        ${sectionHeader("server-cog", "运行环境", health.ok ? "服务正常" : "服务异常")}
        <div class="settings-kv">
          ${kvRow("配置档案", enforcement.profile || policy.profile || "-")}
          ${kvRow("审批超时", `${formatNumber(enforcement.approvalTimeoutMs)} ms`)}
          ${pathKvRow("配置路径", enforcement.runtimeConfigPath || "-")}
          ${pathKvRow("审计路径", health.recordsPath || "-")}
          ${kvRow("隔离模式", monitor?.isolation?.mode || "-")}
          ${kvRow("eBPF", monitor.ebpf || "-")}
          ${kvRow("内核执行器", monitor?.observer?.kernel_enforcer_active ? "active" : "unavailable")}
        </div>
      </section>
      <section class="workspace-section capability-section">
        ${sectionHeader("badge-check", "运行能力", `${capabilities.length} 项 · 分类收起`)}
        <div class="capability-details"><div class="capability-category-list">${capabilityGroups.map((group) => `<details class="capability-category"><summary><span><i data-lucide="${capabilityGroupIcon(group.key)}"></i>${escapeHtml(group.label)}</span><b>${formatNumber(group.items.length)}</b><i data-lucide="chevron-down"></i></summary><div>${group.items.map((capability) => `<code>${escapeHtml(capability)}</code>`).join("")}</div></details>`).join("") || emptyInline("暂无能力声明")}</div></div>
      </section>
    </div>

    <section class="workspace-section">
      ${sectionHeader("history", "Checkpoint 回滚", checkpoints.enabled ? escapeHtml(checkpoints.path || "已启用") : "当前运行时未启用")}
      <div class="workspace-table-wrap">
        <table class="workspace-table">
          <thead><tr><th style="width:200px">操作键</th><th style="width:170px">创建时间</th><th>快照</th><th style="width:140px">状态</th><th style="width:110px">操作</th></tr></thead>
          <tbody>${items.map((item) => {
            const operationKey = item.operationKey || item.operation_key || item.key || "";
            const snapshots = item.snapshots || item.files || [];
            return `<tr><td class="mono">${escapeHtml(operationKey)}</td><td class="mono">${escapeHtml(formatDateTime(item.created_at || item.createdAt))}</td><td>${formatNumber(Array.isArray(snapshots) ? snapshots.length : item.snapshot_count)} 个文件快照</td><td>${statusBadge("可恢复", "active")}</td><td><button class="workspace-secondary" type="button" data-action="restore-checkpoint" data-operation-key="${escapeHtml(operationKey)}" ${!operationKey ? "disabled" : ""}><i data-lucide="rotate-ccw"></i>恢复</button></td></tr>`;
          }).join("") || tableEmpty(5, checkpoints.enabled ? "暂无回滚检查点" : "当前运行时未提供回滚管理器")}</tbody>
        </table>
      </div>
    </section>`;
}

function bindInteractions() {
  $("refreshBtn").addEventListener("click", () => void refreshData());
  $("modeSelect").addEventListener("change", (event) => void updateEnforcementMode(event.target.value));
  $("workspaceContent").addEventListener("click", handleContentClick);
  $("workspaceContent").addEventListener("input", handleContentInput);
  $("workspaceContent").addEventListener("change", handleContentChange);
  $("workspaceContent").addEventListener("keydown", handleContentKeydown);
  $("workspaceContent").addEventListener("submit", handleContentSubmit);
  $("workspaceActions").addEventListener("click", handleContentClick);
  $("drawerBody").addEventListener("click", handleContentClick);
  $("closeDrawerBtn").addEventListener("click", closeDrawer);
  $("drawerBackdrop").addEventListener("click", closeDrawer);
  $("closeDialogBtn").addEventListener("click", closeDialog);
  $("workspaceDialogForm").addEventListener("submit", handleDialogSubmit);
  $("workspaceDialog").addEventListener("cancel", (event) => { event.preventDefault(); closeDialog(); });
}

function handleContentInput(event) {
  const input = event.target.closest("[data-filter]");
  if (input) {
    state.filters[input.dataset.filter] = input.value;
    if (input.dataset.filter.startsWith("audit")) state.auditPage = 1;
    renderPage();
    focusFilter(input.dataset.filter, input.value.length);
    return;
  }
  if (event.target.closest("#policyForm")) {
    markPolicyDirty(event.target.name || "policy");
  }
}

function handleContentChange(event) {
  const input = event.target.closest("[data-filter]");
  if (input) {
    state.filters[input.dataset.filter] = input.value;
    if (input.dataset.filter.startsWith("audit")) state.auditPage = 1;
    renderPage();
    return;
  }
  const mode = event.target.closest('input[name="runtime-mode"]');
  if (mode) void updateEnforcementMode(mode.value);
  if (event.target.closest("#policyForm")) {
    markPolicyDirty(event.target.name || "policy");
    const toggle = event.target.closest('.policy-toggle input[type="checkbox"]');
    const label = toggle?.closest(".policy-toggle")?.querySelector(".policy-toggle-state");
    if (label) label.textContent = toggle.checked ? "已启用" : "未启用";
  }
}

function handleContentKeydown(event) {
  const input = event.target.closest("[data-policy-rule-input]");
  if (!input || event.key !== "Enter") return;
  event.preventDefault();
  addPolicyRule(input.closest("[data-policy-rule-key]"));
}

function handleContentSubmit(event) {
  if (event.target.id !== "policyForm") return;
  event.preventDefault();
  void savePolicy(event.target);
}

function handleContentClick(event) {
  const actionTarget = event.target.closest("[data-action]");
  if (actionTarget) {
    event.preventDefault();
    const action = actionTarget.dataset.action;
    if (action === "refresh") void refreshData();
    if (action === "save-policy") $("policyForm")?.requestSubmit();
    if (action === "reset-policy") {
      state.dirty = false;
      state.policyChanges.clear();
      renderPolicies();
      renderIcons();
    }
    if (action === "add-policy-rule") addPolicyRule(actionTarget.closest("[data-policy-rule-key]"));
    if (action === "remove-policy-rule") removePolicyRule(actionTarget.closest("[data-policy-rule-key]"), actionTarget.dataset.value);
    if (action === "register-tool") openRegisterToolDialog();
    if (action === "alert-page") {
      state.alertPage = Math.max(1, Number(actionTarget.dataset.page) || 1);
      void refreshData();
    }
    if (action === "audit-page") {
      state.auditPage = Math.max(1, Number(actionTarget.dataset.page) || 1);
      renderAudit();
      renderIcons();
    }
    if (action === "revoke-tool") openRevokeToolDialog(actionTarget.dataset.toolId);
    if (action === "restore-tool") openRestoreToolDialog(actionTarget.dataset.toolId);
    if (action === "restore-checkpoint") openCheckpointDialog(actionTarget.dataset.operationKey);
    if (action === "save-audit-query") saveAuditQuery();
    if (action === "load-audit-query") loadAuditQuery();
    if (action === "clear-audit-query") clearAuditQuery();
    if (action === "copy-value") void copyValue(actionTarget.dataset.value);
    return;
  }

  const recordRow = event.target.closest("[data-record-id]");
  if (recordRow?.dataset.recordId) {
    void openRecordDrawer(recordRow.dataset.recordId);
    return;
  }

  const selection = event.target.closest("[data-select]");
  if (!selection) return;
  const id = selection.dataset.id;
  if (selection.dataset.select === "agent") openAgentDrawer(id);
  if (selection.dataset.select === "tool") openToolDrawer(id);
  if (selection.dataset.select === "alert") void openAlertDrawer(id);
}

async function updateEnforcementMode(mode) {
  const previous = state.data.enforcement?.mode;
  $("modeSelect").disabled = true;
  try {
    const enforcement = await fetchJson("/api/settings/enforcement", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode }),
    });
    state.data.enforcement = enforcement;
    if (state.data.policy?.enforcement) state.data.policy.enforcement.mode = mode;
    renderHeaderData();
    if (state.page === "settings") renderSettings();
    showToast(`执行模式已切换为${decisionLabel(mode)}`, "success");
  } catch (error) {
    $("modeSelect").value = previous || "block";
    showToast(`模式切换失败：${error?.message || error}`, "error");
  } finally {
    $("modeSelect").disabled = false;
    renderIcons();
  }
}

function markPolicyDirty(key) {
  state.dirty = true;
  state.policyChanges.add(String(key || "policy"));
  const bar = document.querySelector(".policy-save-bar");
  bar?.classList.add("is-visible");
  bar?.setAttribute("aria-hidden", "false");
  const status = $("policySaveState");
  if (status) status.textContent = `${Math.max(1, state.policyChanges.size)} 项未保存修改`;
}

function readSavedAuditQuery() {
  try {
    const value = JSON.parse(window.localStorage.getItem(AUDIT_QUERY_STORAGE_KEY) || "null");
    return value && typeof value === "object" && value.filters ? value : null;
  } catch {
    return null;
  }
}

function saveAuditQuery() {
  const filters = Object.fromEntries(Object.entries(state.filters).filter(([key]) => key.startsWith("audit")));
  const active = Object.entries(filters).filter(([, value]) => value && value !== "all");
  const label = active.length ? `审计查询 · ${active.length} 个条件` : "全部审计记录";
  state.savedAuditQuery = { label, filters };
  try {
    window.localStorage.setItem(AUDIT_QUERY_STORAGE_KEY, JSON.stringify(state.savedAuditQuery));
  } catch {
    // The query remains available for the current page when storage is unavailable.
  }
  renderAudit();
  renderIcons();
  showToast("当前审计查询已保存", "success");
}

function loadAuditQuery() {
  if (!state.savedAuditQuery?.filters) return;
  for (const [key, value] of Object.entries(state.savedAuditQuery.filters)) {
    if (key in state.filters) state.filters[key] = value;
  }
  state.auditPage = 1;
  renderAudit();
  renderIcons();
}

function clearAuditQuery() {
  state.savedAuditQuery = null;
  try {
    window.localStorage.removeItem(AUDIT_QUERY_STORAGE_KEY);
  } catch {
    // Ignore storage failures; the in-memory query is already cleared.
  }
  renderAudit();
  renderIcons();
  showToast("已删除保存的查询");
}

async function copyValue(value) {
  const text = String(value || "");
  if (!text || text === "-") return;
  try {
    await navigator.clipboard.writeText(text);
    showToast("路径已复制", "success");
  } catch {
    showToast("浏览器未允许复制，请在详情中选取路径", "warning");
  }
}

function addPolicyRule(editor) {
  if (!editor) return;
  const input = editor.querySelector("[data-policy-rule-input]");
  const value = String(input?.value || "").trim();
  if (!value) return input?.focus();
  const values = policyRuleValues(editor);
  if (!values.includes(value)) values.push(value);
  syncPolicyRuleEditor(editor, values);
  input.value = "";
  input.focus();
}

function removePolicyRule(editor, value) {
  if (!editor) return;
  syncPolicyRuleEditor(editor, policyRuleValues(editor).filter((item) => item !== value));
}

function policyRuleValues(editor) {
  return splitLines(editor?.querySelector("textarea[name^=list]")?.value);
}

function syncPolicyRuleEditor(editor, values) {
  const normalized = Array.from(new Set(values.map((item) => String(item).trim()).filter(Boolean)));
  const textarea = editor.querySelector("textarea[name^=list]");
  if (textarea) textarea.value = normalized.join(String.fromCharCode(10));
  const list = editor.querySelector("[data-policy-rule-list]");
  if (list) list.innerHTML = normalized.length
    ? normalized.map((item) => policyRuleChip(item, editor.dataset.policyKind)).join("")
    : `<span class="policy-rule-empty">尚未设置边界</span>`;
  const count = editor.querySelector("[data-policy-rule-count]");
  if (count) count.textContent = `${normalized.length} 项`;
  markPolicyDirty(editor.dataset.policyRuleKey || "boundary");
  renderIcons();
}

async function savePolicy(form) {
  const submitters = form.querySelectorAll('button[type="submit"]');
  submitters.forEach((button) => { button.disabled = true; });
  const toggles = Object.fromEntries(POLICY_TOGGLES.map(([key]) => [key, Boolean(form.elements[`toggle-${key}`]?.checked)]));
  const lists = Object.fromEntries(POLICY_LISTS.map(([key]) => [key, splitLines(form.elements[`list-${key}`]?.value)]));
  try {
    const policy = await fetchJson("/api/policy/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ toggles, lists }),
    });
    state.data.policy = policy;
    state.dirty = false;
    state.policyChanges.clear();
    renderPolicies();
    renderIcons();
    showToast("策略配置已保存并开始作用于后续裁决", "success");
  } catch (error) {
    showToast(`策略保存失败：${error?.message || error}`, "error");
  } finally {
    submitters.forEach((button) => { button.disabled = false; });
  }
}

function openAgentDrawer(id) {
  const agent = (state.data.policy?.agents || []).find((item) => item.id === id);
  if (!agent) return;
  const latest = latestAgentRecord(agent, recordList());
  const trustVerdict = Number(agent.score) >= 80 ? "allow" : Number(agent.score) >= 55 ? "ask" : "deny";
  openDrawer("智能体身份", agent.label || agent.id, `
    <section class="drawer-section verdict-drawer-section"><header>信任结论</header>${verdictCard(trustVerdict, `${trustSummary(agent.score)}，信任评分 ${formatNumber(agent.score)}/100`, "IDENTITY_TRUST_BOUNDARY")}</section>
    <section class="drawer-section"><header>身份属性</header><div class="drawer-kv">
      ${kvRow("Agent ID", agent.id)}${kvRow("信任等级", trustLabel(agent.level))}${kvRow("租户", agent.tenant || "-")}${kvRow("命名空间", agent.namespace || "-")}${kvRow("最近活动", latest ? formatDateTime(latest.created_at) : "未观测")}
    </div></section>
    <section class="drawer-section"><header>调用与数据边界</header><div class="drawer-kv">${kvRow("谁能调用它", agent.level === "owner" ? "用户会话 / 系统入口" : "主 Agent 委托")}${kvRow("它能调用谁", agent.mayDelegate ? "可继续委托受信 Agent" : "不可继续委托")}${kvRow("敏感工具", agent.mayAuthorizeSensitiveTools ? "可在 TaskSpec 内授权" : "不可授权")}${kvRow("可接触数据", agent.mayReceiveUntrustedData ? "可接收不可信数据" : "仅可信或任务内数据")}</div></section>
  `);
}

function openToolDrawer(id) {
  const envelope = (state.data.tools?.manifests || []).find((item) => item.manifest?.toolId === id);
  if (!envelope) return;
  const manifest = envelope.manifest || {};
  const revocation = findRevocation(id, state.data.tools?.revocations || []);
  const boundaryVerdict = revocation ? "deny" : manifest.canExfiltrate || manifest.defaultTrust === "unknown" ? "ask" : "allow";
  const boundaryReason = revocation
    ? `工具已吊销：${revocation.reason || "未记录原因"}`
    : manifest.canExfiltrate ? "工具具备外发能力，调用时必须满足 TaskSpec 与目标边界" : "工具清单完整，当前按既定授权边界运行";
  openDrawer("工具安全清单", id, `
    <section class="drawer-section verdict-drawer-section"><header>工具边界裁决</header>${verdictCard(boundaryVerdict, boundaryReason, revocation ? "TOOL_TRUST_REVOKED" : manifest.canExfiltrate ? "EXTERNAL_SIDE_EFFECT_BOUNDARY" : "TOOL_MANIFEST_VERIFIED")}</section>
    <section class="drawer-section"><header>安全属性</header><div class="drawer-kv">${kvRow("信任等级", trustLabel(manifest.defaultTrust))}${kvRow("数据来源", (manifest.dataOrigins || []).join(", ") || "-")}${kvRow("副作用", (manifest.sideEffects || []).join(", ") || "-")}${kvRow("接收敏感数据", yesNo(manifest.acceptsSensitiveData))}${kvRow("可外泄", yesNo(manifest.canExfiltrate))}${kvRow("要求显式授权", yesNo(manifest.requiresExplicitAuthorization))}</div></section>
    <section class="drawer-section"><header>完整性</header><div class="drawer-kv">${kvRow("Digest", envelope.digest || "-")}${kvRow("签名", envelope.signature ? "有效" : "未签名")}${kvRow("登记时间", formatDateTime(envelope.registeredAt))}${kvRow("别名", (manifest.aliases || []).join(", ") || "无")}</div></section>
    <div class="workspace-actions">${revocation ? `<button class="workspace-primary" type="button" data-action="restore-tool" data-tool-id="${escapeHtml(id)}"><i data-lucide="rotate-ccw"></i>恢复信任</button>` : `<button class="workspace-danger" type="button" data-action="revoke-tool" data-tool-id="${escapeHtml(id)}"><i data-lucide="shield-off"></i>吊销工具</button>`}</div>
  `);
}

async function openAlertDrawer(id) {
  const alert = (state.data.alerts?.alerts || []).find((item) => item.id === id) || (state.data.overview?.alerts || []).find((item) => item.id === id);
  if (!alert) return;
  openDrawer("安全告警", alert.type || "运行风险事件", `
    <section class="drawer-section verdict-drawer-section"><header>调查结论</header>${verdictCard(alert.action, alertNarrative(alert), alert.rule || "SECURITY_EVENT_REVIEW")}</section>
    <section class="drawer-section"><header>行为链</header><div class="drawer-path">${alertPathItems(alert).map((item, index) => `${index ? `<i data-lucide="arrow-down"></i>` : ""}<span>${escapeHtml(item)}</span>`).join("")}</div></section>
    <section class="drawer-section"><header>关键证据</header><div class="drawer-kv">${kvRow("风险等级", alert.severity || "-")}${kvRow("工具", alert.tool || "-")}${kvRow("裁决", decisionLabel(alert.action))}${kvRow("规则", alert.rule || "-")}${kvRow("来源", sourceLabel(alert.source))}${kvRow("时间", alert.time || "-")}</div></section>
    <section class="drawer-section"><header>原始审计</header><p class="drawer-copy" id="alertRecordState">正在读取关联记录...</p></section>
  `);
  try {
    const payload = await fetchJson(`/api/records/${encodeURIComponent(id)}`);
    const record = payload.record;
    const stateNode = $("alertRecordState");
    if (stateNode && record) {
      stateNode.outerHTML = `<div class="drawer-kv">${kvRow("记录 ID", record.id)}${kvRow("会话", record.session_key || record.run_id || "-")}${kvRow("事件类型", typeLabel(record.type))}${kvRow("创建时间", formatDateTime(record.created_at))}</div><div class="workspace-actions" style="padding:10px"><a class="workspace-primary" href="/?session=${encodeURIComponent(record.session_key || record.run_id || "")}"><i data-lucide="waypoints"></i>打开攻击监控</a></div>`;
      renderIcons();
    }
  } catch {
    const stateNode = $("alertRecordState");
    if (stateNode) stateNode.textContent = "该告警当前没有可读取的关联记录。";
  }
}

async function openRecordDrawer(id) {
  openDrawer("审计记录", id, '<div class="workspace-loading"><span></span><strong>正在读取完整记录</strong></div>');
  try {
    const payload = await fetchJson(`/api/records/${encodeURIComponent(id)}`);
    const record = payload.record;
    $("drawerTitle").textContent = brandText(record.title || record.summary || record.id);
    $("drawerBody").innerHTML = `
      <section class="drawer-section"><header>发生了什么</header><p class="drawer-copy">${escapeHtml(record.summary || record.title || "未记录事件摘要")}</p></section>
      <section class="drawer-section audit-chain-drawer"><header>完整审计链</header><div class="audit-trace-chain">${auditTraceSteps(record).map((step, index) => `<div><span><i data-lucide="${step.icon}"></i></span><small>${escapeHtml(step.label)}</small><strong>${escapeHtml(step.value)}</strong>${index < 4 ? '<i data-lucide="arrow-right"></i>' : ""}</div>`).join("")}</div></section>
      <section class="drawer-section"><header>审计属性</header><div class="drawer-kv">${kvRow("记录 ID", record.id)}${kvRow("创建时间", formatDateTime(record.created_at))}${kvRow("会话", record.session_key || record.run_id || "-")}${kvRow("类型", typeLabel(record.type))}${kvRow("安全层", record.layer || "-")}${kvRow("等级", severityLabel(record.severity))}${kvRow("工具", recordTool(record) || "-")}${kvRow("裁决", decisionLabel(recordDecision(record)))}</div></section>
      <details class="drawer-section"><summary>技术详情 / 原始 Trace</summary><code class="drawer-code">${escapeHtml(JSON.stringify(record.payload || {}, null, 2))}</code></details>
      ${record.session_key || record.run_id ? `<div class="workspace-actions"><a class="workspace-primary" href="/?session=${encodeURIComponent(record.session_key || record.run_id)}"><i data-lucide="waypoints"></i>查看会话因果图</a></div>` : ""}
    `;
    renderIcons();
  } catch (error) {
    $("drawerBody").innerHTML = `<div class="workspace-error"><i data-lucide="triangle-alert"></i><strong>${escapeHtml(error?.message || error)}</strong></div>`;
    renderIcons();
  }
}

function openRegisterToolDialog() {
  openDialog({
    kicker: "工具登记",
    title: "登记工具安全清单",
    confirmLabel: "签名并登记",
    body: `<div class="form-grid">
      <label class="field-group"><span>Tool ID</span><input class="workspace-input" name="toolId" required placeholder="example_tool" /></label>
      <label class="field-group"><span>默认信任</span><select class="workspace-select" name="defaultTrust"><option value="workspace">工作区</option><option value="trusted">可信</option><option value="external">外部</option><option value="unknown">未知</option></select></label>
      <label class="field-group full"><span>别名</span><input class="workspace-input" name="aliases" placeholder="alias_one, alias_two" /></label>
      <label class="field-group"><span>数据来源</span><input class="workspace-input" name="dataOrigins" required value="workspace" /></label>
      <label class="field-group"><span>副作用</span><input class="workspace-input" name="sideEffects" required value="none" /></label>
      <label class="field-group"><span>版本</span><input class="workspace-input" name="version" placeholder="1.0.0" /></label>
      <label class="field-group"><span>端点</span><input class="workspace-input" name="endpoint" placeholder="local://tool" /></label>
      <div class="boolean-grid">
        <label class="boolean-option"><input type="checkbox" name="acceptsSensitiveData" />接收敏感数据</label>
        <label class="boolean-option"><input type="checkbox" name="canExfiltrate" />可向外发送</label>
        <label class="boolean-option"><input type="checkbox" name="requiresExplicitAuthorization" checked />要求显式授权</label>
      </div>
    </div>`,
    onConfirm: async (form) => {
      const values = new FormData(form);
      await fetchJson("/api/tools/manifests/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          manifest: {
            toolId: String(values.get("toolId") || "").trim(),
            aliases: splitLines(values.get("aliases")),
            dataOrigins: splitLines(values.get("dataOrigins")),
            sideEffects: splitLines(values.get("sideEffects")),
            acceptsSensitiveData: values.has("acceptsSensitiveData"),
            canExfiltrate: values.has("canExfiltrate"),
            requiresExplicitAuthorization: values.has("requiresExplicitAuthorization"),
            defaultTrust: values.get("defaultTrust"),
          },
          metadata: { version: values.get("version"), endpoint: values.get("endpoint") },
        }),
      });
      showToast("工具安全清单已签名登记", "success");
      await refreshData({ quiet: true });
    },
  });
}

function openRevokeToolDialog(toolId) {
  if (!toolId) return;
  openDialog({
    kicker: "信任吊销",
    title: `吊销 ${toolId}`,
    confirmLabel: "确认吊销",
    danger: true,
    body: `<p class="drawer-copy">吊销后，该工具的后续调用会在执行前被阻断。</p><label class="field-group"><span>吊销原因</span><textarea class="workspace-textarea" name="reason" required placeholder="记录风险依据与处置原因"></textarea></label>`,
    onConfirm: async (form) => {
      const reason = new FormData(form).get("reason");
      await fetchJson("/api/tools/manifests/revoke", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ toolId, reason }) });
      closeDrawer();
      showToast(`${toolId} 已吊销`, "success");
      await refreshData({ quiet: true });
    },
  });
}

function openRestoreToolDialog(toolId) {
  if (!toolId) return;
  openDialog({
    kicker: "恢复信任",
    title: `恢复 ${toolId}`,
    confirmLabel: "恢复信任",
    body: '<p class="drawer-copy">恢复后，工具会重新按其安全清单与当前策略接受执行前裁决。</p>',
    onConfirm: async () => {
      await fetchJson("/api/tools/manifests/restore", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ toolId }) });
      closeDrawer();
      showToast(`${toolId} 已恢复`, "success");
      await refreshData({ quiet: true });
    },
  });
}

function openCheckpointDialog(operationKey) {
  if (!operationKey) return;
  openDialog({
    kicker: "检查点恢复",
    title: "恢复操作检查点",
    confirmLabel: "确认恢复",
    danger: true,
    body: `<p class="drawer-copy">玄鉴将恢复操作 <code class="mono">${escapeHtml(operationKey)}</code> 对应的文件快照。当前工作区内容可能被覆盖。</p>`,
    onConfirm: async () => {
      const result = await fetchJson("/api/checkpoints/restore", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ operationKey }) });
      showToast(`已恢复 ${formatNumber(result.restored?.length)} 个快照`, result.errors?.length ? "warning" : "success");
      await refreshData({ quiet: true });
    },
  });
}

function openDialog({ kicker, title, body, confirmLabel, danger = false, onConfirm }) {
  $("dialogKicker").textContent = kicker;
  $("dialogTitle").textContent = title;
  $("dialogBody").innerHTML = body;
  $("dialogActions").innerHTML = `<button class="workspace-secondary" type="button" data-dialog-cancel>取消</button><button class="${danger ? "workspace-danger" : "workspace-primary"}" type="submit">${escapeHtml(confirmLabel)}</button>`;
  state.dialogConfirm = onConfirm;
  const dialog = $("workspaceDialog");
  if (!dialog.open) dialog.showModal();
  $("dialogActions").querySelector("[data-dialog-cancel]").addEventListener("click", closeDialog);
  renderIcons();
  window.setTimeout(() => $("dialogBody").querySelector("input, textarea, select")?.focus(), 0);
}

async function handleDialogSubmit(event) {
  event.preventDefault();
  if (typeof state.dialogConfirm !== "function") return closeDialog();
  const submit = event.target.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    await state.dialogConfirm(event.target);
    closeDialog();
  } catch (error) {
    showToast(`操作失败：${error?.message || error}`, "error");
  } finally {
    submit.disabled = false;
  }
}

function closeDialog() {
  const dialog = $("workspaceDialog");
  if (dialog.open) dialog.close();
  state.dialogConfirm = null;
}

function openDrawer(kicker, title, body) {
  $("drawerKicker").textContent = kicker;
  $("drawerTitle").textContent = brandText(title);
  $("drawerBody").innerHTML = body;
  $("workspaceDrawer").classList.add("open");
  $("workspaceDrawer").setAttribute("aria-hidden", "false");
  $("drawerBackdrop").hidden = false;
  renderIcons();
  $("closeDrawerBtn").focus();
}

function closeDrawer() {
  $("workspaceDrawer").classList.remove("open");
  $("workspaceDrawer").setAttribute("aria-hidden", "true");
  $("drawerBackdrop").hidden = true;
}

function renderLoading() {
  $("workspaceContent").innerHTML = '<div class="workspace-loading"><span></span><strong>正在同步安全数据</strong></div>';
}

function renderError(error) {
  $("workspaceContent").innerHTML = `<div class="workspace-error"><i data-lucide="triangle-alert"></i><strong>数据同步失败</strong><span>${escapeHtml(error?.message || error)}</span><button class="workspace-secondary" type="button" data-action="refresh"><i data-lucide="refresh-cw"></i>重试</button></div>`;
  renderIcons();
}

function setConnection(kind, label) {
  const target = $("connectionStatus");
  target.className = `connection-state ${kind}`;
  target.querySelector("span:last-child").textContent = label;
}

function showToast(message, tone = "info") {
  const toast = $("toast");
  toast.textContent = brandText(message);
  toast.className = `toast show ${tone}`;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { toast.className = "toast"; }, 3200);
}

function focusFilter(name, position) {
  window.requestAnimationFrame(() => {
    const input = document.querySelector(`[data-filter="${name}"]`);
    if (!input) return;
    input.focus();
    if (typeof input.setSelectionRange === "function") input.setSelectionRange(position, position);
  });
}

function findRecordForOperation(operation) {
  return recordList().find((record) => {
    const sameTool = !operation.tool || recordTool(record) === operation.tool;
    const sameReason = !operation.reason || record.summary === operation.reason || record.title === operation.reason || record.payload?.reason === operation.reason;
    return sameTool && sameReason;
  }) || null;
}

function latestAgentRecord(agent, records) {
  const direct = records.find((record) => {
    const text = `${record.run_id || ""} ${record.session_key || ""} ${JSON.stringify(record.payload || {})}`;
    return text.includes(agent.id);
  });
  return direct || (agent.level === "owner" ? records[0] : null);
}

function findRevocation(toolId, revocations) {
  return revocations.find((item) => (item.toolId || item.tool_id) === toolId) || null;
}

function recordList() {
  return Array.isArray(state.data.records?.records) ? state.data.records.records : [];
}

function sectionHeader(icon, title, meta) {
  return `<header><div><i data-lucide="${icon}"></i><h3>${escapeHtml(title)}</h3></div><small>${escapeHtml(meta || "")}</small></header>`;
}

function summaryStat(label, value) {
  return `<div class="summary-stat"><small>${escapeHtml(label)}</small><strong>${escapeHtml(String(value ?? 0))}</strong></div>`;
}

function riskContributions(risks, score) {
  const gap = Math.max(0, 100 - (Number(score) || 0));
  const weighted = risks.map((item) => {
    const containment = Math.max(0, Math.min(100, Number(item?.[1]) || 0));
    const events = Math.max(1, Number(item?.[2]) || 0);
    return { label: String(item?.[0] || "未分类风险"), weight: Math.max(1, 100 - containment) * events };
  });
  const totalWeight = weighted.reduce((sum, item) => sum + item.weight, 0) || 1;
  return weighted.map((item) => ({ ...item, points: Math.max(gap ? 1 : 0, Math.round(gap * item.weight / totalWeight)) }));
}

function completeRiskDimensions(risks, metricByKey, totalRecords) {
  const dimensions = [...risks];
  const total = Math.max(1, Number(totalRecords) || 0);
  const fallbacks = [
    ["数据外泄", "taint"],
    ["意图风险", "drift"],
    ["身份风险", "pending"],
  ];
  for (const [label, key] of fallbacks) {
    if (dimensions.length >= 3) break;
    if (dimensions.some((item) => String(item?.[0]).includes(label))) continue;
    const count = Math.max(0, Number(metricByKey.get(key)?.num) || 0);
    const exposure = Math.min(100, Math.round(count / total * 100));
    dimensions.push([label, 100 - exposure, count]);
  }
  return dimensions.slice(0, 3);
}

function metricIcon(key) {
  return ({ total: "logs", tools: "wrench", taint: "git-branch", drift: "route" })[String(key)] || "activity";
}

function agentCapability(label, enabled, warningWhenEnabled = false) {
  const tone = warningWhenEnabled ? (enabled ? "warning" : "safe") : (enabled ? "safe" : "restricted");
  const icon = warningWhenEnabled ? (enabled ? "triangle-alert" : "shield-check") : (enabled ? "check" : "x");
  return `<li class="tone-${tone}"><i data-lucide="${icon}"></i><span>${escapeHtml(label)}</span><b>${enabled ? "是" : "否"}</b></li>`;
}

function toolIcon(toolId) {
  const text = String(toolId || "").toLowerCase();
  if (/mail|email/.test(text)) return "mail";
  if (/file|read|write/.test(text)) return "file-text";
  if (/shell|exec|command|terminal/.test(text)) return "square-terminal";
  if (/web|http|api|network/.test(text)) return "globe-2";
  if (/database|sql|store|memory/.test(text)) return "database";
  return "wrench";
}

function toolCategory(toolId) {
  const icon = toolIcon(toolId);
  return ({ mail: "Email 工具", "file-text": "文件工具", "square-terminal": "Shell 工具", "globe-2": "网络 / API", database: "数据工具", wrench: "通用工具" })[icon];
}

function aggregateAlerts(alerts) {
  const groups = new Map();
  for (const alert of alerts) {
    const key = [alertTitle(alert), alert.tool, normalizeVerdict(alert.action), alert.rule, alertPathSummary(alert)].map((item) => String(item || "")).join("|");
    const group = groups.get(key) || { alert, count: 0, times: [], decisions: [] };
    group.count += 1;
    if (alert.time) group.times.push(String(alert.time));
    group.decisions.push(normalizeVerdict(alert.action));
    groups.set(key, group);
  }
  return [...groups.values()].map((group) => ({
    ...group,
    timeLabel: group.times.length > 1 ? `${group.times.at(-1)} – ${group.times[0]}` : group.times[0] || "--:--:--",
    outcomeSummary: group.count > 1 ? `${formatNumber(group.count)} 次均${aggregateOutcomeLabel(group.decisions[0])}` : "",
  }));
}

function aggregateOutcomeLabel(value) {
  const labels = { deny: "已阻断", review: "待确认", allow: "已放行", observe: "已记录" };
  return labels[normalizeVerdict(value)] || "已记录";
}

function recordInTimeWindow(record, windowKey) {
  if (!windowKey || windowKey === "all") return true;
  const createdAt = new Date(record.created_at).getTime();
  if (!Number.isFinite(createdAt)) return false;
  const duration = windowKey === "24h" ? 24 * 60 * 60 * 1000 : windowKey === "7d" ? 7 * 24 * 60 * 60 * 1000 : Infinity;
  return Date.now() - createdAt <= duration;
}

function auditTraceSteps(record) {
  const payload = record?.payload || {};
  const input = payload.raw_input || payload.command || (payload.task_spec ? "TaskSpec 已解析" : record.summary || "已接收行为输入");
  const policy = payload.rule || payload.violations?.[0] || record.layer || "默认行为策略";
  const output = payload.blocked === true
    ? "执行前阻断"
    : payload.ok === true ? "执行成功" : payload.result || payload.status || typeLabel(record.type);
  return [
    { label: "Input", value: compactValue(input), icon: "message-square-text" },
    { label: "Tool", value: recordTool(record) || "Agent", icon: "wrench" },
    { label: "Policy", value: compactValue(policy), icon: "shield-check" },
    { label: "Decision", value: decisionLabel(recordDecision(record)), icon: verdictMeta(recordDecision(record)).icon },
    { label: "Output", value: compactValue(output), icon: "square-check-big" },
  ];
}

function compactValue(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return String(text || "-").replace(/\s+/g, " ").slice(0, 64);
}

function verdictSummaryStat(label, value) {
  const meta = verdictMeta(value);
  return `<div class="summary-stat verdict-summary verdict-${meta.key}"><small>${escapeHtml(label)}</small><strong>${escapeHtml(meta.label)}</strong><code>${escapeHtml(meta.code)}</code></div>`;
}

function verdictCard(value, summary, rule) {
  const meta = verdictMeta(value);
  return `<div class="verdict-card verdict-${meta.key}">
    <span class="verdict-icon"><i data-lucide="${escapeHtml(meta.icon)}"></i></span>
    <span class="verdict-copy"><small>玄鉴裁决</small><strong>${escapeHtml(meta.label)}</strong><code>${escapeHtml(meta.code)}</code><p>${escapeHtml(summary || meta.summary)}</p>${rule ? `<b>${escapeHtml(rule)}</b>` : ""}</span>
  </div>`;
}

function policyRuleEditor(key, label, kind, hint, rawValues) {
  const values = Array.from(new Set((Array.isArray(rawValues) ? rawValues : []).map(String).filter(Boolean)));
  return `<section class="policy-rule-editor" data-policy-rule-key="${escapeHtml(key)}" data-policy-kind="${escapeHtml(kind)}">
    <header><span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(hint)}</small></span><b data-policy-rule-count>${values.length} 项</b></header>
    <div class="policy-rule-list" data-policy-rule-list>${values.length ? values.map((item) => policyRuleChip(item, kind)).join("") : `<span class="policy-rule-empty">尚未设置边界</span>`}</div>
    <div class="policy-rule-add"><input class="workspace-input" data-policy-rule-input placeholder="${escapeHtml(hint)}" aria-label="${escapeHtml(`添加${label}`)}" /><button class="workspace-secondary" type="button" data-action="add-policy-rule"><i data-lucide="plus"></i><span>添加边界</span></button></div>
    <textarea name="list-${escapeHtml(key)}" hidden aria-hidden="true">${escapeHtml(values.join(String.fromCharCode(10)))}</textarea>
  </section>`;
}

function policyRuleChip(value, kind) {
  return `<span class="policy-rule-chip"><span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(kind || "边界")}</small></span><button type="button" data-action="remove-policy-rule" data-value="${escapeHtml(value)}" title="删除 ${escapeHtml(value)}" aria-label="删除 ${escapeHtml(value)}"><i data-lucide="x"></i></button></span>`;
}

function agentBoundaryItems(agent) {
  const items = [];
  items.push(agent.mayDelegate ? "可继续委托" : "不可继续委托");
  items.push(agent.mayAuthorizeSensitiveTools ? "可授权敏感工具" : "敏感工具受限");
  items.push(agent.mayReceiveUntrustedData ? "可接收不可信数据" : "拒绝不可信数据");
  return items;
}

function integrityStatus(valid) {
  return valid
    ? `<span class="integrity-status valid"><i data-lucide="badge-check"></i>有效</span>`
    : `<span class="integrity-status invalid"><i data-lucide="badge-alert"></i>签名异常</span>`;
}

function alertTitle(alert) {
  const text = `${alert?.type || ""} ${alert?.reason || ""} ${alert?.rule || ""}`;
  if (/prompt.?injection|taint|污染|注入/i.test(text)) return "检测到上下文污染传播";
  if (/send_email|recipient|email|外发|收件人/i.test(text)) return "外部邮件行为触发边界检查";
  if (/read_file|file read|文件读取/i.test(text)) return "文件读取触发风险检查";
  if (/shell|command|命令/i.test(text)) return "命令执行触发安全检查";
  return String(alert?.type || "运行行为触发风险检查");
}

function alertNarrative(alert) {
  const text = brandText(alert?.reason || "未记录告警原因")
    .replace(/read_file is explicitly authorized by the current TaskSpec/gi, "读取行为符合当前 TaskSpec")
    .replace(/recipient is outside the current TaskSpec target scope/gi, "外部收件人超出当前任务授权范围")
    .replace(/tool arguments carry secret-tainted data/gi, "敏感数据正在尝试流向外部目标")
    .replace(/returned a safe downgraded response/gi, "已返回安全降级响应");
  return text || "该行为已进入玄鉴调查队列";
}

function alertPathItems(alert) {
  const graph = alert?.causal_graph || alert?.causalGraph;
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const nodeById = new Map(nodes.map((node) => [String(node.id), node]));
  const pathIds = Array.isArray(graph?.path_node_ids) ? graph.path_node_ids : Array.isArray(graph?.pathNodeIds) ? graph.pathNodeIds : [];
  const path = pathIds.map((id) => nodeById.get(String(id))).filter(Boolean).map((node) => String(node.tool || node.sink || node.path || node.label || node.kind || "行为"));
  if (path.length) return path.slice(0, 7);
  return [String(alert?.tool || "Agent 行为"), verdictLabel(alert?.action)];
}

function alertPathSummary(alert) {
  return alertPathItems(alert).slice(0, 4).join(" → ");
}

function groupCapabilities(capabilities) {
  const groups = [
    { key: "security", label: "安全能力", match: /security|policy|guard|taint|provenance|preflight|isolation|kernel/i, items: [] },
    { key: "audit", label: "审计能力", match: /record|audit|export|metric|checkpoint|restore/i, items: [] },
    { key: "agent", label: "Agent 能力", match: /agent|tool|session|memory|message/i, items: [] },
    { key: "lab", label: "实验与集成", match: /.*/, items: [] },
  ];
  for (const capability of capabilities.map(String)) {
    (groups.find((group) => group.match.test(capability)) || groups.at(-1)).items.push(capability);
  }
  return groups.filter((group) => group.items.length);
}

function capabilityGroupIcon(key) {
  return ({ security: "shield-check", audit: "notebook-tabs", agent: "bot", lab: "flask-conical" })[String(key)] || "boxes";
}

function attentionRow(label, value, detail, tone, href) {
  return `<a class="attention-row tone-${escapeHtml(tone)}" href="${escapeHtml(href)}">
    <strong>${formatNumber(value)}</strong>
    <span><b>${escapeHtml(label)}</b><small>${escapeHtml(detail)}</small></span>
    <em>处理</em>
    <i data-lucide="chevron-right"></i>
  </a>`;
}

function kvRow(label, value) {
  return `<div class="drawer-kv-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value ?? "-"))}</strong></div>`;
}

function pathKvRow(label, value) {
  const fullValue = String(value ?? "-");
  const filename = fullValue.split(/[\\/]/).filter(Boolean).at(-1) || fullValue;
  return `<div class="drawer-kv-row path-kv-row"><span>${escapeHtml(label)}</span><code title="${escapeHtml(fullValue)}">${escapeHtml(filename)}</code><button type="button" title="复制完整路径" aria-label="复制${escapeHtml(label)}" data-action="copy-value" data-value="${escapeHtml(fullValue)}"><i data-lucide="copy"></i></button></div>`;
}

function tableEmpty(columns, label) {
  return `<tr><td colspan="${columns}"><div class="workspace-empty" style="min-height:150px"><span>${escapeHtml(label)}</span></div></td></tr>`;
}

function emptyInline(label) {
  return `<div class="workspace-empty" style="min-height:120px"><span>${escapeHtml(label)}</span></div>`;
}

function toneBadge(label, tone = "info") {
  return `<span class="tone-badge tone-${tone}">${escapeHtml(String(label || "-"))}</span>`;
}

function trustBadge(value) {
  const key = String(value || "unknown").toLowerCase();
  return `<span class="trust-badge ${escapeHtml(key)}">${escapeHtml(trustLabel(key))}</span>`;
}

function statusBadge(label, status) {
  return `<span class="status-badge ${escapeHtml(status)}">${escapeHtml(label)}</span>`;
}

function decisionBadge(value, detail = "") {
  const meta = verdictMeta(value);
  return `<span class="verdict-badge verdict-${escapeHtml(meta.key)}" ${detail ? `title="${escapeHtml(detail)}"` : ""}><strong>${escapeHtml(meta.label)}</strong><code>${escapeHtml(meta.code)}</code></span>`;
}

function plainAttribute(value, tone = "neutral") {
  return `<span class="plain-attribute tone-${escapeHtml(tone)}">${escapeHtml(String(value ?? "-"))}</span>`;
}

function plainBoolean(value, dangerWhenTrue = false) {
  return plainAttribute(value ? "是" : "否", value && dangerWhenTrue ? "danger" : "neutral");
}

function protectionStatus(value) {
  const score = Number(value) || 0;
  if (score >= 80) return { label: "风险可控", tone: "safe" };
  if (score >= 60) return { label: "需要关注", tone: "warning" };
  return { label: "风险偏高", tone: "danger" };
}

function metricTrendLabel(value) {
  const trend = Number(value) || 0;
  if (Math.abs(trend) < 0.05) return "与前一窗口持平";
  return `较前一窗口 ${trend > 0 ? "+" : ""}${Math.round(trend * 10) / 10}%`;
}

function metricTone(value, count) {
  const text = String(value || "info").toLowerCase();
  if ((text === "red" || text === "danger") && Number(count) <= 0) return "info";
  if (text === "red" || text === "danger") return "danger";
  if (text === "amber" || text === "warning") return "warning";
  if (text === "green" || text === "safe") return "safe";
  return "info";
}

function toneFromSeverity(value) {
  const text = String(value || "").toLowerCase();
  if (["critical", "high", "danger", "error", "severe"].includes(text)) return "danger";
  if (["medium", "warning", "warn", "ask"].includes(text)) return "warning";
  if (["success", "safe", "allow", "low"].includes(text)) return "safe";
  return "info";
}

function severityLabel(value) {
  const labels = { critical: "严重", high: "高危", medium: "中危", low: "低危", danger: "高危", warning: "中危", info: "信息", success: "安全" };
  return labels[String(value || "info").toLowerCase()] || String(value || "信息").toUpperCase();
}

function decisionLabel(value) {
  const text = String(value || "info").toLowerCase();
  const modeLabels = { observe: "观察模式", approval_mode: "审批模式", block_mode: "阻断模式" };
  return modeLabels[text] || verdictLabel(text);
}

function trustLabel(value) {
  const labels = { owner: "所有者", trusted: "可信", trusted_agent: "可信 Agent", delegated_agent: "委托 Agent", workspace: "工作区", external: "外部", unknown: "未知", revoked: "已吊销" };
  return labels[String(value || "unknown").toLowerCase()] || String(value || "未知");
}

function trustSummary(score) {
  const value = Number(score) || 0;
  if (value >= 85) return "高信任";
  if (value >= 60) return "受限信任";
  return "低信任";
}

function agentBoundary(agent) {
  const boundaries = [];
  if (agent.mayDelegate) boundaries.push("可委托");
  if (agent.mayAuthorizeSensitiveTools) boundaries.push("可授权敏感工具");
  if (agent.mayReceiveUntrustedData) boundaries.push("可接收不可信数据");
  return boundaries.join(" · ") || "仅限当前身份范围";
}

function typeLabel(value) {
  const labels = { tool_result: "工具结果", tool_decision: "工具裁决", tool_call: "工具调用", approval_request: "审批请求", lab_command: "用户命令", alert: "安全告警", task_spec: "任务授权", runtime: "运行配置", finding: "安全发现" };
  return labels[String(value || "")] || String(value || "未分类");
}

function sourceLabel(value) {
  const text = String(value || "玄鉴");
  return /openclaw|agentsentry/i.test(text) ? "玄鉴" : text;
}

function recordTool(record) {
  return record?.payload?.normalized_tool || record?.payload?.toolName || record?.payload?.tool || record?.tool || "";
}

function recordDecision(record) {
  return record?.payload?.decision || record?.payload?.verdict || record?.decision || "info";
}

function yesNo(value) {
  return value ? "是" : "否";
}

function splitLines(value) {
  return String(value || "").split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
}

function formatNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? new Intl.NumberFormat("zh-CN").format(number) : "0";
}

function formatDateTime(value) {
  if (!value) return "未记录";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(date).replace(/\//g, "-");
}

function formatClock(value) {
  if (!value) return "--:--:--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(date);
}

function escapeHtml(value) {
  return brandText(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character]));
}

function brandText(value) {
  return String(value ?? "")
    .replace(/showing latest\s+(\d+)\s+of\s+(\d+)\s+(?:AgentSentry|OpenClaw)\s+plugin\s+records/gi, "最近 $1 / $2 条玄鉴审计记录")
    .replace(/\b(?:AgentSentry|OpenClaw)\s+plugin\s+records\b/gi, "玄鉴审计记录")
    .replace(/\b(?:AgentSentry|OpenClaw)\b/gi, "玄鉴");
}

function renderIcons() {
  window.lucide?.createIcons({ attrs: { "stroke-width": 1.8 } });
}
