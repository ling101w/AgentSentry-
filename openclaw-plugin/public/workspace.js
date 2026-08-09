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
    eyebrow: "风险发现",
    description: "按风险、裁决和工具筛查实时告警并下钻原始证据。",
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
  ["allowlistedRecipients", "允许的外发收件人", "每行一个邮箱或目标标识"],
  ["allowlistedApiHosts", "允许的 API 主机", "每行一个域名或主机"],
  ["allowedWriteRoots", "允许写入的根目录", "每行一个目录"],
  ["sensitiveAssets", "敏感资产特征", "每行一个文件名或关键字"],
];

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
  },
};

initialize();

async function initialize() {
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
    policies: '<button class="workspace-primary" type="button" data-action="save-policy"><i data-lucide="save"></i><span>保存策略</span></button>',
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
  const rules = Array.isArray(overview.rules) ? overview.rules.slice(0, 8) : [];
  const operations = Array.isArray(overview.recentOperations) ? overview.recentOperations.slice(0, 12) : [];
  const runs = Array.isArray(overview.runs) ? overview.runs.slice(0, 8) : [];
  const maxLifecycle = Math.max(1, ...lifecycle.map((item) => Number(item?.[1]) || 0));
  const metricByKey = new Map(metrics.map((metric) => [String(metric.key), metric]));
  const secondaryMetrics = ["total", "tools", "taint", "drift"]
    .map((key) => metricByKey.get(key))
    .filter(Boolean);
  const primaryRisks = [...lifecycle]
    .sort((left, right) => (Number(right?.[1]) || 0) - (Number(left?.[1]) || 0))
    .slice(0, 3);
  const protection = protectionStatus(overview.protectionIndex);
  const blocked = Number(metricByKey.get("blocks")?.num ?? overview.blockedHighRisk) || 0;
  const pending = Number(metricByKey.get("pending")?.num) || 0;
  const allowed = Number(metricByKey.get("allowed")?.num) || 0;
  const windowRecords = Number(overview?.source?.window_records ?? metricByKey.get("total")?.num) || 0;

  $("workspaceContent").innerHTML = `
    <section class="overview-command-center" aria-label="当前安全状态">
      <div class="posture-primary">
        <div class="overview-block-heading"><i data-lucide="shield-check"></i><span>当前安全状态</span></div>
        <div class="posture-value"><strong>${formatNumber(overview.protectionIndex)}</strong><span>/100</span></div>
        <div><span class="posture-state tone-${protection.tone}">${escapeHtml(protection.label)}</span></div>
        <p><strong>${formatNumber(blocked)}</strong> 个高危行为已在执行前阻断</p>
        <a href="/alerts" class="overview-text-link">查看高危事件<i data-lucide="arrow-right"></i></a>
      </div>

      <div class="posture-risk">
        <header class="overview-block-header"><div><h3>主要风险</h3><small>${formatNumber(windowRecords)} 条实时记录</small></div></header>
        <div class="lifecycle-list">
          ${primaryRisks.map((item) => {
            const value = Number(item?.[1]) || 0;
            const total = Number(item?.[2]) || 0;
            const percent = Math.round((value / maxLifecycle) * 100);
            const tone = value > 70 ? "danger" : value > 35 ? "warning" : "neutral";
            return `<div class="lifecycle-row tone-${tone}">
              <span>${escapeHtml(item?.[0] || "未分类")}</span>
              <div class="metric-track" style="--value:${percent}%"><span></span></div>
              <b>${formatNumber(value)}</b><small>${formatNumber(total)} 个事件</small>
            </div>`;
          }).join("") || emptyInline("暂无风险数据")}
        </div>
      </div>

      <div class="posture-queue">
        <header class="overview-block-header"><div><h3>需要处理</h3><small>按处置优先级排列</small></div></header>
        <nav class="attention-list" aria-label="待处理事项">
          ${attentionRow("高危事件", blocked, "复核已阻断动作", "danger", "/alerts")}
          ${attentionRow("待审批", pending, pending ? "需要人工裁决" : "当前没有积压", "warning", "/alerts")}
          ${attentionRow("策略放行", allowed, allowed ? "检查例外范围" : "当前没有例外", "neutral", "/audit")}
        </nav>
      </div>
    </section>

    <section class="overview-metric-strip" aria-label="运行指标">
      ${secondaryMetrics.map((metric) => `
        <div class="overview-metric tone-${metricTone(metric.type, metric.num)}">
          <small>${escapeHtml(metric.cn || metric.key)}</small>
          <strong>${formatNumber(metric.num)}</strong>
          <span>${escapeHtml(metricTrendLabel(metric.trend))}</span>
        </div>
      `).join("") || emptyInline("暂无指标")}
    </section>

    <div class="workspace-grid-two overview-investigation-grid">
      <section class="workspace-section workspace-section-flat">
      ${sectionHeader("activity", "最近运行事件", `${operations.length} 条`)}
      <div class="workspace-table-wrap">
        <table class="workspace-table">
          <thead><tr><th style="width:90px">时间</th><th style="width:130px">类型</th><th style="width:130px">工具</th><th>发生了什么</th><th style="width:105px">裁决</th><th style="width:96px">来源</th></tr></thead>
          <tbody>
            ${operations.map((item) => {
              const record = findRecordForOperation(item);
              return `<tr ${record ? `data-record-id="${escapeHtml(record.id)}"` : ""}>
                <td class="mono">${escapeHtml(item.time || "--:--:--")}</td>
                <td>${escapeHtml(typeLabel(item.type))}</td>
                <td class="mono">${escapeHtml(item.tool || "-")}</td>
                <td title="${escapeHtml(item.reason)}">${escapeHtml(item.reason || "未记录")}</td>
                <td>${decisionBadge(item.decision)}</td>
                <td>${escapeHtml(sourceLabel(item.source))}</td>
              </tr>`;
            }).join("") || tableEmpty(6, "暂无运行事件")}
          </tbody>
        </table>
      </div>
      </section>

      <section class="workspace-section workspace-section-flat">
        ${sectionHeader("list-checks", "策略命中", `${rules.length} 条规则`)}
        <div class="rule-list">
          ${rules.map((item) => `<div class="rule-row"><code title="${escapeHtml(item?.[0])}">${escapeHtml(item?.[0] || "未命名规则")}</code><b>${formatNumber(item?.[1])}</b><small>${formatNumber(item?.[2])}%</small></div>`).join("") || emptyInline("暂无策略命中")}
        </div>
      </section>
    </div>

    <div class="workspace-grid-equal">
      <section class="workspace-section workspace-section-flat">
        ${sectionHeader("route", "最近会话", `${runs.length} 个会话`)}
        <div class="session-list">
          ${runs.map((run) => `<a class="session-row" href="/?session=${encodeURIComponent(run.id)}">
            <div><strong>${escapeHtml(run.task || run.id)}</strong><span>${escapeHtml(run.id)} · ${formatNumber(run.event_count)} 个事件</span></div>
            <time>${escapeHtml(formatDateTime(run.created_at))}</time>
          </a>`).join("") || emptyInline("暂无会话")}
        </div>
      </section>
      <section class="workspace-section workspace-section-flat">
        ${sectionHeader("radar", "当前态势结论", `生成于 ${formatClock(overview.generated_at)}`)}
        <p class="drawer-copy">${escapeHtml(overview.summary || "暂无态势结论。")}</p>
        <div class="settings-kv">
          ${kvRow("审计口径", overview?.source?.primary || "未记录")}
          ${kvRow("策略命中", `${formatNumber(overview?.meshMeta?.policy_hits)} 次`)}
          ${kvRow("污染事件", `${formatNumber(overview?.meshMeta?.pollution_events)} 条`)}
          ${kvRow("裁决事件", `${formatNumber(overview?.meshMeta?.decision_events)} 条`)}
        </div>
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

  $("workspaceContent").innerHTML = `
    <section class="workspace-section">
      <div class="agent-summary-band">
        ${summaryStat("已登记智能体", agents.length)}
        ${summaryStat("可继续委托", delegators)}
        ${summaryStat("可授权敏感工具", sensitive)}
        ${summaryStat("可接收不可信数据", untrustedReceivers)}
      </div>
      <div class="workspace-toolbar">
        <label class="workspace-search"><i data-lucide="search"></i><input class="workspace-input" name="agentSearch" data-filter="agentSearch" value="${escapeHtml(state.filters.agentSearch)}" placeholder="搜索名称、ID、租户或命名空间" aria-label="搜索智能体" /></label>
        <span class="toolbar-spacer"></span><small>${filtered.length} / ${agents.length} 个资产</small>
      </div>
      <div class="workspace-table-wrap">
        <table class="workspace-table">
          <thead><tr><th style="width:220px">智能体</th><th style="width:130px">信任等级</th><th style="width:110px">信任分</th><th style="width:140px">租户 / 空间</th><th>授权边界</th><th style="width:150px">最近活动</th></tr></thead>
          <tbody>
            ${filtered.map((agent) => {
              const latest = latestAgentRecord(agent, records);
              return `<tr data-select="agent" data-id="${escapeHtml(agent.id)}">
                <td><div class="cell-main"><strong>${escapeHtml(agent.label || agent.id)}</strong><small>${escapeHtml(agent.id)}</small></div></td>
                <td>${trustBadge(agent.level)}</td>
                <td><div class="cell-main"><strong>${formatNumber(agent.score)} / 100</strong><small>${trustSummary(agent.score)}</small></div></td>
                <td><div class="cell-main"><strong>${escapeHtml(agent.tenant || "default")}</strong><small>${escapeHtml(agent.namespace || "-")}</small></div></td>
                <td>${escapeHtml(agentBoundary(agent))}</td>
                <td class="mono">${latest ? escapeHtml(formatDateTime(latest.created_at)) : "未观测"}</td>
              </tr>`;
            }).join("") || tableEmpty(6, "没有匹配的智能体")}
          </tbody>
        </table>
      </div>
    </section>

    <div class="workspace-grid-two">
      <section class="workspace-section">
        ${sectionHeader("workflow", "会话活动", `${runs.length} 个真实会话`)}
        <div class="session-list">
          ${runs.slice(0, 10).map((run) => `<a class="session-row" href="/?session=${encodeURIComponent(run.id)}"><div><strong>${escapeHtml(run.task || run.id)}</strong><span>${escapeHtml(run.id)} · ${escapeHtml(run.defense_mode || "full")}</span></div><time>${escapeHtml(formatDateTime(run.created_at))}</time></a>`).join("") || emptyInline("暂无会话活动")}
        </div>
      </section>
      <section class="workspace-section">
        ${sectionHeader("shield", "身份链风险", "来自策略配置")}
        <div class="compact-list">
          ${agents.map((agent) => `<button class="compact-row" type="button" data-select="agent" data-id="${escapeHtml(agent.id)}"><div><strong>${escapeHtml(agent.label || agent.id)}</strong><span>${escapeHtml(agentBoundary(agent))}</span></div>${toneBadge(trustSummary(agent.score), Number(agent.score) >= 80 ? "safe" : Number(agent.score) >= 55 ? "warning" : "danger")}</button>`).join("") || emptyInline("暂无身份配置")}
        </div>
      </section>
    </div>`;
}

function renderPolicies() {
  const policy = state.data.policy || {};
  const toggles = policy.toggles || {};
  const lists = policy.lists || {};
  const agents = Array.isArray(policy.agents) ? policy.agents : [];

  $("workspaceContent").innerHTML = `
    <form id="policyForm" class="policy-layout">
      <section class="workspace-section">
        ${sectionHeader("sliders-horizontal", "安全能力开关", `${Object.values(toggles).filter(Boolean).length}/${POLICY_TOGGLES.length} 已启用`)}
        <div class="policy-toggle-list">
          ${POLICY_TOGGLES.map(([key, icon, label, description]) => `<label class="policy-toggle">
            <i data-lucide="${icon}"></i>
            <span><strong>${label}</strong><small>${description}</small></span>
            <span class="switch-control"><input type="checkbox" name="toggle-${key}" ${toggles[key] ? "checked" : ""} /><span></span></span>
          </label>`).join("")}
        </div>
      </section>

      <section class="workspace-section">
        ${sectionHeader("list-filter", "资源边界与白名单", "保存后立即作用于后续裁决")}
        <div class="policy-list-editors">
          ${POLICY_LISTS.map(([key, label, hint]) => `<label class="field-group"><span>${label}</span><textarea class="workspace-textarea" name="list-${key}" placeholder="${hint}">${escapeHtml((lists[key] || []).join("\n"))}</textarea><small>${hint}</small></label>`).join("")}
        </div>
        <div class="policy-save-bar"><span id="policySaveState">${state.dirty ? "存在未保存改动" : `配置档案 ${escapeHtml(policy.profile || "default")}`}</span><button class="workspace-primary" type="submit"><i data-lucide="save"></i>保存策略</button></div>
      </section>
    </form>

    <section class="workspace-section">
      ${sectionHeader("users-round", "Agent 授权矩阵", `${agents.length} 个身份`)}
      <div class="workspace-table-wrap">
        <table class="workspace-table">
          <thead><tr><th style="width:220px">身份</th><th style="width:125px">等级</th><th style="width:90px">信任分</th><th style="width:120px">允许委托</th><th style="width:150px">敏感工具授权</th><th>不可信数据接收</th></tr></thead>
          <tbody>${agents.map((agent) => `<tr data-select="agent" data-id="${escapeHtml(agent.id)}"><td><div class="cell-main"><strong>${escapeHtml(agent.label || agent.id)}</strong><small>${escapeHtml(agent.id)}</small></div></td><td>${trustBadge(agent.level)}</td><td class="mono">${formatNumber(agent.score)}</td><td>${booleanBadge(agent.mayDelegate)}</td><td>${booleanBadge(agent.mayAuthorizeSensitiveTools)}</td><td>${booleanBadge(agent.mayReceiveUntrustedData)}</td></tr>`).join("") || tableEmpty(6, "暂无 Agent 授权配置")}</tbody>
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
    <section class="workspace-section">
      <div class="tool-summary-band">
        ${summaryStat("登记工具", envelopes.length)}
        ${summaryStat("签名完整", signed)}
        ${summaryStat("可外泄", exfiltration)}
        ${summaryStat("已吊销", revocations.length)}
      </div>
      <div class="workspace-toolbar">
        <label class="workspace-search"><i data-lucide="search"></i><input class="workspace-input" name="toolSearch" data-filter="toolSearch" value="${escapeHtml(state.filters.toolSearch)}" placeholder="搜索工具、别名、来源或副作用" aria-label="搜索工具" /></label>
        <select class="workspace-select" name="toolTrust" data-filter="toolTrust" aria-label="按信任等级筛选"><option value="all">全部信任等级</option>${["trusted", "workspace", "external", "unknown", "revoked"].map((value) => `<option value="${value}" ${trust === value ? "selected" : ""}>${trustLabel(value)}</option>`).join("")}</select>
        <span class="toolbar-spacer"></span><small>${rows.length} / ${envelopes.length} 个工具</small>
      </div>
      <div class="workspace-table-wrap">
        <table class="workspace-table">
          <thead><tr><th style="width:190px">工具</th><th style="width:110px">信任</th><th style="width:190px">数据来源</th><th style="width:220px">副作用</th><th style="width:100px">敏感数据</th><th style="width:90px">可外泄</th><th>完整性</th></tr></thead>
          <tbody>${rows.map((envelope) => {
            const manifest = envelope.manifest || {};
            return `<tr data-select="tool" data-id="${escapeHtml(manifest.toolId)}"><td><div class="cell-main"><strong>${escapeHtml(manifest.toolId || "未命名")}</strong><small>${escapeHtml((manifest.aliases || []).join(" · ") || "无别名")}</small></div></td><td>${envelope.revoked ? statusBadge("已吊销", "revoked") : plainAttribute(trustLabel(manifest.defaultTrust))}</td><td>${escapeHtml((manifest.dataOrigins || []).join(" · ") || "-")}</td><td>${escapeHtml((manifest.sideEffects || []).join(" · ") || "-")}</td><td>${plainBoolean(manifest.acceptsSensitiveData)}</td><td>${plainBoolean(manifest.canExfiltrate, true)}</td><td>${envelope.signature ? statusBadge("签名有效", "active") : statusBadge("未签名", "unsigned")}</td></tr>`;
          }).join("") || tableEmpty(7, "没有匹配的工具")}</tbody>
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

  $("workspaceContent").innerHTML = `
    <section class="workspace-section">
      <div class="workspace-toolbar">
        <label class="workspace-search"><i data-lucide="search"></i><input class="workspace-input" name="alertSearch" data-filter="alertSearch" value="${escapeHtml(state.filters.alertSearch)}" placeholder="搜索攻击类型、工具、规则或原因" aria-label="搜索告警" /></label>
        <select class="workspace-select" name="alertSeverity" data-filter="alertSeverity" aria-label="按风险等级筛选"><option value="all">全部风险</option>${["critical", "high", "medium", "low", "info"].map((value) => `<option value="${value}" ${severity === value ? "selected" : ""}>${severityLabel(value)}</option>`).join("")}</select>
        <select class="workspace-select" name="alertAction" data-filter="alertAction" aria-label="按裁决筛选"><option value="all">全部裁决</option>${["block", "ask", "allow"].map((value) => `<option value="${value}" ${action === value ? "selected" : ""}>${decisionLabel(value)}</option>`).join("")}</select>
        <span class="toolbar-spacer"></span><small>第 ${formatNumber(payload.page)} / ${formatNumber(payload.pages)} 页</small>
      </div>
      <div class="alert-feed">
        ${filtered.map((alert) => `<button class="alert-row" type="button" data-select="alert" data-id="${escapeHtml(alert.id)}">
          <span>${toneBadge(alert.severity || "INFO", toneFromSeverity(alert.severity))}</span>
          <div><strong>${escapeHtml(alert.type || "运行风险事件")}</strong><small>${escapeHtml(alert.tool || "未知工具")}</small></div>
          <div><strong>${escapeHtml(alert.reason || "未记录告警原因")}</strong><small>${escapeHtml(alert.rule || "未记录规则")}</small></div>
          <span>${decisionBadge(alert.action)}</span>
          <time>${escapeHtml(alert.time || "--:--:--")}</time>
          <i data-lucide="chevron-right"></i>
        </button>`).join("") || emptyInline("当前筛选条件下没有告警")}
      </div>
      <div class="workspace-pagination"><span>显示 ${formatNumber(payload.start)}-${formatNumber(payload.end)}，共 ${formatNumber(payload.totalAlerts)} 条</span><button class="workspace-secondary" type="button" data-action="alert-page" data-page="${Math.max(1, Number(payload.page || 1) - 1)}" ${Number(payload.page || 1) <= 1 ? "disabled" : ""}><i data-lucide="chevron-left"></i>上一页</button><button class="workspace-secondary" type="button" data-action="alert-page" data-page="${Math.min(Number(payload.pages || 1), Number(payload.page || 1) + 1)}" ${Number(payload.page || 1) >= Number(payload.pages || 1) ? "disabled" : ""}>下一页<i data-lucide="chevron-right"></i></button></div>
    </section>`;
}

function renderAudit() {
  const records = recordList();
  const stats = state.data.stats || {};
  const search = state.filters.auditSearch.trim().toLowerCase();
  const type = state.filters.auditType;
  const severity = state.filters.auditSeverity;
  const types = [...new Set(records.map((record) => record.type).filter(Boolean))].sort();
  const filtered = records.filter((record) => {
    const matchesSearch = !search || `${record.id} ${record.title} ${record.summary} ${JSON.stringify(record.payload || {})}`.toLowerCase().includes(search);
    const matchesType = type === "all" || record.type === type;
    const matchesSeverity = severity === "all" || String(record.severity).toLowerCase() === severity;
    return matchesSearch && matchesType && matchesSeverity;
  });
  const pages = Math.max(1, Math.ceil(filtered.length / state.auditPageSize));
  state.auditPage = Math.min(state.auditPage, pages);
  const start = (state.auditPage - 1) * state.auditPageSize;
  const pageRows = filtered.slice(start, start + state.auditPageSize);

  $("workspaceContent").innerHTML = `
    <section class="workspace-section">
      <div class="agent-summary-band">
        ${summaryStat("审计记录", stats.totalRecords ?? records.length)}
        ${summaryStat("会话", stats.sessions)}
        ${summaryStat("运行批次", stats.runs)}
        ${summaryStat("当前窗口", stats.windowRecords ?? records.length)}
      </div>
      <div class="workspace-toolbar">
        <label class="workspace-search"><i data-lucide="search"></i><input class="workspace-input" name="auditSearch" data-filter="auditSearch" value="${escapeHtml(state.filters.auditSearch)}" placeholder="搜索记录 ID、标题、工具、路径或规则" aria-label="搜索审计记录" /></label>
        <select class="workspace-select" name="auditType" data-filter="auditType" aria-label="按记录类型筛选"><option value="all">全部类型</option>${types.map((value) => `<option value="${escapeHtml(value)}" ${type === value ? "selected" : ""}>${escapeHtml(typeLabel(value))}</option>`).join("")}</select>
        <select class="workspace-select" name="auditSeverity" data-filter="auditSeverity" aria-label="按风险等级筛选"><option value="all">全部等级</option>${["danger", "warning", "info", "success"].map((value) => `<option value="${value}" ${severity === value ? "selected" : ""}>${severityLabel(value)}</option>`).join("")}</select>
        <span class="toolbar-spacer"></span><small>${filtered.length} / ${records.length} 条</small>
      </div>
      <div class="workspace-table-wrap">
        <table class="workspace-table">
          <thead><tr><th style="width:155px">时间</th><th style="width:145px">记录类型</th><th style="width:160px">会话</th><th>事件</th><th style="width:125px">工具</th><th style="width:95px">裁决</th><th style="width:90px">等级</th></tr></thead>
          <tbody>${pageRows.map((record) => `<tr data-record-id="${escapeHtml(record.id)}"><td class="mono">${escapeHtml(formatDateTime(record.created_at))}</td><td>${escapeHtml(typeLabel(record.type))}</td><td class="mono" title="${escapeHtml(record.session_key || record.run_id)}">${escapeHtml(record.session_key || record.run_id || "-")}</td><td><div class="cell-main"><strong>${escapeHtml(record.title || record.summary || "未命名事件")}</strong><small>${escapeHtml(record.summary || record.id)}</small></div></td><td class="mono">${escapeHtml(recordTool(record) || "-")}</td><td>${decisionBadge(recordDecision(record))}</td><td>${toneBadge(severityLabel(record.severity), toneFromSeverity(record.severity))}</td></tr>`).join("") || tableEmpty(7, "没有匹配的审计记录")}</tbody>
        </table>
      </div>
      <div class="workspace-pagination"><span>第 ${state.auditPage} / ${pages} 页</span><button class="workspace-secondary" type="button" data-action="audit-page" data-page="${Math.max(1, state.auditPage - 1)}" ${state.auditPage <= 1 ? "disabled" : ""}><i data-lucide="chevron-left"></i>上一页</button><button class="workspace-secondary" type="button" data-action="audit-page" data-page="${Math.min(pages, state.auditPage + 1)}" ${state.auditPage >= pages ? "disabled" : ""}>下一页<i data-lucide="chevron-right"></i></button></div>
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

  $("workspaceContent").innerHTML = `
    <section class="workspace-section">
      <div class="settings-summary-band">
        ${summaryStat("执行模式", decisionLabel(enforcement.mode), false)}
        ${summaryStat("已启用安全层", `${formatNumber(enforcement.enabledSecurityLayers)}/${stack.length}`, false)}
        ${summaryStat("执行前策略", monitor.pre_exec_policy === "active" ? "ACTIVE" : "INACTIVE", false)}
        ${summaryStat("回滚检查点", items.length, false)}
      </div>
    </section>

    <div class="settings-layout">
      <section class="workspace-section">
        ${sectionHeader("shield-check", "执行模式", `当前 ${escapeHtml(enforcement.mode || "unknown")}`)}
        <div class="mode-segments">
          ${modes.map((mode) => `<label class="mode-option ${mode.value === enforcement.mode ? "selected" : ""}"><input type="radio" name="runtime-mode" value="${escapeHtml(mode.value)}" ${mode.value === enforcement.mode ? "checked" : ""} /><strong>${escapeHtml(mode.label)}</strong><small>${escapeHtml(mode.summary)}</small></label>`).join("")}
        </div>
      </section>

      <section class="workspace-section">
        ${sectionHeader("layers", "安全栈", `${stack.filter((item) => item.enabled).length}/${stack.length} 已启用`)}
        <div class="stack-list">${stack.map((item) => `<div class="stack-row"><div><strong>${escapeHtml(item.label)}</strong><span>${escapeHtml(item.key)}</span></div>${item.enabled ? statusBadge("已启用", "active") : toneBadge("未启用", "warning")}</div>`).join("") || emptyInline("暂无安全栈状态")}</div>
      </section>
    </div>

    <div class="workspace-grid-equal">
      <section class="workspace-section">
        ${sectionHeader("server-cog", "运行环境", health.ok ? "服务正常" : "服务异常")}
        <div class="settings-kv">
          ${kvRow("配置档案", enforcement.profile || policy.profile || "-")}
          ${kvRow("审批超时", `${formatNumber(enforcement.approvalTimeoutMs)} ms`)}
          ${kvRow("配置路径", enforcement.runtimeConfigPath || "-")}
          ${kvRow("审计路径", health.recordsPath || "-")}
          ${kvRow("隔离模式", monitor?.isolation?.mode || "-")}
          ${kvRow("eBPF", monitor.ebpf || "-")}
          ${kvRow("内核执行器", monitor?.observer?.kernel_enforcer_active ? "active" : "unavailable")}
        </div>
      </section>
      <section class="workspace-section">
        ${sectionHeader("badge-check", "运行能力", `${(health.capabilities || []).length} 项`)}
        <div class="policy-list-editors">${(health.capabilities || []).map((capability) => `<span class="tone-badge tone-info">${escapeHtml(capability)}</span>`).join("") || emptyInline("暂无能力声明")}</div>
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
    state.dirty = true;
    const status = $("policySaveState");
    if (status) status.textContent = "存在未保存改动";
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
    state.dirty = true;
    const status = $("policySaveState");
    if (status) status.textContent = "存在未保存改动";
  }
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
  openDrawer("智能体身份", agent.label || agent.id, `
    <section class="drawer-section"><header>身份结论</header><p class="drawer-copy">${escapeHtml(agentBoundary(agent))}。当前信任评分为 ${formatNumber(agent.score)}/100。</p></section>
    <section class="drawer-section"><header>身份属性</header><div class="drawer-kv">
      ${kvRow("Agent ID", agent.id)}${kvRow("信任等级", trustLabel(agent.level))}${kvRow("租户", agent.tenant || "-")}${kvRow("命名空间", agent.namespace || "-")}${kvRow("最近活动", latest ? formatDateTime(latest.created_at) : "未观测")}
    </div></section>
    <section class="drawer-section"><header>授权能力</header><div class="drawer-kv">${kvRow("允许继续委托", yesNo(agent.mayDelegate))}${kvRow("允许敏感工具授权", yesNo(agent.mayAuthorizeSensitiveTools))}${kvRow("允许接收不可信数据", yesNo(agent.mayReceiveUntrustedData))}</div></section>
  `);
}

function openToolDrawer(id) {
  const envelope = (state.data.tools?.manifests || []).find((item) => item.manifest?.toolId === id);
  if (!envelope) return;
  const manifest = envelope.manifest || {};
  const revocation = findRevocation(id, state.data.tools?.revocations || []);
  openDrawer("工具安全清单", id, `
    <section class="drawer-section"><header>信任结论</header><p class="drawer-copy">${revocation ? `该工具已吊销：${escapeHtml(revocation.reason || "未记录原因")}` : `工具清单由 ${escapeHtml(envelope.issuer || "本地管理员")} 签发，当前信任级别为 ${escapeHtml(trustLabel(manifest.defaultTrust))}。`}</p></section>
    <section class="drawer-section"><header>安全属性</header><div class="drawer-kv">${kvRow("信任等级", trustLabel(manifest.defaultTrust))}${kvRow("数据来源", (manifest.dataOrigins || []).join(", ") || "-")}${kvRow("副作用", (manifest.sideEffects || []).join(", ") || "-")}${kvRow("接收敏感数据", yesNo(manifest.acceptsSensitiveData))}${kvRow("可外泄", yesNo(manifest.canExfiltrate))}${kvRow("要求显式授权", yesNo(manifest.requiresExplicitAuthorization))}</div></section>
    <section class="drawer-section"><header>完整性</header><div class="drawer-kv">${kvRow("Digest", envelope.digest || "-")}${kvRow("签名", envelope.signature ? "有效" : "未签名")}${kvRow("登记时间", formatDateTime(envelope.registeredAt))}${kvRow("别名", (manifest.aliases || []).join(", ") || "无")}</div></section>
    <div class="workspace-actions">${revocation ? `<button class="workspace-primary" type="button" data-action="restore-tool" data-tool-id="${escapeHtml(id)}"><i data-lucide="rotate-ccw"></i>恢复信任</button>` : `<button class="workspace-danger" type="button" data-action="revoke-tool" data-tool-id="${escapeHtml(id)}"><i data-lucide="shield-off"></i>吊销工具</button>`}</div>
  `);
}

async function openAlertDrawer(id) {
  const alert = (state.data.alerts?.alerts || []).find((item) => item.id === id) || (state.data.overview?.alerts || []).find((item) => item.id === id);
  if (!alert) return;
  openDrawer("安全告警", alert.type || "运行风险事件", `
    <section class="drawer-section"><header>告警结论</header><p class="drawer-copy">${escapeHtml(alert.reason || "未记录告警原因")}</p></section>
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

function attentionRow(label, value, detail, tone, href) {
  return `<a class="attention-row tone-${escapeHtml(tone)}" href="${escapeHtml(href)}">
    <strong>${formatNumber(value)}</strong>
    <span><b>${escapeHtml(label)}</b><small>${escapeHtml(detail)}</small></span>
    <i data-lucide="chevron-right"></i>
  </a>`;
}

function kvRow(label, value) {
  return `<div class="drawer-kv-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value ?? "-"))}</strong></div>`;
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

function decisionBadge(value) {
  const key = String(value || "info").toLowerCase();
  const normalized = key === "block" || key === "blocked" ? "deny" : key === "review" || key === "approval" ? "ask" : key;
  return `<span class="decision-badge ${escapeHtml(normalized)}">${escapeHtml(decisionLabel(normalized))}</span>`;
}

function booleanBadge(value, dangerWhenTrue = false) {
  return value ? toneBadge("是", dangerWhenTrue ? "danger" : "safe") : toneBadge("否", "info");
}

function plainAttribute(value, tone = "neutral") {
  return `<span class="plain-attribute tone-${escapeHtml(tone)}">${escapeHtml(String(value ?? "-"))}</span>`;
}

function plainBoolean(value, dangerWhenTrue = false) {
  return plainAttribute(value ? "是" : "否", value && dangerWhenTrue ? "danger" : "neutral");
}

function protectionStatus(value) {
  const score = Number(value) || 0;
  if (score >= 80) return { label: "防护稳定", tone: "safe" };
  if (score >= 60) return { label: "需要关注", tone: "warning" };
  return { label: "需要加强", tone: "danger" };
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
  const labels = { deny: "阻断", block: "阻断", blocked: "阻断", ask: "待审批", approval: "审批", allow: "放行", observe: "观察模式", approval_mode: "审批模式", block_mode: "阻断模式", info: "记录" };
  return labels[String(value || "info").toLowerCase()] || String(value || "记录").toUpperCase();
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
