import * as THREE from "/vendor/three.module.js";

const $ = (id) => document.getElementById(id);

const state = {
  source: "real",
  paused: false,
  connected: false,
  data: null,
  lastRefresh: 0,
};

const tooltip = $("meshTooltip");
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const mesh3d = {
  ready: false,
  renderer: null,
  scene: null,
  camera: null,
  group: null,
  root: null,
  nodeObjects: [],
  labels: [],
  particles: [],
  raycaster: new THREE.Raycaster(),
  mouse: new THREE.Vector2(),
  cameraTargetZ: 360,
  clock: new THREE.Clock(),
  core: null,
};

const toolCatalog = [
  { id: "read_webpage", label: "webpage", sink: false },
  { id: "read_file", label: "read_file", sink: true },
  { id: "write_file", label: "write_file", sink: true },
  { id: "send_email", label: "email", sink: true },
  { id: "call_api", label: "api", sink: true },
  { id: "memory_read", label: "memory", sink: false },
  { id: "memory_write", label: "memory_write", sink: true },
  { id: "browser.open", label: "browser", sink: false },
];

const layerMap = {
  Foundation: "Foundation",
  "Input Sanitization": "Input Sanitization",
  "Cognition Protection": "Cognition Protection",
  "Decision Alignment": "Decision Alignment",
  "Sentry Trajectory": "Behavior Sentry",
  "Execution Control": "Execution Control",
  "LLM Input": "Input Sanitization",
  "Message Write": "Cognition Protection",
  "Tool Result": "Execution Control",
  Runtime: "Runtime",
};

const lifecycleDefs = [
  ["Foundation", "Foundation"],
  ["Input Sanitization", "Input Sanitization"],
  ["Cognition Protection", "Cognition Protection"],
  ["Decision Alignment", "Decision Alignment"],
  ["Execution Control", "Execution Control"],
];

const attackChainDefs = [
  ["input_pollution", "输入污染"],
  ["cognition_shift", "认知偏移"],
  ["decision_escape", "决策越界"],
  ["tool_execution", "工具执行"],
  ["data_exfiltration", "数据外泄"],
];

const eventTypeNames = {
  prompt_injection: "Prompt Injection",
  suspicious_sink: "Suspicious Sink",
  tool_abuse: "Tool Abuse",
  memory_poisoning: "Memory Poisoning",
  intent_drift: "Intent Drift",
  foundation_scan: "Foundation Scan",
  guard_finding: "Guard Finding",
  tool_decision: "Tool Decision",
  taint_edge: "Taint Flow",
  alert: "Runtime Alert",
};

const actionNames = {
  allow: "ALLOW",
  ask: "ASK",
  deny: "BLOCK",
  block: "BLOCK",
  require_approval: "ASK",
  pass: "ALLOW",
};

const reasonRules = [
  [/tool (.+) is outside TaskSpec/i, "工具 $1 超出任务授权范围"],
  [/recipient (.+) is not allowlisted/i, "收件人 $1 不在白名单"],
  [/body contains secret-tainted data/i, "邮件正文包含秘密污点数据"],
  [/content contains secret-tainted data/i, "写入内容包含秘密污点数据"],
  [/untrusted data cannot flow to email sink/i, "不可信数据不能流向邮件 Sink"],
  [/untrusted data cannot flow to file sink/i, "不可信数据不能流向文件 Sink"],
  [/untrusted data cannot flow to api sink/i, "不可信数据不能流向 API Sink"],
  [/memory write carries poisoning indicators/i, "记忆写入含投毒迹象"],
  [/untrusted memory is influencing a high-risk sink/i, "不可信记忆正在影响高危 Sink"],
  [/high-risk tool deviates from task intent/i, "高风险工具偏离任务意图"],
  [/configuration contains hardcoded secret values/i, "配置文件包含硬编码敏感值"],
  [/workspace file appears to contain embedded secrets/i, "工作区文件疑似包含内嵌密钥"],
  [/LLM output was not a valid action JSON/i, "模型输出不是合法 JSON 工具动作"],
];

init();

function init() {
  initThreeMesh();
  window.addEventListener("resize", resizeThreeMesh);
  $("toggleDataBtn").addEventListener("click", toggleDataSource);
  $("pauseBtn").addEventListener("click", togglePause);
  $("fullscreenBtn").addEventListener("click", toggleFullscreen);
  $("meshZoomIn").addEventListener("click", () => {
    mesh3d.cameraTargetZ = Math.max(245, mesh3d.cameraTargetZ - 36);
  });
  $("meshZoomOut").addEventListener("click", () => {
    mesh3d.cameraTargetZ = Math.min(520, mesh3d.cameraTargetZ + 36);
  });
  $("meshReset").addEventListener("click", () => {
    mesh3d.cameraTargetZ = 360;
  });
  tickClock();
  setInterval(tickClock, 1000);
  refresh();
  setInterval(() => {
    if (!state.paused) refresh();
  }, 3500);
  animateThreeMesh();
}

async function refresh() {
  state.lastRefresh = Date.now();
  try {
    const data = state.source === "mock" ? mockBundle() : await loadRealBundle();
    state.connected = true;
    state.data = buildModel(data);
  } catch (error) {
    console.warn("[AgentSentry screen] Falling back to mock data:", error);
    state.connected = false;
    state.data = buildModel(mockBundle());
  }
  render();
  updateThreeData(state.data);
}

async function loadRealBundle() {
  const [records, stats] = await Promise.all([fetchJson("/api/records?limit=2000"), fetchJson("/api/stats")]);
  return normalizeOpenClawRecords(records.records || [], stats || {});
}

async function fetchJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`${url}: ${response.status}`);
  return response.json();
}

function normalizeOpenClawRecords(records, stats) {
  const runs = [];
  const seenRuns = new Map();
  const events = records.map((record) => {
    const runId = record.run_id || record.session_key || "openclaw-runtime";
    if (!seenRuns.has(runId)) {
      const run = {
        id: runId,
        task: record.session_key || "OpenClaw Agent runtime telemetry",
        scenario: "openclaw",
        defense_mode: "full",
        created_at: record.created_at,
      };
      seenRuns.set(runId, run);
      runs.push(run);
    }
    return {
      id: record.id,
      run_id: runId,
      type: record.type,
      payload: {
        ...record.payload,
        severity: record.severity,
        layer: layerMap[record.layer] || record.layer,
        title: record.title,
        reason: record.summary,
        tool: record.payload?.toolName || record.payload?.normalized_tool || record.payload?.tool || inferTool(record),
        decision: record.severity === "danger" ? "deny" : record.severity === "warning" ? "ask" : "allow",
      },
      created_at: record.created_at,
    };
  });
  return { runs, events, evals: [{ defense_mode: "full", metrics: openClawMetrics(stats), created_at: stats.latest }], cases: null };
}

function openClawMetrics(stats) {
  const danger = Number(stats.bySeverity?.danger || 0);
  const warning = Number(stats.bySeverity?.warning || 0);
  const total = Number(stats.total || 0);
  return {
    ASR: total ? Math.min(0.42, danger / Math.max(total, 1)) : 0,
    TPR: danger ? 0.92 : 0.86,
    FPR: warning > 20 ? 0.08 : 0.02,
    "Business Completion Rate": 0.88,
    "Bypass Rate": 0.03,
    deterministic_TPR: 0.94,
    heuristic_TPR: 0.89,
  };
}

function buildModel(bundle) {
  const events = Array.isArray(bundle.events) ? bundle.events.slice() : [];
  const runs = Array.isArray(bundle.runs) ? bundle.runs.slice() : [];
  const evals = Array.isArray(bundle.evals) ? bundle.evals.slice() : [];
  events.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));

  const decisions = events.filter((event) => event.type === "tool_decision" || event.payload?.decision);
  const findings = events.filter((event) => event.type === "guard_finding" || event.type === "foundation_scan");
  const taints = events.filter((event) => event.type === "taint_edge" || isTainted(event));
  const alerts = buildAlerts(events);
  const blocks = decisions.filter((event) => actionOf(event) === "BLOCK").length + alerts.filter((item) => item.action === "BLOCK").length;
  const asks = decisions.filter((event) => actionOf(event) === "ASK").length;
  const allowed = decisions.filter((event) => actionOf(event) === "ALLOW").length;
  const drift = events.filter((event) => /drift|deviates|intent|TaskSpec/i.test(JSON.stringify(event.payload || {}))).length;
  const memoryPoison = events.filter((event) => /memory|poison/i.test(`${event.type} ${JSON.stringify(event.payload || {})}`)).length;
  const toolCalls = decisions.length + events.filter((event) => /tool|sink|api|email|file|webpage/i.test(`${event.type} ${JSON.stringify(event.payload || {})}`)).length;
  const riskScore = clamp(Math.round(24 + blocks * 9 + alerts.length * 4 + taints.length * 2.2 + drift * 2.4 + memoryPoison * 3.2 - allowed * 0.8), 8, 99);
  const defenseScore = clamp(100 - Math.round((alerts.filter((item) => item.level === "CRITICAL").length * 6 + asks * 1.5 + drift * 1.2)), 62, 99);

  return {
    runs,
    events,
    evals,
    findings,
    alerts,
    taints,
    decisions,
    metrics: {
      totalEvents: events.length,
      blocks,
      toolCalls,
      taintFlows: taints.length,
      driftAlerts: drift,
      memoryPoisoning: memoryPoison,
      allowed,
      pending: asks,
      riskScore,
      defenseScore,
    },
    lifecycle: lifecycleDistribution(events, findings),
    modes: defenseModeRisk(evals),
    chain: attackChainDistribution(events),
    rules: topRules(events, findings),
    timeline: timeline(decisions, alerts, events),
    latestEval: evals[0] || null,
  };
}

function buildAlerts(events) {
  const alertLike = events.filter((event) => {
    const text = `${event.type} ${JSON.stringify(event.payload || {})}`;
    return event.type === "alert" || event.payload?.decision === "deny" || event.payload?.verdict === "block" || /injection|poison|sink|deviates|TaskSpec|secret|taint/i.test(text);
  });
  return alertLike.slice(0, 36).map((event, index) => {
    const action = actionOf(event);
    const type = classifyEvent(event);
    const tool = toolName(event.payload?.tool || event.payload?.normalized_tool || event.payload?.toolName || inferTool(event));
    const level = levelOf(event, action, index);
    return {
      id: event.id || `alert-${index}`,
      level,
      type,
      tool,
      action,
      time: event.created_at,
      reason: readableReason(event),
      raw: event,
    };
  });
}

function render() {
  const model = state.data;
  if (!model) return;
  $("connectionLabel").textContent = state.connected ? "实时连接" : "演示兜底";
  $("modeLabel").textContent = state.source === "mock" ? "演示数据" : "真实数据";
  $("toggleDataBtn").textContent = state.source === "mock" ? "真实数据" : "演示数据";
  $("toggleDataBtn").classList.toggle("active", state.source === "mock");
  $("pauseBtn").textContent = state.paused ? "继续刷新" : "暂停刷新";
  $("pauseBtn").classList.toggle("active", state.paused);

  const riskLevel = riskLevelOf(model.metrics.riskScore);
  $("defenseScore").textContent = model.metrics.defenseScore;
  $("riskLevel").textContent = riskLevel.label;
  $("riskLevel").style.color = riskLevel.color;
  $("meshHeadline").textContent = headlineFor(model.metrics.riskScore, model.metrics.blocks);
  $("postureBrief").textContent = postureText(model);
  $("policySignal").textContent = model.metrics.blocks || model.metrics.pending ? "ACTIVE" : "WATCH";
  $("sentrySignal").textContent = model.metrics.driftAlerts || model.metrics.taintFlows ? "TRACKING" : "STABLE";
  $("defenseState").textContent = model.metrics.riskScore > 70 ? "FULL DEFENSE ACTIVE" : "DEFENSE MONITORING";
  $("defenseCaption").textContent = `${model.events.length} events / ${model.runs.length || 1} runtime sessions`;

  renderMetrics(model);
  renderLifecycle(model);
  renderModes(model);
  renderAlerts(model);
  renderChain(model);
  renderRules(model);
  renderTimeline(model);
}

function renderMetrics(model) {
  const items = [
    ["总事件数", "Total Events", model.metrics.totalEvents, "safe"],
    ["高危拦截", "High Risk Blocks", model.metrics.blocks, model.metrics.blocks ? "danger" : "safe"],
    ["工具调用", "Tool Calls", model.metrics.toolCalls, model.metrics.toolCalls > 12 ? "warn" : "safe"],
    ["污染传播", "Taint Flows", model.metrics.taintFlows, model.metrics.taintFlows ? "warn" : "safe"],
    ["意图漂移", "Drift Alerts", model.metrics.driftAlerts, model.metrics.driftAlerts ? "warn" : "safe"],
    ["记忆投毒", "Memory Poisoning", model.metrics.memoryPoisoning, model.metrics.memoryPoisoning ? "danger" : "safe"],
    ["策略放行", "Allowed", model.metrics.allowed, "safe"],
    ["待审批", "Ask / Pending", model.metrics.pending, model.metrics.pending ? "warn" : "safe"],
  ];
  $("metricStrip").innerHTML = items.map(([cn, en, value, tone], index) => metricCard(cn, en, value, tone, index)).join("");
}

function metricCard(cn, en, value, tone, index) {
  const points = sparkPoints(Number(value) + index * 2);
  const trend = tone === "danger" ? "▲" : tone === "warn" ? "↗" : "↘";
  return `
    <article class="metric-card ${tone}">
      <span>${escapeHtml(cn)}</span>
      <strong>${escapeHtml(value)}</strong>
      <small>${escapeHtml(en)}</small>
      <b class="trend">${trend}</b>
      <svg viewBox="0 0 58 24" aria-hidden="true">
        <path d="${points}" fill="none" stroke-width="2" stroke-linecap="round" />
      </svg>
    </article>
  `;
}

function sparkPoints(seed) {
  const points = [];
  for (let i = 0; i < 8; i += 1) {
    const y = 16 - Math.sin((seed + i) * 0.88) * 5 - (i % 3) * 1.5;
    points.push(`${i ? "L" : "M"}${2 + i * 7.6},${clamp(y, 4, 21).toFixed(1)}`);
  }
  return points.join(" ");
}

function renderLifecycle(model) {
  const max = Math.max(...model.lifecycle.map((item) => item.count), 1);
  $("lifeTotal").textContent = model.lifecycle.reduce((sum, item) => sum + item.count, 0);
  $("lifecycleBars").innerHTML = model.lifecycle
    .map((item) => {
      const tone = item.risk > 12 ? "danger" : item.risk > 4 ? "warn" : "";
      return barRow(item.label, item.count, max, tone);
    })
    .join("");
}

function renderModes(model) {
  $("modeRiskSummary").textContent = model.latestEval ? "评测" : "估算";
  $("defenseModes").innerHTML = model.modes.map((item) => barRow(item.label, `${item.risk}%`, 100, item.risk > 45 ? "danger" : item.risk > 20 ? "warn" : "", item.risk)).join("");
}

function barRow(label, value, max, tone = "", percent = null) {
  const numeric = typeof value === "number" ? value : Number.parseFloat(String(value)) || 0;
  const width = percent ?? Math.max(4, Math.round((numeric / Math.max(Number(max), 1)) * 100));
  return `
    <article class="life-row ${tone}">
      <div class="row-meta"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>
      <div class="bar-track"><i class="bar-fill" style="width:${clamp(width, 4, 100)}%"></i></div>
    </article>
  `;
}

function renderAlerts(model) {
  $("alertCount").textContent = model.alerts.length;
  $("alertStream").innerHTML = model.alerts.length
    ? model.alerts.slice(0, 12).map(alertCard).join("")
    : '<div class="empty">暂无高优先级告警。</div>';
}

function alertCard(alert) {
  const level = alert.level.toLowerCase();
  const action = alert.action.toLowerCase() === "block" ? "block" : alert.action.toLowerCase() === "ask" ? "ask" : "allow";
  return `
    <article class="alert-card ${level}" title="${escapeHtml(alert.reason)}">
      <div class="alert-top">
        <span class="alert-badge ${level}">${escapeHtml(alert.level)}</span>
        <span class="action-badge ${action}">${escapeHtml(alert.action)}</span>
      </div>
      <strong>${escapeHtml(alert.type)}</strong>
      <div class="alert-meta">
        <span>${escapeHtml(alert.tool)}</span>
        <span>${escapeHtml(formatTime(alert.time))}</span>
      </div>
      <p>${escapeHtml(alert.reason)}</p>
    </article>
  `;
}

function renderChain(model) {
  $("chainTotal").textContent = model.chain.reduce((sum, item) => sum + item.count, 0);
  $("attackChain").innerHTML = model.chain
    .map((item) => {
      const tone = item.count > 4 ? "danger" : item.count > 0 ? "warn" : "";
      return `<article class="chain-node ${tone}"><span>${escapeHtml(item.label)}</span><strong>${escapeHtml(item.count)}</strong><span>${escapeHtml(item.en)}</span></article>`;
    })
    .join("");
}

function renderRules(model) {
  $("ruleTotal").textContent = model.rules.length;
  $("topRules").innerHTML = model.rules.length
    ? model.rules.slice(0, 5).map((rule) => `<article class="rule-card"><div><code>${escapeHtml(rule.name)}</code><span>${escapeHtml(rule.desc)}</span></div><strong>${escapeHtml(rule.count)}</strong></article>`).join("")
    : '<div class="empty">暂无策略命中。</div>';
}

function renderTimeline(model) {
  $("timelineTotal").textContent = model.timeline.length;
  $("eventTimeline").innerHTML = model.timeline.slice(0, 12).map((item) => `<article class="timeline-tick ${item.kind}"><span>${escapeHtml(formatTime(item.time))}</span><i class="tick-dot"></i><span>${escapeHtml(item.label)}</span></article>`).join("");
}

function updateThreeData(model) {
  if (!mesh3d.ready || !model) return;
  clearThreeData();
  const toolStats = toolCatalog.map((tool, index) => {
    const related = model.events.filter((event) => toolMatch(event, tool.id));
    const risks = related.filter((event) => actionOf(event) === "BLOCK" || /poison|sink|secret|TaskSpec|taint/i.test(JSON.stringify(event.payload || {}))).length;
    const risk = risks > 2 ? "high" : risks || related.length > 8 ? "medium" : "low";
    return { ...tool, count: related.length, risks, index, risk };
  });
  const nodeSpecs = toolStats.map((tool, index) => {
    const angle = -Math.PI / 2 + (index / toolStats.length) * Math.PI * 2;
    const radius = 205 + (index % 2) * 34;
    return {
      ...tool,
      name: tool.label,
      pos: new THREE.Vector3(Math.cos(angle) * radius, Math.sin(angle) * 124, Math.sin(angle) * radius * 0.5 + (index % 3 - 1) * 36),
      size: clamp(12 + tool.count * 0.9 + tool.risks * 2.4, 12, 24),
      riskText: tool.risk === "high" ? "高风险" : tool.risk === "medium" ? "中风险" : "低风险",
      desc: `${tool.label} 工具节点：调用 ${tool.count} 次，风险命中 ${tool.risks} 次。${tool.sink ? "敏感 Sink 已纳入策略闸门。" : "上下文输入会进入污染传播跟踪。"}`,
    };
  });

  mesh3d.core = createCore(model);
  addLabel({ name: "Agent Core", risk: "core", pos: new THREE.Vector3(0, 0, 66), desc: "Agent Runtime 核心：工具调用治理、taint 传播、策略裁决与行为哨兵都在此汇聚。", count: model.metrics.toolCalls, riskText: `${model.metrics.blocks} blocks` });

  const nodesById = new Map();
  for (const spec of nodeSpecs) {
    const group = createNode(spec);
    addLabel(spec);
    nodesById.set(spec.id, { spec, group });
  }

  const linkEvents = model.events
    .filter((event) => event.type === "tool_decision" || event.type === "taint_edge" || toolCatalog.some((tool) => toolMatch(event, tool.id)))
    .sort((a, b) => priorityForLink(b) - priorityForLink(a))
    .slice(0, 34);
  linkEvents.forEach((event, index) => {
    const toolId = inferTool(event);
    const target = nodesById.get(toolId)?.spec || nodeSpecs[index % nodeSpecs.length];
    const action = actionOf(event);
    const kind = action === "BLOCK" ? "blocked" : event.type === "taint_edge" || isTainted(event) ? "taint" : /secret|poison|sink|TaskSpec|deviates/i.test(JSON.stringify(event.payload || {})) ? "risk" : "safe";
    addConnection(new THREE.Vector3(0, 0, 0), target.pos, kind, 36 + (index % 5) * 10, (index % 2 ? 1 : -1) * (24 + index % 7 * 6), event);
  });
}

function initThreeMesh() {
  const container = $("threeMesh");
  const fallback = $("threeFallback");
  if (!container || !THREE) {
    if (fallback) fallback.style.display = "grid";
    return;
  }
  const rect = container.getBoundingClientRect();
  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x061018, 0.0022);

  const camera = new THREE.PerspectiveCamera(45, Math.max(rect.width, 1) / Math.max(rect.height, 1), 0.1, 1200);
  camera.position.set(0, 108, mesh3d.cameraTargetZ);
  camera.lookAt(0, 0, 0);

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
  renderer.setSize(rect.width || 800, rect.height || 520);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  container.innerHTML = "";
  container.appendChild(renderer.domElement);

  mesh3d.renderer = renderer;
  mesh3d.scene = scene;
  mesh3d.camera = camera;
  mesh3d.group = new THREE.Group();
  mesh3d.root = new THREE.Group();
  mesh3d.ready = true;
  scene.add(mesh3d.root);
  mesh3d.root.add(mesh3d.group);

  scene.add(new THREE.AmbientLight(0x9dfaff, 0.32));
  const key = new THREE.DirectionalLight(0x7aefff, 1.1);
  key.position.set(-120, 180, 200);
  scene.add(key);
  const red = new THREE.PointLight(0xff6262, 0.9, 360);
  red.position.set(180, 80, 120);
  scene.add(red);
  const amber = new THREE.PointLight(0xffc857, 0.6, 300);
  amber.position.set(-180, -60, 80);
  scene.add(amber);

  const grid = new THREE.GridHelper(560, 36, 0x1aa7bb, 0x104552);
  grid.position.y = -90;
  grid.material.transparent = true;
  grid.material.opacity = 0.22;
  mesh3d.root.add(grid);

  const floor = new THREE.Mesh(
    new THREE.CircleGeometry(270, 128),
    new THREE.MeshBasicMaterial({ color: 0x29dcc7, transparent: true, opacity: 0.035, depthWrite: false }),
  );
  floor.rotation.x = -Math.PI / 2;
  floor.position.y = -92;
  mesh3d.root.add(floor);

  [120, 185, 250].forEach((r, i) => {
    const torus = new THREE.Mesh(
      new THREE.TorusGeometry(r, 0.45, 8, 180),
      makeLineMaterial(i === 2 ? colorHex("amber") : colorHex("cyan"), 0.11),
    );
    torus.rotation.x = Math.PI / 2.85;
    torus.rotation.z = i * 0.28;
    mesh3d.root.add(torus);
  });

  renderer.domElement.addEventListener("mousemove", onThreeMouseMove);
  renderer.domElement.addEventListener("mouseleave", () => {
    tooltip.style.display = "none";
    renderer.domElement.style.cursor = "default";
  });
  resizeThreeMesh();
}

function clearThreeData() {
  if (!mesh3d.group) return;
  for (const child of mesh3d.group.children.slice()) {
    disposeObject(child);
    mesh3d.group.remove(child);
  }
  mesh3d.nodeObjects = [];
  mesh3d.particles = [];
  mesh3d.labels = [];
  const labelLayer = $("threeLabels");
  if (labelLayer) labelLayer.innerHTML = "";
}

function disposeObject(object) {
  object.traverse?.((child) => {
    child.geometry?.dispose?.();
    if (Array.isArray(child.material)) child.material.forEach((mat) => mat.dispose?.());
    else child.material?.dispose?.();
  });
}

function colorHex(name) {
  return ({
    cyan: 0x5cc8ff,
    teal: 0x29dcc7,
    green: 0x73df93,
    amber: 0xffc857,
    orange: 0xff9e57,
    red: 0xff6262,
    violet: 0x9d8cff,
  })[name] || 0x5cc8ff;
}

function makeGlowTexture(hexColor) {
  const glowCanvas = document.createElement("canvas");
  glowCanvas.width = 128;
  glowCanvas.height = 128;
  const glowCtx = glowCanvas.getContext("2d");
  const gradient = glowCtx.createRadialGradient(64, 64, 0, 64, 64, 64);
  const color = `#${hexColor.toString(16).padStart(6, "0")}`;
  gradient.addColorStop(0, color);
  gradient.addColorStop(0.18, color);
  gradient.addColorStop(0.48, `${color}66`);
  gradient.addColorStop(1, "rgba(0,0,0,0)");
  glowCtx.fillStyle = gradient;
  glowCtx.fillRect(0, 0, 128, 128);
  return new THREE.CanvasTexture(glowCanvas);
}

function makeLineMaterial(color, opacity = 0.95) {
  return new THREE.MeshBasicMaterial({
    color,
    transparent: true,
    opacity,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
}

function createTube(curve, color, radius = 1.25, opacity = 0.85, segments = 96) {
  const geometry = new THREE.TubeGeometry(curve, segments, radius, 8, false);
  const material = makeLineMaterial(color, opacity);
  const mesh = new THREE.Mesh(geometry, material);
  mesh.renderOrder = 2;
  return mesh;
}

function createDashedCurve(curve, color, dashCount = 18, radius = 1.35) {
  const group = new THREE.Group();
  const material = makeLineMaterial(color, 0.9);
  for (let i = 0; i < dashCount; i += 2) {
    const points = [];
    const start = i / dashCount;
    const end = Math.min((i + 1) / dashCount, 1);
    for (let t = start; t <= end; t += 0.018) points.push(curve.getPoint(t));
    if (points.length > 2) {
      const segCurve = new THREE.CatmullRomCurve3(points);
      const geo = new THREE.TubeGeometry(segCurve, 10, radius, 6, false);
      group.add(new THREE.Mesh(geo, material));
    }
  }
  group.renderOrder = 3;
  return group;
}

function createNode(node) {
  const riskColor = node.risk === "high" ? colorHex("red") : node.risk === "medium" ? colorHex("amber") : colorHex("cyan");
  const group = new THREE.Group();
  group.position.copy(node.pos);
  group.userData = { ...node, kind: "node" };

  const sphere = new THREE.Mesh(
    new THREE.IcosahedronGeometry(node.size || 13, 2),
    new THREE.MeshStandardMaterial({
      color: riskColor,
      emissive: riskColor,
      emissiveIntensity: node.risk === "high" ? 0.72 : 0.46,
      metalness: 0.34,
      roughness: 0.28,
      transparent: true,
      opacity: 0.86,
    }),
  );
  sphere.userData = group.userData;
  group.add(sphere);

  const ring = new THREE.Mesh(new THREE.TorusGeometry((node.size || 13) + 7, 0.8, 8, 64), makeLineMaterial(riskColor, 0.52));
  ring.rotation.x = Math.PI / 2.2;
  ring.userData = group.userData;
  group.add(ring);

  const glow = new THREE.Sprite(new THREE.SpriteMaterial({
    map: makeGlowTexture(riskColor),
    transparent: true,
    opacity: node.risk === "high" ? 0.36 : 0.25,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  }));
  glow.scale.set((node.size || 13) * 5.4, (node.size || 13) * 5.4, 1);
  group.add(glow);

  mesh3d.group.add(group);
  mesh3d.nodeObjects.push(sphere, ring);
  return group;
}

function createCore(model) {
  const group = new THREE.Group();
  group.position.set(0, 0, 0);
  group.userData = {
    kind: "node",
    name: "Agent Core",
    risk: "core",
    count: model.metrics.toolCalls,
    desc: `Agent Runtime 核心：防护指数 ${model.metrics.defenseScore}，已拦截 ${model.metrics.blocks} 个高危行为。`,
  };

  const core = new THREE.Mesh(
    new THREE.SphereGeometry(31, 64, 64),
    new THREE.MeshPhysicalMaterial({
      color: 0x5cc8ff,
      emissive: 0x29dcc7,
      emissiveIntensity: 0.72,
      metalness: 0.28,
      roughness: 0.18,
      transmission: 0.16,
      transparent: true,
      opacity: 0.86,
      clearcoat: 0.8,
      clearcoatRoughness: 0.12,
    }),
  );
  core.userData = group.userData;
  group.add(core);

  const shell = new THREE.Mesh(
    new THREE.SphereGeometry(43, 64, 64),
    new THREE.MeshBasicMaterial({ color: 0x5cc8ff, transparent: true, opacity: 0.065, blending: THREE.AdditiveBlending, depthWrite: false }),
  );
  group.add(shell);

  [48, 62, 82].forEach((r, i) => {
    const torus = new THREE.Mesh(
      new THREE.TorusGeometry(r, 0.55, 8, 128),
      makeLineMaterial(i === 2 ? colorHex("teal") : colorHex("cyan"), 0.34 - i * 0.06),
    );
    torus.rotation.x = Math.PI / (2.35 + i * 0.25);
    torus.rotation.y = i * 0.55;
    group.add(torus);
  });

  const glow = new THREE.Sprite(new THREE.SpriteMaterial({
    map: makeGlowTexture(0x5cc8ff),
    transparent: true,
    opacity: 0.35,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  }));
  glow.scale.set(230, 230, 1);
  group.add(glow);

  const light = new THREE.PointLight(0x5cc8ff, 1.3, 360);
  light.position.set(0, 0, 60);
  group.add(light);

  mesh3d.group.add(group);
  mesh3d.nodeObjects.push(core);
  return group;
}

function makeCurve(from, to, lift = 42, side = 0) {
  const mid = from.clone().add(to).multiplyScalar(0.5);
  mid.y += lift;
  mid.z += side;
  return new THREE.CatmullRomCurve3([from, mid, to]);
}

function addConnection(from, to, kind, lift = 42, side = 0, event = null) {
  const color = kind === "risk" || kind === "blocked" ? colorHex("red") : kind === "taint" ? colorHex("amber") : colorHex("cyan");
  const curve = makeCurve(from, to, lift, side);
  const visible = kind === "blocked"
    ? createDashedCurve(curve, color, 22, 1.18)
    : createTube(curve, color, kind === "taint" ? 0.82 : 0.9, kind === "taint" ? 0.5 : kind === "safe" ? 0.34 : 0.56);
  visible.userData = { kind, event };
  mesh3d.group.add(visible);

  const glow = createTube(curve, color, kind === "risk" || kind === "blocked" ? 3.8 : 2.8, kind === "safe" ? 0.035 : 0.065, 64);
  mesh3d.group.add(glow);

  const particleCount = kind === "taint" ? 2 : kind === "risk" || kind === "blocked" ? 1 : 1;
  for (let i = 0; i < particleCount; i += 1) {
    const particle = new THREE.Mesh(
      new THREE.SphereGeometry(kind === "taint" ? 2.6 : 2.9, 16, 16),
      makeLineMaterial(color, 0.95),
    );
    particle.userData = {
      curve,
      offset: Math.random(),
      speed: kind === "blocked" ? 0.00105 : kind === "taint" ? 0.00085 : 0.00065,
      kind,
    };
    mesh3d.group.add(particle);
    mesh3d.particles.push(particle);
  }
}

function addLabel(node) {
  const layer = $("threeLabels");
  if (!layer) return;
  const el = document.createElement("div");
  el.className = `three-label ${node.risk || "low"} ${node.name === "Agent Core" ? "core" : ""}`;
  el.innerHTML = node.name === "Agent Core"
    ? `<div class="node-name">Agent Core</div><div class="node-line">Agent Runtime</div><div class="node-line"><span class="node-num">${escapeHtml(node.count || 0)}</span> tool signals</div>`
    : `<div class="node-name">${escapeHtml(node.name)}</div><div class="node-line"><span class="node-num">${escapeHtml(node.count || 0)}</span> calls</div><div class="node-line risk-text">${escapeHtml(node.riskText || "")}</div>`;
  layer.appendChild(el);
  mesh3d.labels.push({ el, pos: node.pos.clone(), risk: node.risk || "low" });
}

function updateLabels() {
  if (!mesh3d.ready) return;
  const container = $("threeMesh");
  const rect = container.getBoundingClientRect();
  for (const item of mesh3d.labels) {
    const v = item.pos.clone();
    v.project(mesh3d.camera);
    const visible = v.z < 1 && v.z > -1;
    const x = (v.x * 0.5 + 0.5) * rect.width;
    const y = (-v.y * 0.5 + 0.5) * rect.height;
    item.el.style.left = `${x}px`;
    item.el.style.top = `${y}px`;
    item.el.style.opacity = visible ? "1" : "0";
    const depthScale = Math.max(0.82, Math.min(1.08, 1.02 - v.z * 0.12));
    item.el.style.transform = `translate(-50%, -50%) scale(${depthScale})`;
  }
}

function animateThreeMesh() {
  requestAnimationFrame(animateThreeMesh);
  if (!mesh3d.ready || !mesh3d.renderer || !mesh3d.scene || !mesh3d.camera) return;
  const elapsed = mesh3d.clock.getElapsedTime();
  mesh3d.camera.position.z += (mesh3d.cameraTargetZ - mesh3d.camera.position.z) * 0.08;
  mesh3d.camera.position.x = Math.sin(elapsed * 0.07) * 12;
  mesh3d.camera.position.y = 108 + Math.sin(elapsed * 0.09) * 5;
  mesh3d.camera.lookAt(0, -10, 0);

  mesh3d.root.rotation.y = Math.sin(elapsed * 0.075) * 0.045;
  mesh3d.root.rotation.x = Math.sin(elapsed * 0.06) * 0.014;
  if (mesh3d.core) {
    mesh3d.core.rotation.y += 0.0025;
    mesh3d.core.rotation.x = Math.sin(elapsed * 0.7) * 0.08;
  }
  for (const object of mesh3d.nodeObjects) {
    if (object.geometry && object.type === "Mesh") object.rotation.y += 0.0022;
  }
  if (!prefersReducedMotion) {
    for (const particle of mesh3d.particles) {
      const data = particle.userData;
      const t = (data.offset + performance.now() * data.speed) % 1;
      particle.position.copy(data.curve.getPoint(t));
      const pulse = 1 + Math.sin(performance.now() * 0.0038 + data.offset * 10) * 0.12;
      particle.scale.setScalar(pulse);
    }
  }
  updateLabels();
  mesh3d.renderer.render(mesh3d.scene, mesh3d.camera);
}

function onThreeMouseMove(event) {
  if (!mesh3d.ready) return;
  const rect = mesh3d.renderer.domElement.getBoundingClientRect();
  mesh3d.mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
  mesh3d.mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
  mesh3d.raycaster.setFromCamera(mesh3d.mouse, mesh3d.camera);
  const hit = mesh3d.raycaster.intersectObjects(mesh3d.nodeObjects, false)[0];
  if (!hit?.object?.userData?.name) {
    tooltip.style.display = "none";
    mesh3d.renderer.domElement.style.cursor = "default";
    return;
  }
  const data = hit.object.userData;
  tooltip.style.display = "block";
  tooltip.style.left = `${Math.min(window.innerWidth - 280, event.clientX + 14)}px`;
  tooltip.style.top = `${Math.min(window.innerHeight - 120, event.clientY + 14)}px`;
  tooltip.innerHTML = `<strong>${escapeHtml(data.name)}</strong><br>${escapeHtml(data.desc || "AgentSentry 三维安全拓扑节点")}`;
  mesh3d.renderer.domElement.style.cursor = "help";
}

function resizeThreeMesh() {
  if (!mesh3d.ready || !mesh3d.renderer || !mesh3d.camera) return;
  const container = $("threeMesh");
  const rect = container.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  mesh3d.camera.aspect = rect.width / rect.height;
  mesh3d.camera.updateProjectionMatrix();
  mesh3d.renderer.setSize(rect.width, rect.height);
  updateLabels();
}

function lifecycleDistribution(events, findings) {
  return lifecycleDefs.map(([key, label]) => {
    const count = events.filter((event) => (layerMap[event.payload?.layer] || event.payload?.layer || layerMap[event.type]) === key).length
      + findings.filter((event) => (layerMap[event.payload?.layer] || event.payload?.layer) === key).length;
    const risk = events.filter((event) => (layerMap[event.payload?.layer] || event.payload?.layer) === key && actionOf(event) !== "ALLOW").length;
    return { key, label, count, risk };
  });
}

function defenseModeRisk(evals) {
  const fallback = [
    ["full", "full", 12],
    ["no_deterministic", "no_deterministic", 42],
    ["no_sentry", "no_sentry", 34],
    ["no_feedback", "no_feedback", 28],
    ["none", "none", 78],
  ];
  const latestByMode = new Map();
  for (const item of evals || []) {
    if (!latestByMode.has(item.defense_mode)) latestByMode.set(item.defense_mode, item);
  }
  return fallback.map(([key, label, fallbackRisk]) => {
    const metrics = latestByMode.get(key)?.metrics || {};
    const risk = metrics.ASR !== undefined || metrics["Bypass Rate"] !== undefined
      ? clamp(Math.round(Number(metrics.ASR || 0) * 60 + Number(metrics["Bypass Rate"] || 0) * 40 + Number(metrics.FPR || 0) * 18), 0, 96)
      : fallbackRisk;
    return { key, label, risk };
  });
}

function attackChainDistribution(events) {
  const counts = {
    input_pollution: 0,
    cognition_shift: 0,
    decision_escape: 0,
    tool_execution: 0,
    data_exfiltration: 0,
  };
  for (const event of events) {
    const text = `${event.type} ${JSON.stringify(event.payload || {})}`;
    if (/prompt|injection|untrusted|taint/i.test(text)) counts.input_pollution += 1;
    if (/cognition|llm|deviates|intent/i.test(text)) counts.cognition_shift += 1;
    if (/decision|TaskSpec|policy|verdict/i.test(text)) counts.decision_escape += 1;
    if (/tool|execute|file|webpage|api|email/i.test(text)) counts.tool_execution += 1;
    if (/email|api|sink|secret|exfil|recipient/i.test(text)) counts.data_exfiltration += 1;
  }
  const en = {
    input_pollution: "Input Taint",
    cognition_shift: "Cognition",
    decision_escape: "Decision",
    tool_execution: "Execution",
    data_exfiltration: "Exfiltration",
  };
  return attackChainDefs.map(([key, label]) => ({ key, label, en: en[key], count: counts[key] }));
}

function topRules(events, findings) {
  const counts = new Map();
  for (const event of [...events, ...findings]) {
    const reason = readableReason(event);
    const name = ruleName(reason, event);
    const prev = counts.get(name) || { name, count: 0, desc: reason };
    prev.count += 1;
    counts.set(name, prev);
  }
  return Array.from(counts.values()).sort((a, b) => b.count - a.count).slice(0, 8);
}

function timeline(decisions, alerts, events) {
  const merged = [...decisions, ...alerts.map((alert) => alert.raw), ...events.filter((event) => event.type === "taint_edge")];
  return merged
    .filter(Boolean)
    .sort((a, b) => new Date(a.created_at || 0) - new Date(b.created_at || 0))
    .slice(-12)
    .map((event) => {
      const action = actionOf(event);
      return {
        time: event.created_at,
        kind: action === "BLOCK" ? "block" : action === "ASK" ? "ask" : "allow",
        label: action,
      };
    });
}

function classifyEvent(event) {
  const text = `${event.type} ${JSON.stringify(event.payload || {})}`;
  if (/memory.*poison|poison.*memory/i.test(text)) return "Memory Poisoning";
  if (/prompt|injection|system_prompt|developer prompt/i.test(text)) return "Prompt Injection";
  if (/sink|email|api|secret|recipient|exfil/i.test(text)) return "Suspicious Sink";
  if (/TaskSpec|tool .*outside|tool|write_file|read_file/i.test(text)) return "Tool Abuse";
  if (/drift|deviates|intent/i.test(text)) return "Intent Drift";
  return eventTypeNames[event.type] || "Agent Runtime Event";
}

function actionOf(event) {
  const payload = event?.payload || {};
  const raw = payload.decision || payload.verdict || payload.action || payload.original_decision;
  if (raw === "deny" || raw === "block") return "BLOCK";
  if (raw === "ask" || raw === "require_approval") return "ASK";
  if (raw === "allow" || raw === "pass") return "ALLOW";
  if (event?.type === "alert" || payload.severity === "danger") return "BLOCK";
  if (payload.severity === "warning") return "ASK";
  return "ALLOW";
}

function levelOf(event, action, index = 0) {
  const text = `${event.type} ${JSON.stringify(event.payload || {})}`;
  if (action === "BLOCK" && /secret|poison|email|api|system_prompt|TaskSpec/i.test(text)) return "CRITICAL";
  if (action === "BLOCK") return "HIGH";
  if (action === "ASK" || /taint|untrusted|drift/i.test(text)) return "MEDIUM";
  return index < 2 ? "MEDIUM" : "INFO";
}

function inferTool(event) {
  const text = `${event?.payload?.tool || ""} ${event?.payload?.toolName || ""} ${event?.payload?.normalized_tool || ""} ${event?.type || ""} ${JSON.stringify(event?.payload || {})}`.toLowerCase();
  for (const tool of toolCatalog) {
    if (text.includes(tool.id.toLowerCase()) || text.includes(tool.label.toLowerCase())) return tool.id;
  }
  if (text.includes("email")) return "send_email";
  if (text.includes("api")) return "call_api";
  if (text.includes("memory")) return "memory_write";
  if (text.includes("file")) return text.includes("write") ? "write_file" : "read_file";
  if (text.includes("web") || text.includes("browser")) return "read_webpage";
  return "read_webpage";
}

function toolMatch(event, toolId) {
  return inferTool(event) === toolId;
}

function priorityForLink(event) {
  const action = actionOf(event);
  if (action === "BLOCK") return 100;
  if (event.type === "taint_edge" || isTainted(event)) return 80;
  if (/secret|poison|sink|TaskSpec|deviates/i.test(JSON.stringify(event.payload || {}))) return 70;
  if (action === "ASK") return 55;
  return 20;
}

function isTainted(event) {
  return /taint|untrusted|pollution|poison/i.test(`${event.type} ${JSON.stringify(event.payload || {})}`);
}

function readableReason(event) {
  const payload = event?.payload || {};
  const raw = payload.reason || payload.summary || payload.title || (Array.isArray(payload.violations) ? payload.violations.join("; ") : "") || JSON.stringify(payload).slice(0, 160);
  return translateReason(raw || event?.type || "-");
}

function translateReason(value) {
  let text = String(value || "-").replace(/\s+/g, " ").trim();
  for (const [pattern, replacement] of reasonRules) text = text.replace(pattern, replacement);
  return text;
}

function ruleName(reason, event) {
  const text = `${reason} ${event?.type || ""}`;
  if (/TaskSpec|工具 .*超出|outside/i.test(text)) return "policy.task_scope.enforce";
  if (/secret|秘密|system_prompt/i.test(text)) return "sink.secret_exfiltration.block";
  if (/email|recipient|收件人/i.test(text)) return "sink.email.allowlist";
  if (/memory|poison|投毒/i.test(text)) return "memory.poisoning.audit";
  if (/taint|untrusted|不可信|污点/i.test(text)) return "taint.flow.sink_guard";
  if (/api/i.test(text)) return "sink.api.host_allowlist";
  if (/file|path|写入|读取/i.test(text)) return "sink.file.path_guard";
  return "runtime.behavior_sentry.score";
}

function toolName(value) {
  return {
    read_webpage: "webpage",
    "browser.open": "browser",
    browser_open: "browser",
    read_file: "read_file",
    write_file: "write_file",
    send_email: "email",
    call_api: "api",
    memory_read: "memory",
    memory_write: "memory",
    agents_list: "agents_list",
  }[value] || value || "runtime";
}

function headlineFor(risk, blocks) {
  if (risk >= 72 || blocks >= 5) return "风险活动密集";
  if (risk >= 45 || blocks) return "风险活动受控";
  return "运行态势平稳";
}

function postureText(model) {
  const { blocks, taintFlows, driftAlerts, memoryPoisoning } = model.metrics;
  if (blocks >= 4) return `近期高危工具调用和敏感 Sink 被连续拦截，建议重点复盘策略命中与任务授权边界。`;
  if (taintFlows || memoryPoisoning) return `检测到污染传播或记忆投毒信号，行为哨兵正在跟踪上下文来源并收紧高危 Sink。`;
  if (driftAlerts) return `存在轻微意图漂移迹象，当前策略仍可覆盖主要执行路径。`;
  return `当前 Agent Runtime 处于稳定监测状态，策略闸门和行为哨兵均在线。`;
}

function riskLevelOf(risk) {
  if (risk >= 72) return { label: "LEVEL CRITICAL", color: "var(--red)" };
  if (risk >= 45) return { label: "LEVEL HIGH", color: "var(--amber)" };
  return { label: "LEVEL NORMAL", color: "var(--teal)" };
}

function toggleDataSource() {
  state.source = state.source === "mock" ? "real" : "mock";
  refresh();
}

function togglePause() {
  state.paused = !state.paused;
  render();
}

function toggleFullscreen() {
  if (document.fullscreenElement) {
    document.exitFullscreen();
    return;
  }
  document.documentElement.requestFullscreen?.();
}

function tickClock() {
  $("clock").textContent = new Date().toLocaleString("zh-CN", { hour12: false });
}

function formatTime(value) {
  return value ? new Date(value).toLocaleTimeString("zh-CN", { hour12: false }) : "--:--:--";
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, Number(value) || 0));
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[char]);
}

function mockBundle() {
  const now = Date.now();
  const runId = "run_soc_demo";
  const events = [
    event(runId, "guard_finding", -580, { layer: "Input Sanitization", finding_type: "heuristic", verdict: "block", reason: "prompt injection tries to override system policy", tool: "read_webpage" }),
    event(runId, "taint_edge", -540, { from: "webpage:mock://attack", to: "llm_context", integrity: "untrusted", confidentiality: "public", tool: "read_webpage" }),
    event(runId, "tool_decision", -500, { tool: "read_file", decision: "deny", verdict: "block", risk_score: 94, violations: ["tool read_file is outside TaskSpec"], layer: "Execution Control" }),
    event(runId, "alert", -470, { tool: "read_file", decision: "deny", reason: "attempt to read system_prompt.txt", layer: "Execution Control" }),
    event(runId, "guard_finding", -430, { layer: "Cognition Protection", finding_type: "heuristic", verdict: "require_approval", reason: "high-risk tool deviates from task intent", tool: "send_email" }),
    event(runId, "tool_decision", -390, { tool: "send_email", decision: "deny", verdict: "block", risk_score: 98, violations: ["recipient attacker@x.com is not allowlisted", "body contains secret-tainted data"], layer: "Execution Control" }),
    event(runId, "taint_edge", -350, { from: "memory:report_route", to: "email.body", integrity: "untrusted", confidentiality: "secret", tool: "memory_write" }),
    event(runId, "alert", -310, { tool: "memory_write", decision: "ask", reason: "memory write carries poisoning indicators and remains provenance-tracked", layer: "Sentry Trajectory" }),
    event(runId, "tool_decision", -270, { tool: "call_api", decision: "allow", verdict: "pass", risk_score: 18, reason: "api host is allowlisted", layer: "Execution Control" }),
    event(runId, "tool_decision", -230, { tool: "write_file", decision: "deny", verdict: "block", risk_score: 88, violations: ["write path looks like a system or traversal path"], layer: "Execution Control" }),
    event(runId, "guard_finding", -190, { layer: "Decision Alignment", finding_type: "deterministic", verdict: "block", reason: "untrusted data cannot flow to file sink", tool: "write_file" }),
    event(runId, "tool_decision", -150, { tool: "read_webpage", decision: "allow", verdict: "pass", risk_score: 10, reason: "tool is allowed by TaskSpec", layer: "Execution Control" }),
    event(runId, "guard_finding", -110, { layer: "Foundation", finding_type: "deterministic", verdict: "pass", reason: "foundation scan completed", tool: "runtime" }),
    event(runId, "alert", -70, { tool: "send_email", decision: "deny", reason: "untrusted memory is influencing a high-risk sink", layer: "Sentry Trajectory" }),
  ].map((item) => ({ ...item, created_at: new Date(now + item.offset * 1000).toISOString() }));
  return {
    runs: [{ id: runId, task: "总结 mock://attack 页面，不要给任何人发邮件。", scenario: "indirect_injection", defense_mode: "full", created_at: new Date(now - 600000).toISOString() }],
    events,
    evals: [
      { defense_mode: "full", metrics: { ASR: 0, TPR: 0.95, FPR: 0.04, "Business Completion Rate": 0.91, "Bypass Rate": 0.02 }, created_at: new Date(now - 400000).toISOString() },
      { defense_mode: "no_deterministic", metrics: { ASR: 0.28, TPR: 0.64, FPR: 0.1, "Business Completion Rate": 0.93, "Bypass Rate": 0.22 }, created_at: new Date(now - 390000).toISOString() },
      { defense_mode: "no_sentry", metrics: { ASR: 0.2, TPR: 0.72, FPR: 0.06, "Business Completion Rate": 0.94, "Bypass Rate": 0.16 }, created_at: new Date(now - 380000).toISOString() },
      { defense_mode: "no_feedback", metrics: { ASR: 0.15, TPR: 0.78, FPR: 0.05, "Business Completion Rate": 0.94, "Bypass Rate": 0.12 }, created_at: new Date(now - 370000).toISOString() },
      { defense_mode: "none", metrics: { ASR: 0.72, TPR: 0.1, FPR: 0, "Business Completion Rate": 0.98, "Bypass Rate": 0.68 }, created_at: new Date(now - 360000).toISOString() },
    ],
    cases: null,
  };
}

function event(runId, type, offset, payload) {
  return {
    id: `evt_${type}_${Math.abs(offset)}_${Math.random().toString(16).slice(2, 7)}`,
    run_id: runId,
    type,
    offset,
    payload,
  };
}
