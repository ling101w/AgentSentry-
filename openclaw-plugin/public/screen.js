import * as THREE from "/vendor/three.module.js";

const state = {
  records: [],
  stats: {},
  model: null,
  sceneReady: false,
};

const severityNames = {
  danger: "高危",
  warning: "警告",
  success: "通过",
  info: "信息",
};

const severityColors = {
  danger: 0xff5a52,
  warning: 0xffc04d,
  success: 0x62d982,
  info: 0x20d0b5,
};

const layerNames = {
  Foundation: "基础扫描",
  "LLM Input": "模型输入",
  "Message Write": "消息",
  "Execution Control": "执行控制",
  "Tool Result": "工具结果",
  Runtime: "运行时",
};

const typeNames = {
  session_start: "会话开始",
  foundation_scan: "基础扫描",
  llm_input: "模型输入",
  message_write: "消息写入",
  tool_decision: "工具裁决",
  tool_result: "工具结果",
  guard_finding: "防护发现",
  alert: "告警",
  runtime: "运行时",
};

const toolNames = {
  agents_list: "列出 Agent",
  read_webpage: "读取网页",
  call_api: "调用 API",
  read_file: "读取文件",
  write_file: "写入文件",
  send_email: "发送邮件",
  shell_exec: "执行命令",
};

const stageDefs = [
  ["Foundation", "基础扫描"],
  ["LLM Input", "模型输入"],
  ["Message Write", "消息"],
  ["Execution Control", "工具裁决"],
  ["Tool Result", "工具结果"],
  ["Runtime", "运行时"],
];

const flowDefs = [
  ["Foundation", "基础面"],
  ["LLM Input", "模型面"],
  ["Message Write", "消息面"],
  ["Execution Control", "执行面"],
  ["Tool Result", "工具面"],
  ["alert", "告警面"],
];

const $ = (id) => document.getElementById(id);

const sceneState = {
  renderer: null,
  scene: null,
  camera: null,
  root: new THREE.Group(),
  dynamic: new THREE.Group(),
  rings: new THREE.Group(),
  stars: null,
  clock: new THREE.Clock(),
  materials: {},
};

initScene();
tickClock();
setInterval(tickClock, 1000);
await refreshData();
setInterval(refreshData, 5000);
animate();

function initScene() {
  const canvas = $("threatScene");
  const renderer = new THREE.WebGLRenderer({
    canvas,
    antialias: true,
    alpha: true,
    preserveDrawingBuffer: true,
    powerPreference: "high-performance",
  });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setClearColor(0x000000, 0);

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x071012, 0.032);

  const camera = new THREE.PerspectiveCamera(46, window.innerWidth / window.innerHeight, 0.1, 120);
  camera.position.set(0, 7.8, 16.6);
  camera.lookAt(0, 0, 0);

  sceneState.renderer = renderer;
  sceneState.scene = scene;
  sceneState.camera = camera;
  sceneState.materials = createMaterials();

  scene.add(new THREE.AmbientLight(0x7deee0, 0.42));
  const key = new THREE.DirectionalLight(0xffffff, 1.6);
  key.position.set(8, 12, 10);
  scene.add(key);
  const rim = new THREE.PointLight(0xa98dff, 80, 36);
  rim.position.set(-8, 6, -10);
  scene.add(rim);

  scene.add(sceneState.root);
  sceneState.root.add(sceneState.rings);
  sceneState.root.add(sceneState.dynamic);
  sceneState.stars = createStarField();
  scene.add(sceneState.stars);
  buildStaticWorld();

  window.addEventListener("resize", resizeScene);
  resizeScene();
  state.sceneReady = true;
}

function createMaterials() {
  return {
    grid: new THREE.LineBasicMaterial({ color: 0x2d7770, transparent: true, opacity: 0.22 }),
    ring: new THREE.LineBasicMaterial({ color: 0x20d0b5, transparent: true, opacity: 0.34 }),
    ringHot: new THREE.LineBasicMaterial({ color: 0xffc04d, transparent: true, opacity: 0.48 }),
    link: new THREE.LineBasicMaterial({ color: 0x5debd3, transparent: true, opacity: 0.26 }),
    lane: new THREE.LineBasicMaterial({ color: 0x68c7ff, transparent: true, opacity: 0.2 }),
    spoke: new THREE.LineBasicMaterial({ color: 0x22dec6, transparent: true, opacity: 0.16 }),
    beam: new THREE.MeshBasicMaterial({ color: 0x22dec6, transparent: true, opacity: 0.11, depthWrite: false, side: THREE.DoubleSide }),
    danger: new THREE.MeshStandardMaterial({ color: severityColors.danger, emissive: severityColors.danger, emissiveIntensity: 0.72, roughness: 0.35 }),
    warning: new THREE.MeshStandardMaterial({ color: severityColors.warning, emissive: severityColors.warning, emissiveIntensity: 0.42, roughness: 0.38 }),
    success: new THREE.MeshStandardMaterial({ color: severityColors.success, emissive: severityColors.success, emissiveIntensity: 0.35, roughness: 0.42 }),
    info: new THREE.MeshStandardMaterial({ color: severityColors.info, emissive: severityColors.info, emissiveIntensity: 0.34, roughness: 0.42 }),
    core: new THREE.MeshStandardMaterial({ color: 0xeef7f4, emissive: 0x20d0b5, emissiveIntensity: 0.42, metalness: 0.2, roughness: 0.25 }),
    ghost: new THREE.MeshBasicMaterial({ color: 0x20d0b5, transparent: true, opacity: 0.12, wireframe: true }),
    orbit: new THREE.MeshBasicMaterial({ color: 0x68c7ff, transparent: true, opacity: 0.18, wireframe: true }),
  };
}

function buildStaticWorld() {
  const grid = new THREE.GridHelper(30, 30, 0x20d0b5, 0x21484a);
  grid.position.y = -2.3;
  grid.material.transparent = true;
  grid.material.opacity = 0.22;
  sceneState.root.add(grid);

  const ringRadii = [3.2, 5.5, 7.8, 10.2];
  for (const radius of ringRadii) {
    const curve = new THREE.EllipseCurve(0, 0, radius, radius, 0, Math.PI * 2);
    const points = curve.getPoints(160).map((point) => new THREE.Vector3(point.x, 0, point.y));
    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    const line = new THREE.LineLoop(geometry, radius > 7 ? sceneState.materials.ringHot : sceneState.materials.ring);
    line.rotation.x = 0.02;
    sceneState.rings.add(line);
  }

  const beam = new THREE.Mesh(new THREE.CircleGeometry(10.6, 96, 0, Math.PI * 0.3), sceneState.materials.beam);
  beam.name = "radarBeam";
  beam.rotation.x = -Math.PI / 2;
  beam.position.y = -2.18;
  sceneState.root.add(beam);

  const spokePoints = [];
  for (let i = 0; i < stageDefs.length; i += 1) {
    const angle = (i / stageDefs.length) * Math.PI * 2;
    spokePoints.push(new THREE.Vector3(0, -2.12, 0), new THREE.Vector3(Math.cos(angle) * 11.4, -2.12, Math.sin(angle) * 11.4));
  }
  const spokes = new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(spokePoints), sceneState.materials.spoke);
  spokes.name = "spokes";
  sceneState.root.add(spokes);

  for (let i = 0; i < stageDefs.length; i += 1) {
    const angle = (i / stageDefs.length) * Math.PI * 2 + Math.PI / 7;
    const start = new THREE.Vector3(Math.cos(angle) * 10.2, -1.2, Math.sin(angle) * 10.2);
    const mid = new THREE.Vector3(Math.cos(angle) * 5.2, 1.4 + (i % 2) * 0.9, Math.sin(angle) * 5.2);
    const end = new THREE.Vector3(0, 0.12, 0);
    const curve = new THREE.CatmullRomCurve3([start, mid, end]);
    const lane = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(42)), sceneState.materials.lane);
    lane.name = "dataLane";
    sceneState.root.add(lane);
  }

  const core = new THREE.Mesh(new THREE.IcosahedronGeometry(1.0, 2), sceneState.materials.core);
  core.name = "core";
  sceneState.dynamic.add(core);

  const ghost = new THREE.Mesh(new THREE.IcosahedronGeometry(2.05, 1), sceneState.materials.ghost);
  ghost.name = "coreGhost";
  sceneState.dynamic.add(ghost);

  const orbitAngles = [0, Math.PI / 2.8, Math.PI / 1.8];
  orbitAngles.forEach((angle, index) => {
    const orbit = new THREE.Mesh(new THREE.TorusGeometry(1.65 + index * 0.34, 0.012, 8, 168), sceneState.materials.orbit);
    orbit.name = `coreOrbit-${index}`;
    orbit.rotation.x = Math.PI / 2 + angle;
    orbit.rotation.y = angle * 0.5;
    sceneState.dynamic.add(orbit);
  });
}

function createStarField() {
  const count = 900;
  const positions = new Float32Array(count * 3);
  for (let i = 0; i < count; i += 1) {
    const radius = 24 + Math.random() * 42;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    positions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
    positions[i * 3 + 1] = radius * Math.cos(phi) * 0.45 + 5;
    positions[i * 3 + 2] = radius * Math.sin(phi) * Math.sin(theta);
  }
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  const material = new THREE.PointsMaterial({ color: 0x8deee2, size: 0.035, transparent: true, opacity: 0.38 });
  return new THREE.Points(geometry, material);
}

async function refreshData() {
  try {
    const [recordsResponse, statsResponse] = await Promise.all([
      fetch("/api/records?limit=2000").then((res) => res.json()),
      fetch("/api/stats").then((res) => res.json()),
    ]);
    state.records = recordsResponse.records || [];
    state.stats = statsResponse || {};
    state.model = buildModel(state.records, state.stats);
    $("health").textContent = "实时连接";
    $("health").className = "live-pill ok";
    renderHud();
    updateSceneData();
  } catch {
    $("health").textContent = "连接异常";
    $("health").className = "live-pill bad";
  }
}

function buildModel(records, stats) {
  const severity = stats.bySeverity || countBy(records, (record) => record.severity);
  const byLayer = countBy(records, (record) => record.layer || "Unknown");
  const alerts = records.filter((record) => record.type === "alert");
  const toolDecisions = records.filter((record) => record.type === "tool_decision");
  const blockedTools = toolDecisions.filter(isBlocked);
  const hardcodedSecrets = records.filter((record) => /hardcoded secret/i.test(recordReason(record)));
  const timeouts = records.filter((record) => searchableText(record).includes("timeout") || searchableText(record).includes("timed out"));
  const sessions = buildSessions(records);
  const riskScore = Math.min(
    100,
    Math.round(
      (severity.danger || 0) * 2.6
      + Math.min(severity.warning || 0, 80) * 0.42
      + alerts.length * 3.8
      + blockedTools.length * 3
      + hardcodedSecrets.length * 4.5
      + timeouts.length * 1.5,
    ),
  );

  return {
    total: stats.total || records.length,
    sessions,
    severity,
    byLayer,
    alerts,
    toolDecisions,
    blockedTools,
    hardcodedSecrets,
    timeouts,
    riskScore,
    posture: postureFor(riskScore, alerts.length, blockedTools.length),
    stages: stageDefs.map(([key, label]) => ({ key, label, count: key === "Runtime" ? records.filter((record) => record.type === "runtime").length : byLayer[key] || 0 })),
    flow: flowDefs.map(([key, label]) => ({
      key,
      label,
      count: key === "alert" ? alerts.length : byLayer[key] || 0,
      tone: key === "alert" && alerts.length ? "danger" : key === "Foundation" && hardcodedSecrets.length ? "warn" : "",
    })),
    sceneEvents: records.slice(0, 180),
  };
}

function renderHud() {
  const model = state.model;
  if (!model) return;
  $("kpiRow").innerHTML = [
    kpi("总事件", model.total, "条记录"),
    kpi("会话", model.sessions.length, "个会话"),
    kpi("高危", model.severity.danger || 0, "高风险", "danger"),
    kpi("警告", model.severity.warning || 0, "需关注", "warning"),
    kpi("工具裁决", model.toolDecisions.length, "次决策"),
    kpi("阻断", model.blockedTools.length, "已拦截", "danger"),
    kpi("硬编码敏感值", model.hardcodedSecrets.length, "配置风险", "warning"),
    kpi("超时", model.timeouts.length, "异常等待"),
  ].join("");

  $("postureLabel").textContent = model.posture.label;
  $("postureText").textContent = model.posture.text;
  $("riskScore").textContent = model.riskScore;
  $("sceneHeadline").textContent = model.posture.headline;
  renderStages(model);
  renderFlow(model);
  renderAlerts(model);
  renderSessions(model);
  renderTools(model);
  renderLatest(model);
}

function kpi(label, value, caption, tone = "") {
  return `<article class="kpi ${tone}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><em>${escapeHtml(caption)}</em></article>`;
}

function renderStages(model) {
  const max = Math.max(...model.stages.map((item) => item.count), 1);
  $("stageTotal").textContent = model.stages.reduce((sum, item) => sum + item.count, 0);
  $("stageFlow").innerHTML = model.stages.map((item) => metricRow(item.label, item.count, max)).join("");
}

function metricRow(label, value, max) {
  const width = Math.max(4, Math.round((Number(value) / Math.max(max, 1)) * 100));
  return `
    <div class="stage-row">
      <div class="row-head"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>
      <div class="bar-track"><i class="bar-fill" style="width:${width}%"></i></div>
    </div>
  `;
}

function renderFlow(model) {
  $("flowSummary").textContent = `${model.flow.reduce((sum, item) => sum + item.count, 0)} 个阶段事件`;
  $("attackFlow").innerHTML = model.flow
    .map((item) => `<article class="flow-node ${item.count ? `active ${item.tone}` : ""}"><span>${escapeHtml(item.label)}</span><strong>${escapeHtml(item.count)}</strong></article>`)
    .join("");
}

function renderAlerts(model) {
  $("alertTotal").textContent = model.alerts.length;
  const items = model.alerts.length ? model.alerts : state.records.filter((record) => record.severity === "danger").slice(0, 8);
  $("alertStream").innerHTML = items.length ? items.slice(0, 7).map((record) => eventRow(record)).join("") : '<div class="empty">暂无高优先级事件</div>';
}

function renderSessions(model) {
  $("sessionHotTotal").textContent = model.sessions.length;
  $("sessionHeat").innerHTML = model.sessions.length ? model.sessions.slice(0, 7).map(sessionRow).join("") : '<div class="empty">暂无会话</div>';
}

function renderTools(model) {
  const allow = model.toolDecisions.filter((record) => record.payload?.decision === "allow").length;
  const ask = model.toolDecisions.filter((record) => record.payload?.decision === "ask").length;
  const deny = model.blockedTools.length;
  const results = state.records.filter((record) => record.type === "tool_result").length;
  $("toolTotal").textContent = model.toolDecisions.length;
  $("toolGrid").innerHTML = [
    toolCell("允许", allow),
    toolCell("待确认", ask),
    toolCell("阻断", deny),
    toolCell("结果", results),
  ].join("");
}

function renderLatest(model) {
  const important = state.records.filter((record) => record.severity === "danger" || record.type === "alert" || record.type === "tool_decision" || /hardcoded secret/i.test(recordReason(record)));
  $("latestCount").textContent = important.length;
  $("latestEvents").innerHTML = important.length ? important.slice(0, 5).map((record) => eventRow(record)).join("") : '<div class="empty">暂无关键事件</div>';
}

function toolCell(label, value) {
  return `<article class="tool-cell"><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></article>`;
}

function eventRow(record) {
  return `
    <article class="event-row ${escapeHtml(record.severity || "")}">
      <strong>${escapeHtml(titleText(record))}</strong>
      <span>${escapeHtml(formatTime(record.created_at))} · ${escapeHtml(layerNames[record.layer] || record.layer || typeNames[record.type] || record.type)}</span>
      <span>${escapeHtml(summaryText(record))}</span>
    </article>
  `;
}

function sessionRow(session) {
  const tone = session.risk >= 60 ? "danger" : session.risk >= 25 ? "warning" : "";
  return `
    <article class="session-row">
      <div>
        <strong>${escapeHtml(compactSession(session.key))}</strong>
        <span>${escapeHtml(formatTime(session.latest))} · ${session.count} 事件 · ${session.tools} 工具 · ${session.alerts} 告警</span>
      </div>
      <span class="session-risk ${tone}">${session.risk}</span>
    </article>
  `;
}

function updateSceneData() {
  if (!state.sceneReady || !state.model) return;
  const group = sceneState.dynamic;
  for (const child of group.children.slice()) {
    if (child.name === "core" || child.name === "coreGhost") continue;
    group.remove(child);
    child.geometry?.dispose?.();
  }

  const events = state.model.sceneEvents;
  const nodeGeometry = new THREE.SphereGeometry(0.08, 16, 16);
  const linkPoints = [];
  events.forEach((record, index) => {
    const position = eventPosition(record, index, events.length);
    const material = sceneState.materials[record.severity] || sceneState.materials.info;
    const size = record.severity === "danger" ? 2.1 : record.severity === "warning" ? 1.45 : 1;
    const mesh = new THREE.Mesh(nodeGeometry.clone(), material);
    mesh.position.copy(position);
    mesh.scale.setScalar(size);
    mesh.userData = { pulse: Math.random() * Math.PI * 2, severity: record.severity };
    group.add(mesh);

    if (index < 42 || record.severity === "danger") {
      linkPoints.push(new THREE.Vector3(0, 0, 0), position.clone());
    }
  });

  if (linkPoints.length) {
    const lineGeometry = new THREE.BufferGeometry().setFromPoints(linkPoints);
    const links = new THREE.LineSegments(lineGeometry, sceneState.materials.link);
    links.name = "links";
    group.add(links);
  }
}

function eventPosition(record, index, total) {
  const foundLayer = stageDefs.findIndex(([key]) => key === record.layer);
  const sector = foundLayer >= 0 ? foundLayer : hash(record.type || "") % stageDefs.length;
  const sectorWidth = (Math.PI * 2) / stageDefs.length;
  const jitter = (((hash(`${record.id || index}:angle`) % 1000) / 1000) - 0.5) * sectorWidth * 0.78;
  const sessionDrift = (((hash(record.session_key || "") % 1000) / 1000) - 0.5) * 0.42;
  const angle = -Math.PI / 2 + sector * sectorWidth + jitter + sessionDrift;
  const recency = 1 - index / Math.max(total, 1);
  const radius = 2.4 + recency * 7.4 + (hash(record.session_key || "") % 130) / 110;
  const y = -1.25 + (hash(`${record.id || index}:y`) % 260) / 120 - 0.45 + severityLift(record.severity);
  return new THREE.Vector3(Math.cos(angle) * radius, y, Math.sin(angle) * radius);
}

function severityLift(severity) {
  return { danger: 1.6, warning: 0.65, success: 0.2, info: 0 }[severity] || 0;
}

function animate() {
  const delta = sceneState.clock.getDelta();
  const elapsed = sceneState.clock.elapsedTime;
  if (sceneState.renderer && sceneState.scene && sceneState.camera) {
    sceneState.root.rotation.y += delta * 0.055;
    sceneState.rings.rotation.y -= delta * 0.035;
    sceneState.stars.rotation.y += delta * 0.006;
    const radarBeam = sceneState.root.getObjectByName("radarBeam");
    if (radarBeam) radarBeam.rotation.z -= delta * 0.38;
    for (const child of sceneState.dynamic.children) {
      if (child.userData?.pulse !== undefined) {
        const pulse = 1 + Math.sin(elapsed * 2.4 + child.userData.pulse) * 0.16;
        const base = child.userData.severity === "danger" ? 2.1 : child.userData.severity === "warning" ? 1.45 : 1;
        child.scale.setScalar(base * pulse);
      }
      if (child.name === "core" || child.name === "coreGhost") {
        child.rotation.x += delta * 0.18;
        child.rotation.y += delta * 0.26;
      }
      if (child.name?.startsWith("coreOrbit")) {
        child.rotation.z += delta * 0.22;
        child.rotation.y += delta * 0.1;
      }
    }
    sceneState.renderer.render(sceneState.scene, sceneState.camera);
  }
  requestAnimationFrame(animate);
}

function resizeScene() {
  const renderer = sceneState.renderer;
  const camera = sceneState.camera;
  if (!renderer || !camera) return;
  const width = window.innerWidth;
  const height = window.innerHeight;
  renderer.setSize(width, height, false);
  camera.aspect = width / height;
  camera.position.z = width < 900 ? 24 : 16.6;
  camera.position.y = width < 900 ? 10.5 : 7.8;
  camera.updateProjectionMatrix();
}

function buildSessions(records) {
  const map = new Map();
  for (const record of records) {
    const key = record.session_key || "session_unknown";
    const item = map.get(key) || { key, count: 0, latest: record.created_at, danger: 0, warning: 0, alerts: 0, tools: 0, risk: 0 };
    item.count += 1;
    if (new Date(record.created_at) > new Date(item.latest)) item.latest = record.created_at;
    if (record.severity === "danger") item.danger += 1;
    if (record.severity === "warning") item.warning += 1;
    if (record.type === "alert") item.alerts += 1;
    if (record.type === "tool_decision" || record.type === "tool_result") item.tools += 1;
    map.set(key, item);
  }
  return Array.from(map.values())
    .map((item) => ({ ...item, risk: Math.min(99, item.danger * 18 + item.alerts * 16 + item.tools * 5 + Math.min(item.warning, 12) * 2) }))
    .sort((a, b) => b.risk - a.risk || new Date(b.latest) - new Date(a.latest));
}

function postureFor(score, alerts, blocked) {
  if (score >= 75 || alerts >= 4 || blocked >= 6) {
    return { label: "强防护", headline: "高风险活动密集", text: "近期存在多次高风险或阻断事件，建议优先复盘工具调用和任务规范。" };
  }
  if (score >= 38 || alerts || blocked) {
    return { label: "重点监控", headline: "风险可控但需关注", text: "基础扫描和工具治理均有有效信号，建议保留审计并观察后续会话。" };
  }
  return { label: "平稳运行", headline: "运行态势平稳", text: "当前未发现显著高危行为，保持实时观测即可。" };
}

function titleText(record) {
  return translateText(record.title || typeNames[record.type] || record.type || "");
}

function summaryText(record) {
  const payload = record.payload || {};
  if (record.type === "tool_decision") {
    const tool = displayTool(payload.toolName || payload.normalized_tool || "tool");
    const reason = (payload.violations || []).join("; ") || payload.summary || record.summary || "";
    return `${tool} · ${translateText(reason)}`;
  }
  if (record.type === "message_write") return previewText(payload.preview) || translateText(record.summary || "");
  return translateText(record.summary || payload.summary || recordReason(record) || "");
}

function previewText(value) {
  if (!value) return "";
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) {
      return parsed.map((item) => item.type === "toolCall" ? `调用工具 ${displayTool(item.name)}` : item.text || item.type || "").filter(Boolean).join(" ");
    }
  } catch {
    return translateText(value);
  }
  return translateText(value);
}

function translateText(value) {
  return compactText(value)
    .replace(/configuration contains hardcoded secret values/gi, "配置文件包含硬编码敏感值")
    .replace(/configuration appears to contain embedded secrets/gi, "配置文件疑似包含内嵌密钥")
    .replace(/workspace file appears to contain embedded secrets/gi, "工作区文件疑似包含内嵌密钥")
    .replace(/tool ([\w.-]+) is outside TaskSpec/gi, (_, tool) => `工具 ${displayTool(tool)} 超出任务规范`)
    .replace(/OpenClaw prompt build/gi, "OpenClaw 提示词构建")
    .replace(/LLM input prepared/gi, "模型输入已准备")
    .replace(/Message write: user/gi, "写入用户消息")
    .replace(/Message write: assistant/gi, "写入助手消息")
    .replace(/High-risk tool call: ([\w.-]+)/gi, (_, tool) => `高风险工具调用：${displayTool(tool)}`)
    .replace(/Foundation scan completed/gi, "基础扫描完成");
}

function displayTool(value) {
  const key = String(value || "").trim();
  return toolNames[key] || key || "-";
}

function recordReason(record) {
  return String(record.payload?.reason || record.summary || record.title || "");
}

function isBlocked(record) {
  const payload = record.payload || {};
  return record.severity === "danger" || payload.verdict === "block" || payload.decision === "deny" || payload.original_decision === "deny";
}

function searchableText(record) {
  return `${record.title} ${record.summary} ${record.type} ${record.layer} ${record.session_key} ${JSON.stringify(record.payload)}`.toLowerCase();
}

function countBy(items, getKey) {
  return items.reduce((acc, item) => {
    const key = getKey(item);
    if (key) acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function compactSession(value) {
  const text = String(value || "-").replace(/^agent:main:/, "");
  return text.length > 30 ? `${text.slice(0, 20)}...${text.slice(-7)}` : text;
}

function compactText(value, max = 132) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function formatTime(value) {
  return value ? new Date(value).toLocaleTimeString("zh-CN", { hour12: false }) : "-";
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[char]);
}

function hash(value) {
  let out = 0;
  for (let i = 0; i < value.length; i += 1) out = (out * 31 + value.charCodeAt(i)) >>> 0;
  return out;
}

function tickClock() {
  $("clock").textContent = new Date().toLocaleString("zh-CN", { hour12: false });
}
