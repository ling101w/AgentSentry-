export const ALL_SESSIONS = "__all__";

const PING_TEXT = /连通性测试/;
const NO_TOOLS_TEXT = /不要调用任何工具/;
const OFFICE_TEXT = /standup-2026-08-20|站会纪要/;

export function canonicalSessionKey(value) {
  return String(value || "unknown")
    .replace(/#[0-9a-f]{8,64}$/i, "")
    .replace(/^agent:main:/, "");
}

export function sessionKeysMatch(left, right) {
  if (!left || !right) return false;
  if (left === right) return true;
  return canonicalSessionKey(left) === canonicalSessionKey(right);
}

export function isCommandLabLlmRecord(record) {
  const payload = record?.payload || {};
  return payload.source === "command-lab-llm"
    || /command-lab-llm/.test(String(record?.session_key || ""))
    || /openclaw llm test/i.test(String(record?.title || ""));
}

export function isOpenClawLlmPingRecord(record) {
  const payload = record?.payload || {};
  if (payload.scenario === "openclaw_llm_ping") return true;
  const text = `${payload.command || ""} ${payload.preview || ""} ${record?.summary || ""}`;
  return PING_TEXT.test(text) && NO_TOOLS_TEXT.test(text);
}

export function isOpenClawLlmOfficeRecord(record) {
  const payload = record?.payload || {};
  if (payload.scenario === "openclaw_llm_office") return true;
  const text = `${payload.command || ""} ${payload.preview || ""} ${record?.summary || ""}`;
  return OFFICE_TEXT.test(text) && payload.source === "command-lab-llm";
}

export function isFoundationNoiseRecord(record) {
  const payload = record?.payload || {};
  if (record?.type === "foundation_scan" && !payload.__collapsed) return false;
  if (record?.type === "provenance_scan" && !payload.__collapsed) return false;
  if (payload.foundation_scan || payload.__collapsed) return true;
  if (payload.scanRoot || payload.scan_root) return true;
  if (record?.type === "skill_context_annotation") return true;
  if (record?.type === "alert" && /provenance scan|工作区溯源扫描/i.test(`${record.title || ""}${record.summary || ""}`)) return true;
  if (record?.type === "guard_finding" && /初始化防线/.test(`${record.title || ""}${record.summary || ""}`)) return true;
  const inventoryPath = String(payload.evidence?.path || payload.path || "");
  if (record?.type === "guard_finding" && /src\/main|META-INF|apache-dubbo|\/nacos\/|\/mall\//i.test(inventoryPath)) return true;
  return false;
}

export function collapseFoundationFindings(records) {
  const list = Array.isArray(records) ? records : [];
  const noiseBySession = new Map();
  for (const record of list) {
    if (!isFoundationNoiseRecord(record)) continue;
    const key = canonicalSessionKey(record.session_key || record.run_id || "");
    const bucket = noiseBySession.get(key) || [];
    bucket.push(record);
    noiseBySession.set(key, bucket);
  }
  const emitted = new Set();
  const collapsed = [];
  for (const record of list) {
    if (!isFoundationNoiseRecord(record)) {
      collapsed.push(record);
      continue;
    }
    const key = canonicalSessionKey(record.session_key || record.run_id || "");
    if (emitted.has(key)) continue;
    emitted.add(key);
    collapsed.push(summarizeFoundationNoise(noiseBySession.get(key) || [record]));
  }
  return collapsed;
}

function summarizeFoundationNoise(bucket) {
  const sample = bucket[0];
  const reasons = [...new Set(bucket.map((record) => String(record.title || record.summary || "").trim()).filter(Boolean))];
  return {
    ...sample,
    id: `${sample.id}__foundation_collapsed`,
    type: "guard_finding",
    title: "工作区盘点发现（已折叠）",
    summary: `${bucket.length} 条工作区盘点未逐条展开。完整结果见「初始化防线 / 溯源扫描」汇总。${reasons.slice(0, 2).join("；")}`,
    payload: {
      ...(sample.payload || {}),
      collapsed_count: bucket.length,
      __collapsed: true,
      foundation_scan: true,
    },
  };
}

export function inferLabScenario(records, fallback = "manual") {
  const list = Array.isArray(records) ? records : [];
  const fromPayload = list.map((record) => record?.payload?.scenario).find((value) => String(value || "").trim());
  if (fromPayload) return String(fromPayload);
  if (list.some(isOpenClawLlmOfficeRecord)) return "openclaw_llm_office";
  if (list.some(isOpenClawLlmPingRecord)) return "openclaw_llm_ping";
  if (list.some(isCommandLabLlmRecord)) return "openclaw_llm_followup";
  return fallback;
}

const SINK_RANK = {
  send_email: 100,
  shell_exec: 95,
  delete_email: 90,
  call_api: 85,
  delete_file: 80,
  memory_write: 70,
  write_file: 55,
  read_file: 20,
};

const INTERVENTION_LABELS = {
  "risk-based": "风险驱动",
  "evidence-gated": "证据门控",
};

const EVIDENCE_CLASS_LABELS = {
  risk_only: "仅风险、无攻击证据",
  attack_signal: "攻击信号",
  confirmed_attack: "已确认攻击",
  safety_boundary: "安全边界",
};

function decisionValue(record) {
  const payload = record?.payload || {};
  return String(payload.decision || payload.verdict || payload.original_decision || "").toLowerCase();
}

function interventionOf(record) {
  const payload = record?.payload || {};
  return payload.intervention && typeof payload.intervention === "object" ? payload.intervention : null;
}

function sinkRank(record) {
  const payload = record?.payload || {};
  const tool = String(payload.normalized_tool || payload.toolName || "");
  return SINK_RANK[tool] || 0;
}

function pickToolDecision(toolDecisions) {
  const deny = toolDecisions.find((record) => /deny|block/.test(decisionValue(record)));
  if (deny) return deny;
  const ask = toolDecisions.find((record) => decisionValue(record) === "ask");
  if (ask) return ask;
  const overridden = toolDecisions.filter((record) => Boolean(interventionOf(record)?.overridden));
  const ranked = (overridden.length ? overridden : toolDecisions)
    .slice()
    .sort((left, right) => sinkRank(right) - sinkRank(left));
  return ranked[0] || null;
}

function policyDecisionOf(record) {
  const intervention = interventionOf(record);
  return String(intervention?.raw_decision || decisionValue(record) || "").toLowerCase();
}

function interventionFields(record) {
  const intervention = interventionOf(record);
  const mode = String(intervention?.mode || "").trim();
  const policyDecision = policyDecisionOf(record);
  const finalDecision = decisionValue(record);
  const overridden = Boolean(intervention?.overridden);
  const evidenceClass = String(intervention?.evidence_class || "");
  let gateNote = "按风险阈值裁决";
  if (mode === "evidence-gated" && overridden) {
    gateNote = `证据门控覆盖：风险${policyDecision} → ${finalDecision}`;
  } else if (mode === "evidence-gated") {
    gateNote = EVIDENCE_CLASS_LABELS[evidenceClass] || "证据门控维持";
  }
  return {
    interventionMode: mode,
    interventionLabel: INTERVENTION_LABELS[mode] || mode || "—",
    policyDecision,
    overridden,
    evidenceClass,
    evidenceClassLabel: EVIDENCE_CLASS_LABELS[evidenceClass] || "",
    gateNote,
  };
}

function searchablePolicyText(record) {
  const payload = record?.payload || {};
  return [
    record?.title,
    record?.summary,
    payload.reason,
    ...(Array.isArray(payload.violations) ? payload.violations : []),
    ...(Array.isArray(payload.reasons) ? payload.reasons : []),
  ].join(" ").toLowerCase();
}

export function summarizeLabVerdict(records, options = {}) {
  const list = Array.isArray(records) ? records : [];
  const request = list.filter((record) => !isFoundationNoiseRecord(record));
  const scenarioKey = inferLabScenario(request, options.fallbackScenario || "manual");
  const scenario = options.scenarioDefaults?.[scenarioKey] || {};
  const toolDecisions = request.filter((record) => record.type === "tool_decision" || record.type === "approval_request");
  const decisionRecord = pickToolDecision(toolDecisions);
  const ping = scenarioKey === "openclaw_llm_ping" || request.some(isOpenClawLlmPingRecord);
  const office = scenarioKey === "openclaw_llm_office" || request.some(isOpenClawLlmOfficeRecord);
  const llm = ping || office || request.some(isCommandLabLlmRecord);
  const replied = request.some((record) => record.payload?.phase === "replied"
    || (record.type === "message_write" && record.payload?.role === "assistant"));
  const failed = request.some((record) => record.payload?.phase === "failed");
  const targetFallback = String(options.targetValue || "").trim() || "由业务链路确定";

  if (decisionRecord) {
    const rawDecision = decisionValue(decisionRecord) || "info";
    const payload = decisionRecord.payload || {};
    const policyHit = /outside taskspec|lacks explicit capability|intent does not allow/.test(searchablePolicyText(decisionRecord));
    const enforcementAction = String(payload.enforcement_action || "");
    const intercepted = enforcementAction === "block";
    const awaiting = enforcementAction === "require_approval";
    const observedRisk = !enforcementAction
      ? false
      : /deny|block|ask/.test(rawDecision) && !intercepted && !awaiting;
    return {
      scenarioKey,
      taskLabel: scenario.label || "手动请求",
      authorizationText: policyHit ? "超出 TaskSpec" : rawDecision === "allow" ? "边界内授权" : "执行前裁决",
      tool: payload.normalized_tool || payload.toolName || scenario.tool || "自动识别",
      target: targetFallback,
      rawDecision,
      verdict: intercepted ? "deny" : awaiting ? "ask" : observedRisk && /deny|block/.test(rawDecision) ? "observed-deny" : rawDecision,
      tone: intercepted || (!enforcementAction && /deny|block/.test(rawDecision))
        ? "danger"
        : awaiting || observedRisk || rawDecision === "ask"
          ? "warning"
          : "success",
      ...interventionFields(decisionRecord),
    };
  }

  if (llm) {
    const rawDecision = failed ? "warning" : replied ? "allow" : "pending";
    return {
      scenarioKey,
      taskLabel: scenario.label || (office ? "真实 LLM：日常办公" : ping ? "真实 LLM：连通性测试" : "真实 LLM 请求"),
      authorizationText: office ? "等待模型自行选工具" : "无工具调用",
      tool: "未调用",
      target: office ? "工作区 notes" : ping ? "连通性确认" : targetFallback,
      rawDecision,
      verdict: failed ? "发送失败" : replied ? "已回复" : "等待回复",
      tone: failed ? "danger" : replied ? "success" : "warning",
      interventionMode: "",
      interventionLabel: "—",
      policyDecision: "",
      overridden: false,
      evidenceClass: "",
      evidenceClassLabel: "",
      gateNote: "",
    };
  }

  return {
    scenarioKey,
    taskLabel: scenario.label || "手动请求",
    authorizationText: "等待证据",
    tool: scenario.tool || "自动识别",
    target: targetFallback,
    rawDecision: "pending",
    verdict: "等待运行",
    tone: "success",
    interventionMode: "",
    interventionLabel: "—",
    policyDecision: "",
    overridden: false,
    evidenceClass: "",
    evidenceClassLabel: "",
    gateNote: "",
  };
}
