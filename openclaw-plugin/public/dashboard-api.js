const RESOURCE_REQUESTS = {
  overview: "/api/security/overview?limit=1000",
  records: "/api/records?limit=2000",
  enforcement: "/api/settings/enforcement",
  policy: "/api/policy/config",
  tools: "/api/tools/manifests",
  mcp: "/api/mcp/servers",
  skills: "/api/skills/inventory",
  memory: "/api/memory/inventory",
  windowMetrics: "/api/dashboard/metrics?limit=5000",
  alerts: "/api/security/alerts?page=1&pageSize=100",
  stats: "/api/stats?limit=5000",
  health: "/api/health",
  checkpoints: "/api/checkpoints?limit=100",
  dashboardSettings: "/api/settings/dashboard",
  notifications: "/api/settings/notifications",
  auditIntegrity: "/api/audit/integrity?limit=2000",
};

const DEFAULT_TIMEOUT_MS = 8000;

export async function fetchJson(path, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeoutMs || DEFAULT_TIMEOUT_MS);
  try {
    const response = await fetch(path, {
      cache: "no-store",
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.headers || {}),
      },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload?.ok === false) {
      throw new Error(payload?.error || `${path} ${response.status}`);
    }
    return payload;
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function loadDashboardData() {
  const entries = Object.entries(RESOURCE_REQUESTS);
  const settled = await Promise.allSettled(entries.map(([, path]) => fetchJson(path)));
  const resources = {};
  const availability = {};
  const errors = {};

  settled.forEach((result, index) => {
    const [key, path] = entries[index];
    if (result.status === "fulfilled") {
      resources[key] = result.value;
      availability[key] = { available: true, path };
      return;
    }
    const message = result.reason?.name === "AbortError"
      ? "请求超时"
      : String(result.reason?.message || result.reason || "接口不可用");
    resources[key] = null;
    errors[key] = message;
    availability[key] = { available: false, path, error: message };
  });

  return {
    resources,
    availability,
    errors,
    availableCount: Object.values(availability).filter((item) => item.available).length,
    totalCount: entries.length,
  };
}

export function updateEnforcement(mode) {
  return fetchJson("/api/settings/enforcement", {
    method: "POST",
    body: JSON.stringify({ mode }),
  });
}

export function savePolicyConfig({ toggles, lists }) {
  return fetchJson("/api/policy/config", {
    method: "POST",
    body: JSON.stringify({ toggles, lists }),
  });
}

export function registerTool({ manifest, metadata = {} }) {
  return fetchJson("/api/tools/manifests/register", {
    method: "POST",
    body: JSON.stringify({ manifest, metadata }),
  });
}

export function revokeTool(toolId, reason) {
  return fetchJson("/api/tools/manifests/revoke", {
    method: "POST",
    body: JSON.stringify({ toolId, reason }),
  });
}

export function restoreTool(toolId) {
  return fetchJson("/api/tools/manifests/restore", {
    method: "POST",
    body: JSON.stringify({ toolId }),
  });
}

export function restoreCheckpoint(operationKey) {
  return fetchJson("/api/checkpoints/restore", {
    method: "POST",
    body: JSON.stringify({ operationKey }),
  });
}

export function markAlertsRead(alertIds = [], all = false) {
  return fetchJson("/api/security/alerts/read", {
    method: "POST",
    body: JSON.stringify({ alertIds, all }),
  });
}

export function updateAlertState(alertIds, updates) {
  return fetchJson("/api/security/alerts/state", {
    method: "PATCH",
    body: JSON.stringify({ alertIds: Array.isArray(alertIds) ? alertIds : [alertIds], ...updates }),
  });
}

export function saveDashboardSettings(settings) {
  return fetchJson("/api/settings/dashboard", {
    method: "PUT",
    body: JSON.stringify({ settings }),
  });
}

export function saveNotificationSettings(settings) {
  return fetchJson("/api/settings/notifications", {
    method: "PUT",
    body: JSON.stringify(settings),
  });
}

export function runPolicyTest(payload) {
  return fetchJson("/api/policy/test", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function loadWindowMetrics(range = "24h") {
  return fetchJson(`/api/dashboard/metrics?range=${encodeURIComponent(range)}&limit=5000`);
}

export function recordDetail(recordId) {
  return fetchJson(`/api/records/${encodeURIComponent(recordId)}`);
}

export function exportUrl(format = "json") {
  return `/api/export?format=${encodeURIComponent(format)}`;
}

export const dashboardApi = {
  loadDashboardData,
  updateEnforcement,
  savePolicyConfig,
  registerTool,
  revokeTool,
  restoreTool,
  restoreCheckpoint,
  markAlertsRead,
  updateAlertState,
  saveDashboardSettings,
  saveNotificationSettings,
  runPolicyTest,
  loadWindowMetrics,
  recordDetail,
  exportUrl,
};
