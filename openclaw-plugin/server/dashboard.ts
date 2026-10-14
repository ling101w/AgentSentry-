import { evaluateSidecarPolicy } from "./sidecar-service.ts";
import { runPolicyDryTest } from "./policy-test-service.ts";
import { runLabCommand } from "./lab/service.ts";
import { labContent } from "./lab/scenarios.ts";
import { clip } from "./lab/workspace.ts";
import { recordParam, optionalInt, severityForDecision } from "./dashboard-utils.ts";
import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { timingSafeEqual } from "node:crypto";
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createGzip } from "node:zlib";
import { homedir } from "node:os";
import { isInterventionMode, type PluginConfig } from "../config.ts";
import { runtimeConfigPath, saveRuntimeConfig } from "../core/runtime-config.ts";
import { loadOrCreateStateSecret } from "../core/state-secret.ts";
import { safeHttpPost } from "../core/ssrf-http.ts";
import type { RollbackManager } from "../core/rollback.ts";
import { AUDIT_GENESIS_HASH, computeAuditEventHash, type AgentSentryRecord, type RecordSeverity, type RecordStore } from "../core/records.ts";
import { clearSemanticActionCache } from "../core/semantic.ts";
import { systemMonitorStatus } from "../core/system-monitor.ts";
import { agentTrustCatalog } from "../core/agent-trust.ts";
import { listToolManifestRevocations, listToolManifests, registerToolManifest, restoreToolManifest, revokeToolManifest, type ToolSecurityManifest } from "../core/tool-manifest.ts";
import { scanInitializationSurface, type FoundationComponent } from "../core/init-defense.ts";
import { emptyToolCallPerformanceSnapshot, type ToolCallPerformanceSnapshot } from "../core/performance-metrics.ts";
import type { ProductionGraphInput } from "../core/graph-learning/production-graph.ts";
import type { GraphShadowScore } from "../core/graph-learning/shadow-router.ts";
import type { ToolCallPerformanceSample } from "../core/performance-metrics.ts";
import { probeOpenClawGateway, runOpenClawAgentTurn, sanitizeOpenClawSessionKey, type OpenClawAgentTurnInput, type OpenClawAgentTurnResult, type OpenClawGatewayStatus } from "./openclaw-agent.ts";

export type DashboardServer = {
  url: string;
  accessUrl: string;
  close: () => Promise<void>;
};

export type DashboardRuntime = {
  getConfig: () => PluginConfig;
  setConfig: (config: PluginConfig) => void;
  getPerformanceMetrics?: () => ToolCallPerformanceSnapshot;
  getGraphShadowStatus?: () => Record<string, unknown> | null;
  scoreGraphShadow?: (input: ProductionGraphInput) => Promise<GraphShadowScore | null>;
  recordPerformanceSample?: (sample: ToolCallPerformanceSample) => void;
  getRollback?: () => RollbackManager | null;
  runOpenClawAgent?: (input: OpenClawAgentTurnInput) => Promise<OpenClawAgentTurnResult>;
  probeOpenClawGateway?: () => Promise<OpenClawGatewayStatus>;
};

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".txt": "text/plain; charset=utf-8",
};

const COMPRESSIBLE_EXTENSIONS = new Set([".html", ".css", ".js", ".mjs", ".svg", ".json", ".txt"]);
let openClawAgentInFlight = false;
const overviewCache = new Map<string, { signature: string; expiresAt: number; value: Record<string, unknown> }>();
const foundationInventoryCache = new Map<string, {
  expiresAt: number;
  recordCount: number;
  value: { components: FoundationComponent[]; source: "foundation_scan_record" | "live_scan"; scannedAt: string };
}>();
const ENFORCEMENT_MODES = [
  {
    value: "observe",
    label: "观察模式",
    summary: "只记录裁决、发现和告警，不改变 OpenClaw 原生工具执行结果。适合跑基线对照和观察误报。",
  },
  {
    value: "approval",
    label: "审批模式",
    summary: "高风险 ask/deny 工具调用进入 OpenClaw 人工审批；allow-always 会按工具名和参数哈希缓存。",
  },
  {
    value: "block",
    label: "阻断模式",
    summary: "确定为 deny 的高风险工具调用在执行前硬阻断。适合比赛演示和高风险环境。",
  },
] as const;
const INTERVENTION_MODES = [
  {
    value: "evidence-gated",
    label: "证据门控",
    summary: "仅在具备攻击证据时 ASK/DENY；无证据的风险发现默认放行，安全边界默认保留。",
  },
  {
    value: "risk-based",
    label: "风险驱动",
    summary: "按风险阈值与确定性策略裁决。高风险动作进入审批或阻断，不要求先有攻击证据。",
  },
] as const;
type DashboardEnforcementMode = (typeof ENFORCEMENT_MODES)[number]["value"];
type DashboardInterventionMode = (typeof INTERVENTION_MODES)[number]["value"];
type AlertDisposition = "open" | "investigating" | "resolved" | "suppressed";

type DashboardConsoleState = {
  version: 1;
  updatedAt: string;
  alerts: Record<string, {
    read: boolean;
    status?: AlertDisposition;
    note?: string;
    updatedAt: string;
  }>;
  audit: {
    retentionDays: number;
    batchSize: number;
    hashChain: boolean;
    redactSecrets: boolean;
  };
  notifications: {
    notifyHigh: boolean;
    notifyAsk: boolean;
    notifyIntegrity: boolean;
    notifyResolved: boolean;
    webhookUrl: string;
  };
};

type DashboardSecurity = {
  bindHost: string;
  port: number;
  token: string;
};

export function startDashboard(config: PluginConfig, store: RecordStore, logger: LoggerLike, runtime?: DashboardRuntime): Promise<DashboardServer> {
  const publicDir = join(fileURLToPath(new URL(".", import.meta.url)), "..", "public");
  const host = config.dashboard.host;
  const port = config.dashboard.port;
  const loopback = isLoopbackHost(host);
  if (!loopback && !config.dashboard.allowRemote) {
    throw new Error(`dashboard host ${host} is not loopback; set dashboard.allowRemote=true and configure dashboard.authToken to enable remote access`);
  }
  if (!loopback && config.dashboard.authToken.length < 32) {
    throw new Error("remote dashboard access requires dashboard.authToken with at least 32 characters");
  }
  const token = config.dashboard.authToken || loadOrCreateStateSecret(config, "dashboard-session").toString("base64url");
  const security: DashboardSecurity = { bindHost: host, port, token };
  const consoleState = readDashboardConsoleState(store);
  store.configureAudit({ hashChain: consoleState.audit.hashChain, batchSize: consoleState.audit.batchSize });
  const dashboardRuntime: DashboardRuntime = runtime ?? {
    getConfig: () => config,
    setConfig: () => undefined,
  };

  const server = createServer((req, res) => {
    void handleRequest(req, res, publicDir, store, dashboardRuntime, security);
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      const address = server.address();
      const actualPort = typeof address === "object" && address ? address.port : port;
      security.port = actualPort;
      const url = `http://${formatHostForUrl(host)}:${actualPort}`;
      const accessUrl = `${url}/?access_token=${encodeURIComponent(token)}`;
      const unsubscribeNotifications = store.subscribe((record) => dispatchDashboardWebhook(record, store, security));
      logger.info(`[AgentSentry] dashboard listening at ${url}`);
      resolve({
        url,
        accessUrl,
        close: async () => {
          unsubscribeNotifications();
          await closeServer(server);
        },
      });
    });
  });
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  publicDir: string,
  store: RecordStore,
  runtime: DashboardRuntime,
  security: DashboardSecurity,
): Promise<void> {
  const url = new URL(req.url || "/", "http://agentsentry.local");
  const config = runtime.getConfig();

  if (req.method === "GET" && url.pathname.startsWith("/lab-content/")) {
    const name = url.pathname.split("/").pop() || "";
    const content = labContent(name);
    if (!content) {
      sendText(res, 404, "Not found");
      return;
    }
    res.writeHead(200, { "Content-Type": content.contentType, "Cache-Control": "no-store" });
    res.end(content.body);
    return;
  }

  const allowUnauthenticatedSidecar = url.pathname.startsWith("/api/sidecar/")
    && config.externalPolicy.enabled
    && !config.externalPolicy.requireAuth;
  const allowUnauthenticatedDemo = isPublicDemoPath(url.pathname)
    && ((req.method || "GET").toUpperCase() === "GET" || (req.method || "GET").toUpperCase() === "HEAD");
  if (!authorizeDashboardRequest(req, res, url, security, { allowUnauthenticated: allowUnauthenticatedSidecar || allowUnauthenticatedDemo })) return;

  if (req.method === "GET" && url.pathname === "/api/health") {
    sendJson(req, res, {
      ok: true,
      recordsPath: store.recordsPath,
      capabilities: [
        "lab_command",
        "lab_benchmark_browser",
        "lab_openclaw_llm",
        "business_test_request",
        "lab_policy_enforcement",
        "security_overview",
        "records_export",
        "taint_tracking",
        "abac_session_policy",
        "system_preflight",
        "kernel_runtime_gate",
        "multi_turn_lab_session",
        "session_taint_propagation",
        "memory_guard_passports",
        "memory_integrity_check",
        "memory_quarantine",
        "foundation_component_scan",
        "external_policy_sidecar",
        "operation_checkpoints",
        "checkpoint_restore",
        "bootstrap_metrics",
        "performance_metrics",
        "graph_training_export",
        "graphical_policy_config",
        "agent_identity_trust",
        "tool_trust_levels",
        "multi_agent_message_guard",
        "dashboard_window_metrics",
        "mcp_skill_memory_inventory",
        "alert_disposition_workflow",
        "persisted_audit_hash_chain",
        "dashboard_settings_persistence",
      ],
      runtime_isolation: config.runtimeIsolation,
      system_monitor: systemMonitorStatus(),
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/sidecar/health") {
    sendJson(req, res, {
      ok: true,
      enabled: config.externalPolicy.enabled,
      mode: config.enforcement.mode,
      profile: config.profile,
      api: {
        evaluate: "POST /api/sidecar/evaluate",
        checkpoints: "GET /api/checkpoints",
      },
      capabilities: [
        "TaskSpec session authorization",
        "IFC sticky labels and provenance",
        "ABAC data-flow policy",
        "LLM-Judge semantic review when configured",
        "rollback checkpoint metadata",
      ],
    });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/sidecar/evaluate") {
    if (!config.externalPolicy.enabled) {
      sendJson(req, res, { ok: false, error: "external policy sidecar is disabled" }, 404);
      return;
    }
    try {
      const body = await readJsonBody(req, 65536);
      const result = await evaluateSidecarPolicy(body, store, config);
      sendJson(req, res, result, result.ok ? 200 : 400);
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/checkpoints") {
    const manager = runtime.getRollback?.() || null;
    const limit = clampInt(url.searchParams.get("limit"), 1, 1000, 50);
    sendJson(req, res, {
      ok: true,
      enabled: Boolean(manager),
      path: manager?.checkpointPath || "",
      checkpoints: manager?.listCheckpoints(limit) || [],
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/records") {
    const limit = clampInt(url.searchParams.get("limit"), 1, 5000, 500);
    const compact = url.searchParams.get("compact") === "1" || url.searchParams.get("summary") === "1";
    const consoleState = readDashboardConsoleState(store);
    const records = attachAuditHashChain(store.list(limit), consoleState.audit.hashChain);
    sendJson(req, res, {
      records: compact ? records.map(compactRecord) : records,
      totalRecords: store.count(),
      windowRecords: records.length,
      windowLimit: limit,
      compact,
      recordsPath: store.recordsPath,
      integrity: verifyAuditHashChain(records, consoleState.audit.hashChain),
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/audit/integrity") {
    const limit = clampInt(url.searchParams.get("limit"), 1, 5000, 2000);
    const consoleState = readDashboardConsoleState(store);
    const records = attachAuditHashChain(store.list(limit), consoleState.audit.hashChain);
    sendJson(req, res, verifyAuditHashChain(records, consoleState.audit.hashChain));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/audit/persistence") {
    sendJson(req, res, { ok: true, persistence: store.persistenceStatus() });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/settings/dashboard") {
    sendJson(req, res, dashboardSettings(config, readDashboardConsoleState(store)));
    return;
  }

  if (req.method === "PUT" && url.pathname === "/api/settings/dashboard") {
    try {
      const body = await readJsonBody(req, 32768);
      const previous = dashboardSettings(config, readDashboardConsoleState(store));
      const semanticCacheWasEnabled = config.semantic.cacheEnabled;
      const consoleState = await applyDashboardSettings(config, store, body);
      runtime.setConfig(config);
      saveRuntimeConfig(config);
      if (semanticCacheWasEnabled && !config.semantic.cacheEnabled) clearSemanticActionCache();
      overviewCache.clear();
      addDashboardAuditRecord(store, "Dashboard 设置已更新", "dashboard and console settings updated", {
        previous,
        current: dashboardSettings(config, consoleState),
        source: "dashboard-settings",
        runtime_config_path: runtimeConfigPath(config),
      });
      store.configureAudit({ hashChain: consoleState.audit.hashChain });
      sendJson(req, res, dashboardSettings(config, consoleState));
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/settings/notifications") {
    const state = readDashboardConsoleState(store);
    sendJson(req, res, { ok: true, ...state.notifications, updatedAt: state.updatedAt });
    return;
  }

  if (req.method === "PUT" && url.pathname === "/api/settings/notifications") {
    try {
      const body = await readJsonBody(req, 16384);
      const state = readDashboardConsoleState(store);
      const previous = { ...state.notifications };
      state.notifications = parseNotificationSettings(body, state.notifications);
      writeDashboardConsoleState(store, state);
      addDashboardAuditRecord(store, "告警通知路由已更新", "notification routing updated", {
        previous,
        current: state.notifications,
        source: "dashboard-notifications",
      });
      sendJson(req, res, { ok: true, ...state.notifications, updatedAt: state.updatedAt });
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/settings/enforcement") {
    sendJson(req, res, enforcementSettings(config));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/policy/config") {
    sendJson(req, res, policyConsoleConfig(config));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/policy/config") {
    try {
      const body = await readJsonBody(req, 32768);
      const previous = policyConsoleConfig(config);
      applyPolicyConsoleConfig(config, body);
      runtime.setConfig(config);
      saveRuntimeConfig(config);
      overviewCache.clear();
      store.add({
        run_id: `runtime_${Date.now().toString(36)}`,
        session_key: "dashboard:runtime-config",
        type: "runtime",
        layer: "Evidence Feedback",
        severity: "info",
        title: "玄鉴图形化策略配置已更新",
        summary: "policy console config updated",
        payload: {
          previous,
          current: policyConsoleConfig(config),
          source: "dashboard-policy-console",
          runtime_config_path: runtimeConfigPath(config),
        },
      });
      sendJson(req, res, { ok: true, ...policyConsoleConfig(config) });
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/tools/manifests") {
    sendJson(req, res, {
      ok: true,
      manifests: listToolManifests(),
      revocations: listToolManifestRevocations(),
    });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/tools/manifests/register") {
    try {
      const body = await readJsonBody(req, 65536);
      const manifest = requireToolManifest(body.manifest);
      const metadata = recordParam(body.metadata) || {};
      const envelope = registerToolManifest(manifest, {
        schema: metadata.schema,
        endpoint: typeof metadata.endpoint === "string" ? metadata.endpoint : undefined,
        version: typeof metadata.version === "string" ? metadata.version : undefined,
        expectedDigest: typeof metadata.expectedDigest === "string" ? metadata.expectedDigest : undefined,
      });
      store.add({
        run_id: `runtime_${Date.now().toString(36)}`,
        session_key: "dashboard:tool-registry",
        type: "runtime",
        layer: "Foundation Integrity",
        severity: "info",
        title: "工具安全清单已登记",
        summary: `${envelope.manifest.toolId} 已由本地管理员签名并持久化登记`,
        payload: { tool_id: envelope.manifest.toolId, digest: envelope.digest, endpoint: envelope.endpoint || "" },
      });
      sendJson(req, res, { ok: true, envelope });
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/tools/manifests/revoke") {
    try {
      const body = await readJsonBody(req, 8192);
      const toolId = typeof body.toolId === "string" ? body.toolId.trim() : "";
      if (!toolId) throw new Error("toolId is required");
      const revocation = revokeToolManifest(toolId, typeof body.reason === "string" ? body.reason : "");
      store.add({
        run_id: `runtime_${Date.now().toString(36)}`,
        session_key: "dashboard:tool-registry",
        type: "runtime",
        layer: "Foundation Integrity",
        severity: "warning",
        title: "工具信任已吊销",
        summary: `${revocation.toolId} 已吊销，后续调用将在执行前阻断`,
        payload: { revocation },
      });
      sendJson(req, res, { ok: true, revocation });
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/tools/manifests/restore") {
    try {
      const body = await readJsonBody(req, 8192);
      const toolId = typeof body.toolId === "string" ? body.toolId.trim() : "";
      if (!toolId) throw new Error("toolId is required");
      const restored = restoreToolManifest(toolId);
      sendJson(req, res, { ok: true, restored });
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/metrics/bootstrap") {
    const limit = clampInt(url.searchParams.get("limit"), 1, 5000, 1000);
    const iterations = clampInt(url.searchParams.get("iterations"), 100, 5000, 1000);
    sendJson(req, res, bootstrapDecisionMetrics(store.list(limit), iterations));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/metrics/performance") {
    sendJson(req, res, runtime.getPerformanceMetrics?.() || emptyToolCallPerformanceSnapshot());
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/metrics/graph-shadow") {
    sendJson(req, res, runtime.getGraphShadowStatus?.() || { enabled: false, configured: false, state: "disabled" });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/mcp/servers") {
    sendJson(req, res, listMcpServers(config, store));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/skills/inventory") {
    sendJson(req, res, listSkillInventory(config, store));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/memory/inventory") {
    sendJson(req, res, listMemoryInventory(config, store));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/dashboard/metrics") {
    const limit = clampInt(url.searchParams.get("limit"), 1, 10000, 5000);
    sendJson(req, res, buildDashboardMetrics(store, limit));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/lab/benchmarks") {
    sendJson(req, res, buildLabBenchmarkResponse(url));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/settings/enforcement") {
    try {
      const body = await readJsonBody(req, 4096);
      const mode = String(body.mode || body.interventionMode || "").trim();
      if (isDashboardInterventionMode(mode)) {
        const previousMode = config.intervention.mode;
        config.intervention.mode = mode;
        runtime.setConfig(config);
        saveRuntimeConfig(config);
        overviewCache.clear();
        const settings = enforcementSettings(config);
        const modeMeta = INTERVENTION_MODES.find((item) => item.value === mode);
        store.add({
          run_id: `runtime_${Date.now().toString(36)}`,
          session_key: "dashboard:runtime-config",
          type: "runtime",
          layer: "Evidence Feedback",
          severity: "info",
          title: "AgentSentry intervention mode changed",
          summary: `${previousMode} -> ${mode}`,
          payload: {
            previous_mode: previousMode,
            mode,
            label: modeMeta?.label || mode,
            source: "dashboard",
            runtime_config_path: runtimeConfigPath(config),
          },
        });
        sendJson(req, res, { ok: true, ...settings });
        return;
      }
      if (!isDashboardEnforcementMode(mode)) {
        sendJson(req, res, { ok: false, error: "mode must be observe, approval, block, evidence-gated, or risk-based" }, 400);
        return;
      }
      const previousMode = config.enforcement.mode;
      config.enforcement.mode = mode;
      runtime.setConfig(config);
      saveRuntimeConfig(config);
      overviewCache.clear();
      const settings = enforcementSettings(config);
      const modeMeta = ENFORCEMENT_MODES.find((item) => item.value === mode);
      store.add({
        run_id: `runtime_${Date.now().toString(36)}`,
        session_key: "dashboard:runtime-config",
        type: "runtime",
        layer: "Evidence Feedback",
        severity: "info",
        title: "AgentSentry enforcement mode changed",
        summary: `${previousMode} -> ${mode}`,
        payload: {
          previous_mode: previousMode,
          mode,
          label: modeMeta?.label || mode,
          source: "dashboard",
          runtime_config_path: runtimeConfigPath(config),
        },
      });
      sendJson(req, res, { ok: true, ...settings });
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "GET" && url.pathname.startsWith("/api/records/")) {
    const id = decodeURIComponent(url.pathname.slice("/api/records/".length));
    const record = store.get(id);
    if (!record) {
      sendJson(req, res, { ok: false, error: "record not found" }, 404);
      return;
    }
    sendJson(req, res, { ok: true, record });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/checkpoints/restore") {
    const manager = runtime.getRollback?.() || null;
    if (!manager) {
      sendJson(req, res, { ok: false, error: "rollback manager is not available" }, 404);
      return;
    }
    try {
      const body = await readJsonBody(req, 4096);
      const operationKey = String(body.operationKey || body.operation_key || "").trim();
      if (!operationKey) {
        sendJson(req, res, { ok: false, error: "operationKey is required" }, 400);
        return;
      }
      const result = manager.restoreOperation(operationKey);
      store.add({
        run_id: `rollback_${Date.now().toString(36)}`,
        session_key: "dashboard:rollback",
        type: "runtime",
        layer: "Evidence Feedback",
        severity: result.errors.length ? "warning" : "success",
        title: "Checkpoint rollback requested",
        summary: `${result.restored.length} file snapshot(s) restored; ${result.errors.length} error(s)`,
        payload: {
          operation_key: operationKey,
          result,
          source: "dashboard-checkpoint-console",
        },
      });
      sendJson(req, res, { ok: true, ...result });
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/stats") {
    const limit = clampInt(url.searchParams.get("limit"), 1, 5000, 5000);
    sendJson(req, res, store.stats(limit));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/security/overview") {
    const source = url.searchParams.get("source") || "openclaw";
    if (source === "openclaw" || source === "") {
      const limit = clampInt(url.searchParams.get("limit"), 1, 5000, 2000);
      sendJson(req, res, cachedOpenClawSecurityOverview(store, limit));
      return;
    }
    const upstreamPath = source === "combined" || source === "local"
      ? `/api/security/overview?source=${encodeURIComponent(source)}`
      : "/api/security/overview?source=openclaw";
    try {
      const body = await proxyJson("127.0.0.1", 8000, upstreamPath);
      sendRawJson(req, res, body);
    } catch (error) {
      sendJson(
        req,
        res,
        { ok: false, error: error instanceof Error ? error.message : String(error), source: "agentsentry-proxy" },
        502,
      );
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/security/alerts") {
    const page = clampInt(url.searchParams.get("page"), 1, 100000, 1);
    const pageSize = clampInt(url.searchParams.get("pageSize"), 1, 100, 25);
    const defaultLimit = Math.max(1, store.count());
    const limit = clampInt(url.searchParams.get("limit"), 1, 100000, defaultLimit);
    sendJson(req, res, buildOpenClawAlertPage(store, page, pageSize, limit));
    return;
  }

  if (req.method === "PATCH" && url.pathname === "/api/security/alerts/state") {
    try {
      const body = await readJsonBody(req, 16384);
      const ids = alertIdsFromBody(body);
      if (!ids.length) throw new Error("alertId or alertIds is required");
      const unknownIds = ids.filter((id) => !currentAlertIds(store).has(id));
      if (unknownIds.length) throw new Error(`unknown alert id: ${unknownIds[0]}`);
      const state = readDashboardConsoleState(store);
      const status = parseAlertDisposition(body.status);
      const read = typeof body.read === "boolean" ? body.read : undefined;
      const note = typeof body.note === "string" ? body.note.trim().slice(0, 500) : undefined;
      if (status === undefined && read === undefined && note === undefined) throw new Error("status, read, or note is required");
      const now = new Date().toISOString();
      for (const id of ids) {
        const current = state.alerts[id] || { read: false, updatedAt: now };
        state.alerts[id] = {
          ...current,
          ...(status ? { status } : {}),
          ...(read !== undefined ? { read } : {}),
          ...(note !== undefined ? { note } : {}),
          updatedAt: now,
        };
      }
      writeDashboardConsoleState(store, state);
      addDashboardAuditRecord(store, "告警处置状态已更新", `${ids.length} alert state(s) updated`, {
        alert_ids: ids,
        status,
        read,
        note,
        source: "dashboard-alert-console",
      });
      sendJson(req, res, { ok: true, updated: ids.length, alertIds: ids, state: Object.fromEntries(ids.map((id) => [id, state.alerts[id]])) });
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/security/alerts/read") {
    try {
      const body = await readJsonBody(req, 16384);
      const state = readDashboardConsoleState(store);
      let ids = alertIdsFromBody(body);
      if (!ids.length && body.all === true) {
        const page = buildOpenClawAlertPage(store, 1, 100000, Math.max(1, store.count()));
        ids = Array.isArray(page.alerts)
          ? page.alerts.map((alert) => String(recordParam(alert)?.id || "")).filter(Boolean)
          : [];
      }
      if (!ids.length) throw new Error("alertId, alertIds, or all=true is required");
      const unknownIds = ids.filter((id) => !currentAlertIds(store).has(id));
      if (unknownIds.length) throw new Error(`unknown alert id: ${unknownIds[0]}`);
      const now = new Date().toISOString();
      for (const id of ids) {
        state.alerts[id] = { ...(state.alerts[id] || {}), read: true, updatedAt: now };
      }
      writeDashboardConsoleState(store, state);
      addDashboardAuditRecord(store, "告警已读状态已更新", `${ids.length} alert(s) marked read`, {
        alert_ids: ids,
        source: "dashboard-alert-console",
      });
      sendJson(req, res, { ok: true, updated: ids.length, alertIds: ids });
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/policy/test") {
    try {
      const body = await readJsonBody(req, 32768);
      const result = await runPolicyDryTest(config, body);
      addDashboardAuditRecord(store, "策略快速测试已执行", `${result.decision}; risk=${result.risk_score}`, {
        source: "dashboard-policy-test",
        rule: body.rule || "",
        tool: result.toolName,
        decision: result.decision,
        risk_score: result.risk_score,
      }, severityForDecision(result.decision));
      sendJson(req, res, { ok: true, dryRun: true, ...result });
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/lab/command") {
    try {
      const body = await readJsonBody(req, 32768);
      sendJson(req, res, await runLabCommand(body, store, config, runtime));
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/lab/openclaw-status") {
    try {
      const probe = runtime.probeOpenClawGateway || probeOpenClawGateway;
      const status = await probe();
      sendJson(req, res, {
        ok: status.ok,
        reachable: status.reachable,
        summary: status.summary,
        capability: "lab_openclaw_llm",
      }, status.reachable ? 200 : 503);
    } catch (error) {
      sendJson(req, res, {
        ok: false,
        reachable: false,
        summary: error instanceof Error ? error.message : String(error),
      }, 503);
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/lab/openclaw-message") {
    req.setTimeout(210000);
    res.setTimeout(210000);
    if (openClawAgentInFlight) {
      sendJson(req, res, { ok: false, error: "已有一次真实 Agent 请求进行中" }, 409);
      return;
    }
    try {
      const body = await readJsonBody(req, 32768);
      const command = String(body.command || "").trim();
      if (!command) {
        sendJson(req, res, { ok: false, error: "command is required" }, 400);
        return;
      }
      const clientId = String(body.clientId || "browser").replace(/[^\w:.-]/g, "_").slice(0, 80);
      const continueSession = Boolean(body.continueSession);
      const runId = `llm_${Date.now().toString(36)}`;
      const sessionKey = sanitizeOpenClawSessionKey(
        continueSession ? body.sessionKey : "",
        `command-lab-llm-${clientId}-${runId}`,
      );
      const timeoutSeconds = optionalInt(body.timeoutSeconds, 15, 300) ?? 120;
      const scenario = String(body.scenario || "openclaw_llm_office").slice(0, 80);
      const sentPayload = {
        command,
        scenario,
        source: "command-lab-llm",
        phase: "sent",
        openclaw_session_key: sessionKey,
        continue_session: continueSession,
      };
      const sentTitle = scenario === "openclaw_llm_office" ? "OpenClaw LLM office request" : "OpenClaw LLM test request";
      const sent = store.add({
        run_id: runId,
        session_key: sessionKey,
        type: "lab_command",
        layer: "Context Provenance",
        severity: "info",
        title: sentTitle,
        summary: command.slice(0, 240),
        payload: sentPayload,
      });
      openClawAgentInFlight = true;
      const runAgent = runtime.runOpenClawAgent || runOpenClawAgentTurn;
      const outcome = await runAgent({
        message: command,
        sessionKey,
        timeoutSeconds,
      });
      const resolvedSessionKey = sanitizeOpenClawSessionKey(outcome.sessionKey, sessionKey);
      if (resolvedSessionKey !== sessionKey) {
        store.add({
          run_id: runId,
          session_key: resolvedSessionKey,
          type: "lab_command",
          layer: "Context Provenance",
          severity: "info",
          title: sentTitle,
          summary: command.slice(0, 240),
          payload: {
            ...sentPayload,
            openclaw_session_key: resolvedSessionKey,
            aliased_from: sessionKey,
          },
        });
      }
      const replyRecord = store.add({
        run_id: runId,
        session_key: resolvedSessionKey,
        type: outcome.ok ? "message_write" : "lab_command",
        layer: outcome.ok ? "Context Provenance" : "Evidence Feedback",
        severity: outcome.ok ? "success" : "warning",
        title: outcome.ok ? "OpenClaw agent reply" : "OpenClaw LLM test failed",
        summary: (outcome.reply || outcome.error || "").slice(0, 240),
        payload: {
          command,
          preview: outcome.reply ? clip(outcome.reply, 4000) : undefined,
          reply: outcome.reply ? clip(outcome.reply, 4000) : undefined,
          error: outcome.error,
          scenario,
          source: "command-lab-llm",
          phase: outcome.ok ? "replied" : "failed",
          openclaw_session_key: resolvedSessionKey,
          role: outcome.ok ? "assistant" : undefined,
        },
      });
      sendJson(req, res, {
        ok: outcome.ok,
        record: sent,
        replyRecord,
        sessionKey: resolvedSessionKey,
        reply: outcome.reply || "",
        error: outcome.error,
      }, outcome.ok ? 200 : 502);
    } catch (error) {
      sendJson(req, res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    } finally {
      openClawAgentInFlight = false;
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/export") {
    const limit = clampInt(url.searchParams.get("limit"), 1, 50000, 5000);
    const format = (url.searchParams.get("format") || "json").toLowerCase();
    const records = store.list(limit);
    if (format === "csv") {
      sendDownload(res, "text/csv; charset=utf-8", `agentsentry-records-${dateStamp()}.csv`, recordsToCsv(records));
      return;
    }
    sendDownload(
      res,
      "application/json; charset=utf-8",
      `agentsentry-records-${dateStamp()}.json`,
      JSON.stringify({ exported_at: new Date().toISOString(), count: records.length, records }, null, 2),
    );
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/reset") {
    store.reset();
    sendJson(req, res, { ok: true });
    return;
  }

  if (req.method !== "GET") {
    sendText(res, 405, "Method not allowed");
    return;
  }

  if (
    url.pathname === "/demo" ||
    url.pathname === "/demo/" ||
    url.pathname === "/governance-demo" ||
    url.pathname === "/demo/selected-cases" ||
    url.pathname === "/demo/selected-cases/"
  ) {
    res.writeHead(302, {
      Location: `/demo/selected-cases/index.html${url.search}`,
      "Cache-Control": "no-store",
    });
    res.end();
    return;
  }

  const requested = resolvePublicRequestPath(url.pathname);
  const filePath = normalize(join(publicDir, requested));
  if (!filePath.startsWith(normalize(publicDir)) || !existsSync(filePath)) {
    sendText(res, 404, "Not found");
    return;
  }

  serveStaticFile(req, res, filePath, requested);
}

function isPublicDemoPath(pathname: string): boolean {
  return pathname === "/demo" || pathname === "/governance-demo" || pathname.startsWith("/demo/");
}

function resolvePublicRequestPath(pathname: string): string {
  if (pathname === "/") return "/index.html";
  if (pathname === "/screen" || pathname === "/security-screen") return "/security-screen.html";
  if (pathname === "/lab" || pathname === "/command-lab") return "/command-lab.html";
  if (
    pathname === "/demo" ||
    pathname === "/demo/" ||
    pathname === "/governance-demo" ||
    pathname === "/demo/selected-cases" ||
    pathname === "/demo/selected-cases/"
  ) {
    return "/demo/selected-cases/index.html";
  }
  if (["/monitor", "/overview", "/agents", "/policies", "/tools", "/alerts", "/audit", "/settings"].includes(pathname)) {
    return "/index.html";
  }
  return pathname;
}

function authorizeDashboardRequest(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  security: DashboardSecurity,
  options: { allowUnauthenticated?: boolean } = {},
): boolean {
  res.setHeader("Referrer-Policy", "no-referrer");
  if (isPublicDemoPath(url.pathname)) {
    res.setHeader("Content-Security-Policy", "frame-ancestors *");
  } else {
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
  }

  const hostHeader = typeof req.headers.host === "string" ? req.headers.host.trim() : "";
  if (!validDashboardHost(hostHeader, security)) {
    sendText(res, 421, "Invalid dashboard Host header");
    return false;
  }

  const origin = typeof req.headers.origin === "string" ? req.headers.origin.trim() : "";
  if (origin && !validDashboardOrigin(origin, hostHeader)) {
    sendText(res, 403, "Invalid dashboard Origin header");
    return false;
  }

  const bearer = bearerToken(req);
  const bearerAuthenticated = Boolean(bearer && secureTokenEqual(bearer, security.token));
  const sessionAuthenticated = secureTokenEqual(cookieValue(req, "agentsentry_session"), security.token);
  const method = (req.method || "GET").toUpperCase();
  const safeMethod = method === "GET" || method === "HEAD";

  if (options.allowUnauthenticated) return true;
  if (!safeMethod && !origin && !bearerAuthenticated) {
    sendText(res, 403, "Dashboard state changes require a same-origin request or bearer token");
    return false;
  }
  if (bearerAuthenticated || sessionAuthenticated) return true;

  const bootstrapToken = url.searchParams.get("access_token") || "";
  if (safeMethod && secureTokenEqual(bootstrapToken, security.token)) {
    url.searchParams.delete("access_token");
    const location = `${url.pathname}${url.search}` || "/";
    res.writeHead(303, {
      Location: location,
      "Cache-Control": "no-store",
      "Set-Cookie": `agentsentry_session=${encodeURIComponent(security.token)}; Path=/; HttpOnly; SameSite=Strict`,
    });
    res.end();
    return false;
  }

  res.setHeader("WWW-Authenticate", 'Bearer realm="AgentSentry Dashboard"');
  sendText(res, 401, "Dashboard authentication required");
  return false;
}

function validDashboardHost(hostHeader: string, security: DashboardSecurity): boolean {
  if (!hostHeader) return false;
  try {
    const parsed = new URL(`http://${hostHeader}`);
    const requestPort = parsed.port ? Number(parsed.port) : 80;
    if (requestPort !== security.port) return false;
    const requestHost = parsed.hostname.toLowerCase();
    const bindHost = stripIpv6Brackets(security.bindHost).toLowerCase();
    if (isLoopbackHost(bindHost)) return isLoopbackHost(requestHost);
    if (bindHost === "0.0.0.0" || bindHost === "::") return isIP(requestHost) !== 0;
    return requestHost === bindHost;
  } catch {
    return false;
  }
}

function validDashboardOrigin(origin: string, hostHeader: string): boolean {
  try {
    return new URL(origin).origin === new URL(`http://${hostHeader}`).origin;
  } catch {
    return false;
  }
}

function bearerToken(req: IncomingMessage): string {
  const authorization = typeof req.headers.authorization === "string" ? req.headers.authorization : "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || "";
}

function cookieValue(req: IncomingMessage, name: string): string {
  const cookie = typeof req.headers.cookie === "string" ? req.headers.cookie : "";
  for (const item of cookie.split(";")) {
    const separator = item.indexOf("=");
    if (separator < 0 || item.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(item.slice(separator + 1).trim());
    } catch {
      return "";
    }
  }
  return "";
}

function secureTokenEqual(left: string, right: string): boolean {
  if (!left || !right) return false;
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function isLoopbackHost(host: string): boolean {
  const normalized = stripIpv6Brackets(host).toLowerCase();
  if (normalized === "localhost" || normalized === "::1") return true;
  if (isIP(normalized) !== 4) return false;
  const firstOctet = Number(normalized.split(".")[0]);
  return firstOctet === 127;
}

function stripIpv6Brackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function formatHostForUrl(host: string): string {
  const normalized = stripIpv6Brackets(host);
  return isIP(normalized) === 6 ? `[${normalized}]` : normalized;
}

function compactRecord(record: AgentSentryRecord): AgentSentryRecord {
  return {
    ...record,
    payload: compactPayload(record),
  };
}

function enforcementSettings(config: PluginConfig): Record<string, unknown> {
  const securityStack = [
    { key: "task_spec", label: "TaskSpec 授权", enabled: true },
    { key: "deterministic", label: "确定性策略", enabled: config.policy.deterministic },
    { key: "taint_feedback", label: "污点与证据回流", enabled: config.policy.taintFeedback },
    { key: "multi_agent", label: "多 Agent 身份链", enabled: config.multiAgentSecurity.enabled },
    { key: "semantic", label: "语义复核", enabled: config.semantic.enabled },
    { key: "response_cover", label: "污染响应覆盖", enabled: config.responseCover.enabled },
    { key: "rollback", label: "Checkpoint 回滚", enabled: config.rollback.enabled },
  ];
  return {
    ok: true,
    profile: config.profile,
    mode: config.enforcement.mode,
    interventionMode: config.intervention.mode,
    intervention: config.intervention,
    approvalTimeoutMs: config.enforcement.approvalTimeoutMs,
    runtimeConfigPath: runtimeConfigPath(config),
    modes: ENFORCEMENT_MODES,
    interventionModes: INTERVENTION_MODES,
    securityStack,
    enabledSecurityLayers: securityStack.filter((item) => item.enabled).length,
    competitionReady: config.enforcement.mode !== "observe"
      && securityStack.every((item) => item.enabled)
      && config.policy.restrictWritesToAllowedRoots,
  };
}

function policyConsoleConfig(config: PluginConfig): Record<string, unknown> {
  return {
    ok: true,
    profile: config.profile,
    enforcement: {
      mode: config.enforcement.mode,
      approvalTimeoutMs: config.enforcement.approvalTimeoutMs,
    },
    toggles: {
      deterministic: config.policy.deterministic,
      taintFeedback: config.policy.taintFeedback,
      semantic: config.semantic.enabled,
      runtimeAudit: config.runtimeIsolation.auditAfterExecution,
      strictShellNetworkIsolation: config.runtimeIsolation.requireNetworkNamespaceForShell,
      initializationDefense: config.initializationDefense.enabled,
      rollback: config.rollback.enabled,
      multiAgentSecurity: config.multiAgentSecurity.enabled,
      responseCover: config.responseCover.enabled,
    },
    lists: {
      allowlistedRecipients: config.policy.allowlistedRecipients,
      allowlistedApiHosts: config.policy.allowlistedApiHosts,
      allowedWriteRoots: config.policy.allowedWriteRoots,
      sensitiveAssets: config.policy.sensitiveAssets,
    },
    agents: agentTrustCatalog(config),
    tools: listToolManifests().map((item) => ({
      toolId: item.manifest.toolId,
      aliases: item.manifest.aliases,
      trust: item.manifest.defaultTrust,
      origins: item.manifest.dataOrigins,
      sideEffects: item.manifest.sideEffects,
      acceptsSensitiveData: item.manifest.acceptsSensitiveData,
      canExfiltrate: item.manifest.canExfiltrate,
      requiresExplicitAuthorization: item.manifest.requiresExplicitAuthorization,
      digest: item.digest,
      signaturePresent: Boolean(item.signature),
      issuer: item.issuer || "local-administrator",
    })),
    revocations: listToolManifestRevocations(),
  };
}

function applyPolicyConsoleConfig(config: PluginConfig, body: Record<string, unknown>): void {
  const toggles = recordParam(body.toggles) || body;
  const lists = recordParam(body.lists) || {};
  config.policy.deterministic = readBodyBoolean(toggles.deterministic, config.policy.deterministic);
  config.policy.taintFeedback = readBodyBoolean(toggles.taintFeedback, config.policy.taintFeedback);
  config.semantic.enabled = readBodyBoolean(toggles.semantic, config.semantic.enabled);
  config.runtimeIsolation.auditAfterExecution = readBodyBoolean(toggles.runtimeAudit, config.runtimeIsolation.auditAfterExecution);
  config.runtimeIsolation.requireNetworkNamespaceForShell = readBodyBoolean(
    toggles.strictShellNetworkIsolation,
    config.runtimeIsolation.requireNetworkNamespaceForShell,
  );
  config.initializationDefense.enabled = readBodyBoolean(toggles.initializationDefense, config.initializationDefense.enabled);
  config.rollback.enabled = readBodyBoolean(toggles.rollback, config.rollback.enabled);
  config.multiAgentSecurity.enabled = readBodyBoolean(toggles.multiAgentSecurity, config.multiAgentSecurity.enabled);
  config.responseCover.enabled = readBodyBoolean(toggles.responseCover, config.responseCover.enabled);
  config.policy.allowlistedRecipients = readBodyStringList(lists.allowlistedRecipients, config.policy.allowlistedRecipients);
  config.policy.allowlistedApiHosts = readBodyStringList(lists.allowlistedApiHosts, config.policy.allowlistedApiHosts);
  config.policy.allowedWriteRoots = readBodyStringList(lists.allowedWriteRoots, config.policy.allowedWriteRoots);
  config.policy.sensitiveAssets = readBodyStringList(lists.sensitiveAssets, config.policy.sensitiveAssets);
}

function readBodyBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function readBodyStringList(value: unknown, fallback: string[]): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => String(item || "").trim()).filter(Boolean).slice(0, 200);
  }
  if (typeof value === "string") {
    return value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean).slice(0, 200);
  }
  return fallback;
}

function defaultDashboardConsoleState(): DashboardConsoleState {
  return {
    version: 1,
    updatedAt: new Date().toISOString(),
    alerts: {},
    audit: {
      retentionDays: 30,
      batchSize: 25,
      hashChain: true,
      redactSecrets: true,
    },
    notifications: {
      notifyHigh: true,
      notifyAsk: true,
      notifyIntegrity: true,
      notifyResolved: false,
      webhookUrl: "",
    },
  };
}

function dashboardConsoleStatePath(store: RecordStore): string {
  return join(store.dataDir, "dashboard-console-state.json");
}

function readDashboardConsoleState(store: RecordStore): DashboardConsoleState {
  const fallback = defaultDashboardConsoleState();
  const path = dashboardConsoleStatePath(store);
  if (!existsSync(path)) return fallback;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
    const root = recordParam(raw);
    if (!root) return fallback;
    const alerts = recordParam(root.alerts) || {};
    const audit = recordParam(root.audit) || {};
    const notifications = recordParam(root.notifications) || {};
    const normalizedAlerts: DashboardConsoleState["alerts"] = {};
    for (const [id, value] of Object.entries(alerts).slice(0, 10000)) {
      const row = recordParam(value);
      if (!row || !id.trim()) continue;
      const status = parseAlertDisposition(row.status);
      normalizedAlerts[id] = {
        read: typeof row.read === "boolean" ? row.read : false,
        ...(status ? { status } : {}),
        ...(typeof row.note === "string" ? { note: row.note.slice(0, 500) } : {}),
        updatedAt: typeof row.updatedAt === "string" ? row.updatedAt : fallback.updatedAt,
      };
    }
    return {
      version: 1,
      updatedAt: typeof root.updatedAt === "string" ? root.updatedAt : fallback.updatedAt,
      alerts: normalizedAlerts,
      audit: {
        retentionDays: boundedBodyInt(audit.retentionDays, 1, 3650, fallback.audit.retentionDays),
        batchSize: boundedBodyInt(audit.batchSize, 1, 1000, fallback.audit.batchSize),
        hashChain: readBodyBoolean(audit.hashChain, fallback.audit.hashChain),
        redactSecrets: true,
      },
      notifications: parseNotificationSettings(notifications, fallback.notifications),
    };
  } catch {
    return fallback;
  }
}

function writeDashboardConsoleState(store: RecordStore, state: DashboardConsoleState): void {
  mkdirSync(store.dataDir, { recursive: true, mode: 0o700 });
  state.updatedAt = new Date().toISOString();
  const path = dashboardConsoleStatePath(store);
  const temporaryPath = `${path}.${process.pid}.tmp`;
  writeFileSync(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  renameSync(temporaryPath, path);
}

function dashboardSettings(config: PluginConfig, state: DashboardConsoleState): Record<string, unknown> {
  return {
    ok: true,
    updatedAt: state.updatedAt,
    runtimeConfigPath: runtimeConfigPath(config),
    settings: {
      enforcementProfile: config.enforcement.mode,
      interventionMode: config.intervention.mode,
      preserveSafetyBoundaries: config.intervention.preserveSafetyBoundaries,
      approvalsEnabled: config.enforcement.mode === "approval",
      approvalTimeout: Math.round(config.enforcement.approvalTimeoutMs / 1000),
      unknownToolApproval: config.policy.deterministic,
      semanticEnabled: config.semantic.enabled,
      semanticCache: config.semantic.cacheEnabled,
      semanticModel: config.semantic.model,
      semanticBaseUrl: config.semantic.baseUrl,
      semanticTimeout: config.semantic.timeoutMs,
      remoteAccess: config.dashboard.allowRemote,
      dashboardHost: config.dashboard.host,
      dashboardPort: config.dashboard.port,
      originStrict: true,
      bootstrapAuth: true,
      auditRetention: state.audit.retentionDays,
      auditBatchSize: state.audit.batchSize,
      auditHashChain: state.audit.hashChain,
      redactSecrets: true,
      ...state.notifications,
    },
    immutable: {
      originStrict: true,
      bootstrapAuth: true,
      redactSecrets: true,
    },
    restartRequired: ["remoteAccess", "dashboardHost", "dashboardPort"],
  };
}

async function applyDashboardSettings(config: PluginConfig, store: RecordStore, body: Record<string, unknown>): Promise<DashboardConsoleState> {
  const values = recordParam(body.settings) || body;
  const state = readDashboardConsoleState(store);
  const requestedProfile = String(values.enforcementProfile || "").trim();
  const requestedIntervention = String(values.interventionMode || values.intervention_mode || "").trim();
  if (requestedIntervention) {
    if (!isDashboardInterventionMode(requestedIntervention)) {
      throw new Error("interventionMode must be evidence-gated or risk-based");
    }
    config.intervention.mode = requestedIntervention;
  } else if (isDashboardInterventionMode(requestedProfile)) {
    config.intervention.mode = requestedProfile;
  }
  const mode = isDashboardEnforcementMode(requestedProfile)
    ? requestedProfile
    : config.enforcement.mode;
  if (requestedProfile && !isDashboardEnforcementMode(requestedProfile) && !isDashboardInterventionMode(requestedProfile)) {
    throw new Error("enforcementProfile must be observe, approval, or block");
  }
  const approvalTimeoutMs = boundedBodyInt(values.approvalTimeout, 1, 86400, Math.round(config.enforcement.approvalTimeoutMs / 1000)) * 1000;
  const semanticEnabled = readBodyBoolean(values.semanticEnabled, config.semantic.enabled);
  const semanticCacheEnabled = readBodyBoolean(values.semanticCache, config.semantic.cacheEnabled);
  const semanticModel = boundedBodyText(values.semanticModel, config.semantic.model, 200);
  const semanticBaseUrl = validatedHttpUrl(values.semanticBaseUrl, config.semantic.baseUrl, false);
  const semanticTimeoutMs = boundedBodyInt(values.semanticTimeout, 100, 60000, config.semantic.timeoutMs);
  const allowRemote = readBodyBoolean(values.remoteAccess, config.dashboard.allowRemote);
  const dashboardHost = boundedBodyText(values.dashboardHost, config.dashboard.host, 255);
  const dashboardPort = boundedBodyInt(values.dashboardPort, 1, 65535, config.dashboard.port);
  if (!isLoopbackHost(dashboardHost) && !allowRemote) {
    throw new Error("non-loopback dashboard host requires remoteAccess=true");
  }
  if (!isLoopbackHost(dashboardHost) && config.dashboard.authToken.length < 32) {
    throw new Error("remote dashboard access requires dashboard.authToken with at least 32 characters");
  }
  const audit = {
    retentionDays: boundedBodyInt(values.auditRetention, 1, 3650, state.audit.retentionDays),
    batchSize: boundedBodyInt(values.auditBatchSize, 1, 1000, state.audit.batchSize),
    hashChain: readBodyBoolean(values.auditHashChain, state.audit.hashChain),
    redactSecrets: true,
  };
  const notifications = parseNotificationSettings(values, state.notifications);

  config.enforcement.mode = mode;
  config.enforcement.approvalTimeoutMs = approvalTimeoutMs;
  config.semantic.enabled = semanticEnabled;
  config.semantic.cacheEnabled = semanticCacheEnabled;
  config.semantic.model = semanticModel;
  config.semantic.baseUrl = semanticBaseUrl;
  config.semantic.timeoutMs = semanticTimeoutMs;
  config.dashboard.allowRemote = allowRemote;
  config.dashboard.host = dashboardHost;
  config.dashboard.port = dashboardPort;
  state.audit = audit;
  state.notifications = notifications;
  writeDashboardConsoleState(store, state);
  store.configureAudit({ batchSize: audit.batchSize });
  const cutoff = new Date(Date.now() - audit.retentionDays * 24 * 60 * 60 * 1000).toISOString();
  await store.pruneBefore(cutoff);
  return state;
}

function parseNotificationSettings(value: Record<string, unknown>, fallback: DashboardConsoleState["notifications"]): DashboardConsoleState["notifications"] {
  return {
    notifyHigh: readBodyBoolean(value.notifyHigh, fallback.notifyHigh),
    notifyAsk: readBodyBoolean(value.notifyAsk, fallback.notifyAsk),
    notifyIntegrity: readBodyBoolean(value.notifyIntegrity, fallback.notifyIntegrity),
    notifyResolved: readBodyBoolean(value.notifyResolved, fallback.notifyResolved),
    webhookUrl: validatedHttpUrl(value.webhookUrl, fallback.webhookUrl, true),
  };
}

async function dispatchDashboardWebhook(record: AgentSentryRecord, store: RecordStore, security: DashboardSecurity): Promise<void> {
  const settings = readDashboardConsoleState(store).notifications;
  if (!settings.webhookUrl) return;
  const kind = dashboardNotificationKind(record, settings);
  if (!kind) return;
  try {
    const response = await safeHttpPost(settings.webhookUrl, {
      schema: "agentsentry.dashboard.notification.v1",
      kind,
      record: {
        id: record.id,
        created_at: record.created_at,
        severity: record.severity,
        type: record.type,
        layer: record.layer,
        title: record.title,
        summary: record.summary,
        decision: dashboardRecordDecision(record) || null,
        run_id: record.run_id,
        session_key: record.session_key,
      },
      dashboard: `http://${formatHostForUrl(security.bindHost)}:${security.port}`,
    }, { maxBytes: 64 * 1024, timeoutMs: 4000, maxRedirects: 0 });
    if (response.status < 200 || response.status >= 300) return;
  } catch {
    // Webhook delivery is best-effort; the local alert and audit record remain authoritative.
  }
}

function dashboardNotificationKind(
  record: AgentSentryRecord,
  settings: DashboardConsoleState["notifications"],
): "high_deny" | "approval" | "integrity" | "resolved" | "" {
  const decision = dashboardRecordDecision(record);
  const text = `${record.type} ${record.layer} ${record.title} ${record.summary} ${safeJson(record.payload)}`;
  if (settings.notifyResolved && record.payload?.status === "resolved") return "resolved";
  if (settings.notifyIntegrity && /foundation integrity|manifest|digest|integrity|完整性/i.test(text)) return "integrity";
  if (settings.notifyHigh && (decision === "deny" || record.severity === "danger")) return "high_deny";
  if (settings.notifyAsk && decision === "ask") return "approval";
  return "";
}

function boundedBodyInt(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function boundedBodyText(value: unknown, fallback: string, maxLength: number): string {
  return typeof value === "string" && value.trim() ? value.trim().slice(0, maxLength) : fallback;
}

function validatedHttpUrl(value: unknown, fallback: string, allowEmpty: boolean): string {
  if (value === undefined) return fallback;
  const text = typeof value === "string" ? value.trim() : "";
  if (!text && allowEmpty) return "";
  try {
    const parsed = new URL(text);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error("unsupported protocol");
    return parsed.toString().replace(/\/$/, "");
  } catch {
    throw new Error("URL must use http or https");
  }
}

function alertIdsFromBody(body: Record<string, unknown>): string[] {
  const values = Array.isArray(body.alertIds) ? body.alertIds : [body.alertId || body.id];
  return Array.from(new Set(values.map((value) => String(value || "").trim()).filter(Boolean))).slice(0, 1000);
}

function parseAlertDisposition(value: unknown): AlertDisposition | undefined {
  return value === "open" || value === "investigating" || value === "resolved" || value === "suppressed" ? value : undefined;
}

function addDashboardAuditRecord(
  store: RecordStore,
  title: string,
  summary: string,
  payload: Record<string, unknown>,
  severity: RecordSeverity = "info",
): AgentSentryRecord {
  return store.add({
    run_id: `dashboard_${Date.now().toString(36)}`,
    session_key: "dashboard:operations",
    type: "runtime",
    layer: "Evidence Feedback",
    severity,
    title,
    summary,
    payload,
  });
}

function attachAuditHashChain(records: AgentSentryRecord[], enabled: boolean): AgentSentryRecord[] {
  if (!enabled) return records.map(stripAuditHashes);
  return records.map((record) => {
    const previousHash = auditHashField(record, "previous_hash");
    const eventHash = auditHashField(record, "event_hash");
    if (!previousHash || !eventHash) return record;
    return {
      ...record,
      previous_hash: previousHash,
      event_hash: eventHash,
      payload: { ...record.payload, previous_hash: previousHash, event_hash: eventHash },
    };
  });
}

function verifyAuditHashChain(records: AgentSentryRecord[], enabled: boolean): Record<string, unknown> {
  if (!enabled) return { ok: true, enabled: false, verified: false, complete: false, count: 0, unhashedCount: records.length, reason: "hash chain disabled" };
  let valid = true;
  let count = 0;
  let unhashedCount = 0;
  let reason = "";
  const hashed: Array<{ record: AgentSentryRecord; previousHash: string; eventHash: string }> = [];
  const eventOwners = new Map<string, AgentSentryRecord>();
  for (const record of records) {
    const previousHash = auditHashField(record, "previous_hash");
    const eventHash = auditHashField(record, "event_hash");
    if (!previousHash && !eventHash) {
      unhashedCount += 1;
      continue;
    }
    if (!previousHash || !eventHash) {
      valid = false;
      reason = `record ${record.id} has an incomplete audit hash pair`;
      break;
    }
    if (eventOwners.has(eventHash)) {
      valid = false;
      reason = `duplicate event hash on record ${record.id}`;
      break;
    }
    const expected = computeAuditEventHash(record, previousHash);
    if (expected !== eventHash) {
      valid = false;
      reason = `record ${record.id} event hash mismatch`;
      break;
    }
    count += 1;
    eventOwners.set(eventHash, record);
    hashed.push({ record, previousHash, eventHash });
  }
  const referenced = new Map<string, number>();
  for (const item of hashed) {
    if (eventOwners.has(item.previousHash)) referenced.set(item.previousHash, (referenced.get(item.previousHash) || 0) + 1);
  }
  if (valid && hashed.length) {
    const roots = hashed.filter((item) => !eventOwners.has(item.previousHash));
    const segments = roots.length;
    if (segments > 1 && unhashedCount === 0) {
      valid = false;
      reason = "audit hash chain contains multiple disconnected segments";
    }
    if (hashed.some((item) => (referenced.get(item.eventHash) || 0) > 1)) {
      valid = false;
      reason = "audit hash chain contains a fork";
    }
  }
  const roots = hashed.filter((item) => !eventOwners.has(item.previousHash));
  const terminals = hashed.filter((item) => !referenced.has(item.eventHash));
  const firstEventHash = roots[0]?.eventHash || null;
  const lastEventHash = terminals[0]?.eventHash || null;
  const segments = roots.length;
  return {
    ok: true,
    enabled: true,
    verified: valid,
    complete: valid && unhashedCount === 0 && count === records.length,
    count,
    unhashedCount,
    segments,
    firstEventHash,
    lastEventHash,
    checkedAt: new Date().toISOString(),
    algorithm: "sha256",
    mode: "persisted-event-chain",
    anchor: roots.some((item) => item.previousHash === AUDIT_GENESIS_HASH) ? "genesis" : "window",
    ...(reason ? { reason } : {}),
  };
}

function auditHashField(record: AgentSentryRecord, field: "previous_hash" | "event_hash"): string {
  const direct = record[field];
  if (typeof direct === "string" && /^[a-f0-9]{64}$/i.test(direct)) return direct.toLowerCase();
  const legacy = record.payload?.[field];
  return typeof legacy === "string" && /^[a-f0-9]{64}$/i.test(legacy) ? legacy.toLowerCase() : "";
}

function stripAuditHashes(record: AgentSentryRecord): AgentSentryRecord {
  const payload = { ...record.payload };
  delete payload.previous_hash;
  delete payload.event_hash;
  const next = { ...record, payload };
  delete next.previous_hash;
  delete next.event_hash;
  return next;
}


function requireToolManifest(value: unknown): ToolSecurityManifest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("manifest must be an object");
  const manifest = value as Record<string, unknown>;
  const toolId = typeof manifest.toolId === "string" ? manifest.toolId.trim() : "";
  const aliases = Array.isArray(manifest.aliases) ? manifest.aliases.filter((item): item is string => typeof item === "string" && Boolean(item.trim())).map((item) => item.trim()) : [];
  const dataOrigins = Array.isArray(manifest.dataOrigins) ? manifest.dataOrigins : [];
  const sideEffects = Array.isArray(manifest.sideEffects) ? manifest.sideEffects : [];
  const trust = manifest.defaultTrust;
  if (!toolId || !dataOrigins.length || !sideEffects.length || !["trusted", "workspace", "external", "unknown"].includes(String(trust))) {
    throw new Error("manifest is missing required security fields");
  }
  if (dataOrigins.some((item) => typeof item !== "string") || sideEffects.some((item) => typeof item !== "string")
    || typeof manifest.acceptsSensitiveData !== "boolean"
    || typeof manifest.canExfiltrate !== "boolean"
    || typeof manifest.requiresExplicitAuthorization !== "boolean") {
    throw new Error("manifest contains invalid security fields");
  }
  return {
    toolId,
    aliases,
    dataOrigins: dataOrigins as ToolSecurityManifest["dataOrigins"],
    sideEffects: sideEffects as ToolSecurityManifest["sideEffects"],
    acceptsSensitiveData: manifest.acceptsSensitiveData,
    canExfiltrate: manifest.canExfiltrate,
    requiresExplicitAuthorization: manifest.requiresExplicitAuthorization,
    defaultTrust: trust as ToolSecurityManifest["defaultTrust"],
  };
}

function bootstrapDecisionMetrics(records: AgentSentryRecord[], iterations: number): Record<string, unknown> {
  const decisions = records
    .filter((record) => record.type === "tool_decision" || record.type === "sidecar_policy_decision")
    .map((record) => String(record.payload?.decision || record.payload?.verdict || "").toLowerCase())
    .filter(Boolean);
  const base = decisionRates(decisions);
  const samples: Record<string, number[]> = { allow: [], ask: [], deny: [] };
  if (decisions.length) {
    let seed = createHash("sha256").update(decisions.join("|")).digest().readUInt32BE(0) || 1;
    const random = () => {
      seed = (1664525 * seed + 1013904223) >>> 0;
      return seed / 0x100000000;
    };
    for (let i = 0; i < iterations; i += 1) {
      const resampled: string[] = [];
      for (let j = 0; j < decisions.length; j += 1) {
        resampled.push(decisions[Math.floor(random() * decisions.length)] || "");
      }
      const rates = decisionRates(resampled);
      samples.allow.push(rates.allowRate);
      samples.ask.push(rates.askRate);
      samples.deny.push(rates.denyRate);
    }
  }
  return {
    ok: true,
    records: records.length,
    decisions: decisions.length,
    iterations,
    rates: base,
    confidence_intervals: {
      allow_rate: percentileInterval(samples.allow),
      ask_rate: percentileInterval(samples.ask),
      deny_rate: percentileInterval(samples.deny),
    },
  };
}

function decisionRates(decisions: string[]): { allow: number; ask: number; deny: number; allowRate: number; askRate: number; denyRate: number } {
  const allow = decisions.filter((item) => item === "allow" || item === "pass").length;
  const ask = decisions.filter((item) => item === "ask" || item === "require_approval").length;
  const deny = decisions.filter((item) => item === "deny" || item === "block").length;
  const total = Math.max(1, decisions.length);
  return {
    allow,
    ask,
    deny,
    allowRate: allow / total,
    askRate: ask / total,
    denyRate: deny / total,
  };
}

function percentileInterval(values: number[]): { low: number; high: number } | null {
  if (!values.length) return null;
  const sorted = [...values].sort((left, right) => left - right);
  const at = (q: number) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.floor(q * (sorted.length - 1))))] || 0;
  return { low: at(0.025), high: at(0.975) };
}

function isDashboardEnforcementMode(value: string): value is DashboardEnforcementMode {
  return ENFORCEMENT_MODES.some((mode) => mode.value === value);
}

function isDashboardInterventionMode(value: string): value is DashboardInterventionMode {
  return INTERVENTION_MODES.some((mode) => mode.value === value) || isInterventionMode(value);
}

const LAB_BENCHMARK_FILES = [
  {
    suiteKey: "comprehensive",
    suite: "综合攻击回归",
    description: "覆盖外部内容注入、记忆投毒、MCP 工具劫持和工具型提示注入。",
    casePaths: [
      "reports/benchmark_risk_tiered/benchmark_cases.risk_tiered.jsonl",
      "reports/benchmark_eval/benchmark_cases.latest.jsonl",
    ],
    resultPaths: [
      "reports/benchmark_risk_tiered/benchmark_eval_results.risk_tiered.json",
      "reports/benchmark_eval/benchmark_eval_results.latest.json",
    ],
  },
  {
    suiteKey: "tool_attack",
    suite: "工具攻击专项",
    description: "覆盖 MCP 工具投毒、恶意参数、Shell/RCE、敏感文件和直接有害工具任务。",
    casePaths: [
      "reports/benchmark_risk_tiered/tool_attack_cases.risk_tiered.jsonl",
      "reports/tool_attack_benchmark/tool_attack_cases.latest.jsonl",
    ],
    resultPaths: [
      "reports/benchmark_risk_tiered/tool_attack_benchmark_results.risk_tiered.json",
      "reports/tool_attack_benchmark/tool_attack_benchmark_results.latest.json",
    ],
  },
] as const;

type LabBenchmarkCase = {
  id: string;
  suite_key: string;
  suite: string;
  case_id: string;
  source: string;
  source_ref: string;
  category: string;
  scenario: string;
  command: string;
  attack: boolean;
  expectation: string;
  tool: string;
  target: string;
  params?: Record<string, unknown>;
  reset_session: boolean;
  client_id: string;
  notes: string;
  result?: Record<string, unknown>;
};

function buildLabBenchmarkResponse(url: URL): Record<string, unknown> {
  const root = findAgentSentryRepoRoot();
  const limit = clampInt(url.searchParams.get("limit"), 1, 5000, 1000);
  const suiteFilter = normalizeFilter(url.searchParams.get("suite"));
  const sourceFilter = normalizeFilter(url.searchParams.get("source"));
  const categoryFilter = normalizeFilter(url.searchParams.get("category"));
  const query = normalizeFilter(url.searchParams.get("q"));
  const resultMaps = loadBenchmarkResultMaps(root);
  const files: Array<Record<string, unknown>> = [];
  const allCases: LabBenchmarkCase[] = [];

  for (const spec of LAB_BENCHMARK_FILES) {
    const casePath = firstExistingPath(root, spec.casePaths);
    if (!casePath) {
      files.push({
        suite_key: spec.suiteKey,
        suite: spec.suite,
        description: spec.description,
        exists: false,
        candidates: spec.casePaths,
      });
      continue;
    }
    const parsed = readBenchmarkJsonl(casePath, spec.suiteKey, spec.suite, resultMaps.get(spec.suiteKey) || new Map());
    files.push({
      suite_key: spec.suiteKey,
      suite: spec.suite,
      description: spec.description,
      exists: true,
      path: displayRepoPath(root, casePath),
      count: parsed.length,
    });
    allCases.push(...parsed);
  }

  const filtered = allCases.filter((item) => {
    if (suiteFilter && normalizeFilter(item.suite_key) !== suiteFilter) return false;
    if (sourceFilter && normalizeFilter(item.source) !== sourceFilter) return false;
    if (categoryFilter && normalizeFilter(item.category) !== categoryFilter) return false;
    if (!query) return true;
    const haystack = normalizeFilter([
      item.case_id,
      item.source,
      item.source_ref,
      item.category,
      item.scenario,
      item.command,
      item.tool,
      item.target,
      item.notes,
      safeJson(item.params),
    ].join("\n"));
    return haystack.includes(query);
  });

  filtered.sort((a, b) => {
    const source = a.source.localeCompare(b.source);
    if (source) return source;
    const category = a.category.localeCompare(b.category);
    if (category) return category;
    return a.case_id.localeCompare(b.case_id);
  });

  const sources = summarizeBenchmarkCases(filtered, (item) => item.source);
  const categories = summarizeBenchmarkCases(filtered, (item) => item.category);
  return {
    ok: true,
    root: root ? displayRepoPath(root, root) || root : "",
    files,
    total: filtered.length,
    available_total: allCases.length,
    returned: Math.min(filtered.length, limit),
    limit,
    sources,
    categories,
    cases: filtered.slice(0, limit),
  };
}

function readBenchmarkJsonl(filePath: string, suiteKey: string, suite: string, results: Map<string, Record<string, unknown>>): LabBenchmarkCase[] {
  const output: LabBenchmarkCase[] = [];
  const lines = readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const raw = JSON.parse(trimmed) as Record<string, unknown>;
      const caseId = String(raw.case_id || `${suiteKey}:${index + 1}`);
      const params = recordParam(raw.params);
      output.push({
        id: `${suiteKey}:${caseId}`,
        suite_key: suiteKey,
        suite,
        case_id: caseId,
        source: String(raw.source || "-"),
        source_ref: String(raw.source_ref || ""),
        category: String(raw.category || "uncategorized"),
        scenario: String(raw.scenario || "manual"),
        command: String(raw.command || ""),
        attack: Boolean(raw.attack),
        expectation: String(raw.expectation || ""),
        tool: String(raw.tool || ""),
        target: String(raw.target || ""),
        params: params || undefined,
        reset_session: raw.reset_session !== false,
        client_id: String(raw.client_id || `bench-${suiteKey}-${index + 1}`).replace(/[^\w:.-]/g, "_").slice(0, 80),
        notes: String(raw.notes || ""),
        result: results.get(caseId),
      });
    } catch {
      // Keep the dashboard responsive even if a third-party JSONL line is malformed.
    }
  }
  return output;
}

function loadBenchmarkResultMaps(root: string): Map<string, Map<string, Record<string, unknown>>> {
  const maps = new Map<string, Map<string, Record<string, unknown>>>();
  for (const spec of LAB_BENCHMARK_FILES) {
    const resultPath = firstExistingPath(root, spec.resultPaths);
    const resultMap = new Map<string, Record<string, unknown>>();
    if (resultPath) {
      try {
        const parsed = JSON.parse(readFileSync(resultPath, "utf8")) as Record<string, unknown>;
        const results = Array.isArray(parsed.results) ? parsed.results : [];
        for (const item of results) {
          if (!item || typeof item !== "object") continue;
          const result = item as Record<string, unknown>;
          const rawCase = result.case && typeof result.case === "object" ? result.case as Record<string, unknown> : {};
          const caseId = String(rawCase.case_id || "");
          if (!caseId) continue;
          const decisions = Array.isArray(result.decisions) ? result.decisions.slice(0, 4).map((decision) => {
            const value = decision && typeof decision === "object" ? decision as Record<string, unknown> : {};
            return {
              toolName: value.toolName,
              normalized_tool: value.normalized_tool,
              decision: value.decision,
              risk_score: value.risk_score,
              violations: Array.isArray(value.violations) ? value.violations.slice(0, 4) : [],
              findings: value.findings,
            };
          }) : [];
          resultMap.set(caseId, {
            ok: Boolean(result.ok),
            protected: Boolean(result.protected),
            unsafe_release: Boolean(result.unsafe_release),
            false_positive: Boolean(result.false_positive),
            allowed_all: Boolean(result.allowed_all),
            harness_error: result.harness_error || "",
            latency_ms: result.latency_ms,
            decision_sequence: Array.isArray(result.decision_sequence) ? result.decision_sequence.slice(0, 8) : [],
            decisions,
            semantic_judge: result.semantic_judge,
          });
        }
      } catch {
        // Results are optional. The original/mapped benchmark cases are still usable without them.
      }
    }
    maps.set(spec.suiteKey, resultMap);
  }
  return maps;
}

function summarizeBenchmarkCases(cases: LabBenchmarkCase[], keyFn: (item: LabBenchmarkCase) => string): Array<Record<string, unknown>> {
  const map = new Map<string, { name: string; count: number; attack: number; benign: number }>();
  for (const item of cases) {
    const name = keyFn(item) || "-";
    const current = map.get(name) || { name, count: 0, attack: 0, benign: 0 };
    current.count += 1;
    if (item.attack) current.attack += 1;
    else current.benign += 1;
    map.set(name, current);
  }
  return [...map.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

function findAgentSentryRepoRoot(): string {
  const candidates = [
    process.env.AGENTSENTRY_REPO_ROOT,
    process.cwd(),
    process.env.HOME ? join(process.env.HOME, "AgentSentry-") : "",
    "/home/ubuntu/AgentSentry-",
    resolve(fileURLToPath(new URL(".", import.meta.url)), "..", "..", ".."),
  ].filter(Boolean) as string[];
  for (const candidate of candidates) {
    const root = resolve(candidate);
    if (existsSync(join(root, "openclaw-plugin")) && existsSync(join(root, "reports"))) return root;
  }
  return resolve(process.cwd());
}

function firstExistingPath(root: string, paths: readonly string[]): string | null {
  for (const item of paths) {
    const filePath = resolve(root, item);
    if (existsSync(filePath)) return filePath;
  }
  return null;
}

function displayRepoPath(root: string, filePath: string): string {
  const normalizedRoot = normalize(root);
  const normalizedPath = normalize(filePath);
  if (normalizedPath === normalizedRoot) return ".";
  if (normalizedPath.startsWith(`${normalizedRoot}/`)) return normalizedPath.slice(normalizedRoot.length + 1);
  return normalizedPath;
}

function normalizeFilter(value: string | null): string {
  return String(value || "").trim().toLowerCase();
}

function compactPayload(record: AgentSentryRecord): Record<string, unknown> {
  const payload = record.payload || {};
  const compact: Record<string, unknown> = {};
  for (const key of [
    "toolName",
    "normalized_tool",
    "tool",
    "role",
    "stopReason",
    "decision",
    "original_decision",
    "verdict",
    "risk_score",
    "sentry_score",
    "deterministic_block",
    "approval_cache_hit",
    "execution_status",
    "ok",
    "grouped",
    "count",
    "confidence",
    "scenario",
    "source",
    "phase",
    "command_id",
    "toolCallId",
    "openclaw_session_key",
  ]) {
    if (payload[key] !== undefined) compact[key] = payload[key];
  }
  if (typeof payload.reason === "string") compact.reason = payload.reason.slice(0, 180);
  if (typeof payload.summary === "string") compact.summary = payload.summary.slice(0, 180);
  if (typeof payload.preview === "string") compact.preview = payload.preview.slice(0, 220);
  if (typeof payload.command === "string") compact.command = payload.command.slice(0, 220);
  if (typeof payload.reply === "string") compact.reply = payload.reply.slice(0, 220);
  if (Array.isArray(payload.violations)) compact.violations = payload.violations.slice(0, 3).map((item) => String(item).slice(0, 160));
  if (Array.isArray(payload.reasons)) compact.reasons = payload.reasons.slice(0, 2).map((item) => String(item).slice(0, 160));
  if (Array.isArray(payload.findings)) {
    compact.findings = payload.findings.slice(0, 3).map(compactFinding);
    compact.finding_count = payload.findings.length;
  }
  if (Array.isArray(payload.paths)) compact.paths = payload.paths.slice(0, 6);
  if (payload.omitted_paths !== undefined) compact.omitted_paths = payload.omitted_paths;
  if (payload.task_spec && typeof payload.task_spec === "object") {
    const taskSpec = payload.task_spec as Record<string, unknown>;
    compact.task_spec = {
      capabilities: Array.isArray(taskSpec.capabilities) ? taskSpec.capabilities.slice(0, 12) : undefined,
      allowed_tools: Array.isArray(taskSpec.allowed_tools) ? taskSpec.allowed_tools.slice(0, 12) : undefined,
      allowed_targets: Array.isArray(taskSpec.allowed_targets) ? taskSpec.allowed_targets.slice(0, 3) : undefined,
    };
  }
  compact.__compact = true;
  compact.__payload_bytes = Buffer.byteLength(JSON.stringify(payload));
  if (typeof record.event_hash === "string") compact.event_hash = record.event_hash;
  if (typeof record.previous_hash === "string") compact.previous_hash = record.previous_hash;
  return compact;
}

function compactFinding(finding: unknown): Record<string, unknown> | unknown {
  if (!finding || typeof finding !== "object") return finding;
  const source = finding as Record<string, unknown>;
  const next: Record<string, unknown> = {};
  for (const key of ["id", "type", "finding_type", "verdict", "severity", "reason", "confidence", "layer"]) {
    if (source[key] !== undefined) next[key] = source[key];
  }
  if (typeof next.reason === "string") next.reason = next.reason.slice(0, 140);
  return next;
}

function serveStaticFile(req: IncomingMessage, res: ServerResponse, filePath: string, requestedPath: string): void {
  const ext = extname(filePath);
  const stats = statSync(filePath);
  const etag = `W/"${stats.size.toString(16)}-${Math.floor(stats.mtimeMs).toString(16)}"`;
  const cacheControl = staticCacheControl(ext, requestedPath);
  const acceptsGzip = COMPRESSIBLE_EXTENSIONS.has(ext) && /\bgzip\b/i.test(String(req.headers["accept-encoding"] || ""));

  res.setHeader("Content-Type", MIME_TYPES[ext] || "application/octet-stream");
  res.setHeader("Cache-Control", cacheControl);
  res.setHeader("ETag", etag);
  res.setHeader("Last-Modified", stats.mtime.toUTCString());
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (COMPRESSIBLE_EXTENSIONS.has(ext)) {
    res.setHeader("Vary", "Accept-Encoding");
  }

  if (requestMatchesEtag(req.headers["if-none-match"], etag)) {
    res.writeHead(304);
    res.end();
    return;
  }

  if (req.method === "HEAD") {
    if (!acceptsGzip) {
      res.setHeader("Content-Length", String(stats.size));
    }
    res.writeHead(200);
    res.end();
    return;
  }

  if (acceptsGzip) {
    res.setHeader("Content-Encoding", "gzip");
    res.writeHead(200);
    createReadStream(filePath).pipe(createGzip()).pipe(res);
    return;
  }

  res.setHeader("Content-Length", String(stats.size));
  res.writeHead(200);
  createReadStream(filePath).pipe(res);
}

function staticCacheControl(ext: string, requestedPath: string): string {
  if (ext === ".html") return "no-cache";
  if (requestedPath.startsWith("/vendor/")) return "public, max-age=31536000, immutable";
  if ([".js", ".mjs", ".css", ".svg"].includes(ext)) return "public, max-age=3600, stale-while-revalidate=86400";
  if ([".png", ".jpg", ".jpeg", ".webp", ".pdf"].includes(ext)) return "public, max-age=3600, stale-while-revalidate=86400";
  return "no-cache";
}

function requestMatchesEtag(value: string | string[] | undefined, etag: string): boolean {
  if (!value) return false;
  const header = Array.isArray(value) ? value.join(",") : value;
  return header.split(",").map((item) => item.trim()).includes(etag);
}

type McpServerDescriptor = {
  name: string;
  transport: "stdio" | "http";
  command?: string;
  args?: string[];
  url?: string;
  status: "configured" | "observed";
};

function openClawConfigPaths(): string[] {
  const candidates = [
    process.env.OPENCLAW_CONFIG_PATH,
    process.env.OPENCLAW_CONFIG,
    process.env.OPENCLAW_HOME ? join(process.env.OPENCLAW_HOME, "openclaw.json") : "",
    process.env.HOME ? join(process.env.HOME, ".openclaw", "openclaw.json") : "",
    process.env.USERPROFILE ? join(process.env.USERPROFILE, ".openclaw", "openclaw.json") : "",
    join(homedir(), ".openclaw", "openclaw.json"),
  ];
  const seen = new Set<string>();
  const paths: string[] = [];
  for (const candidate of candidates) {
    if (!candidate) continue;
    if (seen.has(candidate)) continue;
    seen.add(candidate);
    if (existsSync(candidate)) paths.push(candidate);
  }
  return paths;
}

function readOpenClawConfigFile(): { path: string; value: Record<string, unknown> } {
  for (const path of openClawConfigPaths()) {
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return { path, value: parsed as Record<string, unknown> };
      }
    } catch {
      // Ignore unreadable config files and keep scanning candidates.
    }
  }
  return { path: "", value: {} };
}

function listMcpServers(_config: PluginConfig, store: RecordStore): Record<string, unknown> {
  const servers: McpServerDescriptor[] = [];
  const seen = new Set<string>();

  // 1) Declared MCP servers from OpenClaw's openclaw.json (authoritative).
  const { path: configPath, value: root } = readOpenClawConfigFile();
  const declared = firstRecordValue(
    root.mcpServers,
    recordParam(root.mcp)?.servers,
    recordParam(root.tools)?.mcpServers,
  );
  if (declared && typeof declared === "object" && !Array.isArray(declared)) {
    for (const [name, entry] of Object.entries(declared as Record<string, unknown>)) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
      const cfg = entry as Record<string, unknown>;
      const url = typeof cfg.url === "string" ? cfg.url.trim() : "";
      const command = typeof cfg.command === "string" ? cfg.command.trim() : "";
      servers.push({
        name,
        transport: url ? "http" : "stdio",
        ...(url ? { url } : {}),
        ...(command ? { command } : {}),
        ...(Array.isArray(cfg.args) ? { args: cfg.args.map((item) => String(item)) } : {}),
        status: "configured",
      });
      seen.add(name);
    }
  }

  // 2) Observed MCP servers recorded at runtime (fallback when no config file is present).
  const runtimeRegistries = store.list(5000)
    .filter((record) => record.type === "mcp_registry" && Array.isArray(record.payload?.servers))
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  for (const record of runtimeRegistries) {
    const entries = record.payload?.servers as Array<Record<string, unknown>>;
    for (const entry of entries) {
      const name = String(entry?.name || "").trim();
      if (!name || seen.has(name)) continue;
      servers.push({
        name,
        transport: entry?.url ? "http" : "stdio",
        ...(entry?.url ? { url: String(entry.url) } : {}),
        ...(entry?.command ? { command: String(entry.command) } : {}),
        ...(Array.isArray(entry?.args) ? { args: entry.args.map((item) => String(item)) } : {}),
        status: "observed",
      });
      seen.add(name);
    }
  }

  return {
    ok: true,
    configured: Boolean(configPath) || servers.some((server) => server.status === "configured"),
    configPath: configPath || null,
    servers,
    tools: servers.map((server) => `${server.name}.*`),
  };
}

function latestFoundationInventory(config: PluginConfig, store: RecordStore): {
  components: FoundationComponent[];
  source: "foundation_scan_record" | "live_scan";
  scannedAt: string;
} {
  const recordCount = store.count();
  const cached = foundationInventoryCache.get(store.recordsPath);
  if (cached && cached.recordCount === recordCount && cached.expiresAt > Date.now()) return cached.value;
  const scans = store.list(5000)
    .filter((record) => record.type === "foundation_scan" && Array.isArray(record.payload?.components))
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  let components = (scans[0]?.payload?.components || []) as FoundationComponent[];
  let source: "foundation_scan_record" | "live_scan" = scans.length ? "foundation_scan_record" : "live_scan";
  let scannedAt = scans[0]?.created_at || "";

  if (!components.length) {
    const scan = scanInitializationSurface("", config);
    components = scan.components;
    scannedAt = scan.scanned_at;
    source = "live_scan";
  }

  const value = { components, source, scannedAt };
  foundationInventoryCache.set(store.recordsPath, { expiresAt: Date.now() + 5000, recordCount, value });
  return value;
}

function listSkillInventory(config: PluginConfig, store: RecordStore): Record<string, unknown> {
  const { components, source, scannedAt } = latestFoundationInventory(config, store);

  const skills = components
    .filter((component) => component.kind === "skill")
    .map((component) => ({
      id: component.id,
      path: component.path,
      root: component.root,
      admission: component.admission,
      trust: component.trust,
      risk: component.risk,
      manifest: {
        present: component.manifest.present,
        signed: component.manifest.signed,
        declaredCapabilities: component.manifest.declaredCapabilities,
      },
    }))
    .filter((skill) => skill.path);

  return {
    ok: true,
    scanned_at: scannedAt,
    source,
    total: skills.length,
    skills,
  };
}

function listMemoryInventory(config: PluginConfig, store: RecordStore): Record<string, unknown> {
  const { components, source, scannedAt } = latestFoundationInventory(config, store);
  const entries = components
    .filter((component) => component.kind === "memory")
    .map((component) => ({
      id: component.id,
      path: component.path,
      root: component.root,
      sha256: component.sha256,
      size: component.size,
      admission: component.admission,
      trust: component.trust,
      risk: component.risk,
      integrity: component.manifest,
    }))
    .filter((entry) => entry.path);
  const memoryRecords = store.list(5000).filter((record) => isMemoryRecord(record));
  const sessions = new Map<string, { sessionKey: string; records: number; lastSeen: string; decisions: Record<string, number> }>();
  for (const record of memoryRecords) {
    const sessionKey = record.session_key || record.run_id;
    if (!sessionKey) continue;
    const current = sessions.get(sessionKey) || { sessionKey, records: 0, lastSeen: record.created_at, decisions: { allow: 0, ask: 0, deny: 0 } };
    current.records += 1;
    if (record.created_at > current.lastSeen) current.lastSeen = record.created_at;
    const decision = dashboardRecordDecision(record);
    if (decision) current.decisions[decision] = (current.decisions[decision] || 0) + 1;
    sessions.set(sessionKey, current);
  }
  const observedSessions = [...sessions.values()].sort((left, right) => right.lastSeen.localeCompare(left.lastSeen));
  return {
    ok: true,
    scanned_at: scannedAt,
    source,
    total: entries.length + observedSessions.length,
    componentCount: entries.length,
    sessionCount: observedSessions.length,
    recordCount: memoryRecords.length,
    entries,
    sessions: observedSessions,
  };
}

function firstRecordValue(...values: unknown[]): Record<string, unknown> | undefined {
  for (const value of values) {
    const record = recordParam(value);
    if (record) return record;
  }
  return undefined;
}

function isMemoryRecord(record: AgentSentryRecord): boolean {
  const payload = record.payload || {};
  const text = [
    record.type,
    record.layer,
    record.title,
    record.summary,
    payload.toolName,
    payload.normalized_tool,
    payload.tool,
    payload.namespace,
    payload.source,
  ].map((value) => String(value || "")).join(" ");
  return /memory|记忆/i.test(text);
}

function buildDashboardMetrics(store: RecordStore, limit: number): Record<string, unknown> {
  const now = Date.now();
  const allRecords = store.list(limit);
  const ranges = [
    ["24h", 24],
    ["7d", 24 * 7],
    ["30d", 24 * 30],
  ] as const;
  const output: Record<string, unknown> = {};
  for (const [key, hours] of ranges) {
    const start = now - hours * 60 * 60 * 1000;
    const records = allRecords.filter((record) => {
      const timestamp = new Date(record.created_at).getTime();
      return Number.isFinite(timestamp) && timestamp >= start && timestamp <= now;
    });
    const events = records.map(overviewEvent);
    const decisions = { allow: 0, ask: 0, deny: 0 };
    for (const event of events) {
      if (event.decision === "ALLOW") decisions.allow += 1;
      else if (event.decision === "ASK") decisions.ask += 1;
      else if (event.decision === "BLOCK") decisions.deny += 1;
    }
    const alerts = overviewAlerts(events);
    const risks = dashboardRiskBars(records, alerts);
    output[key] = {
      range: key,
      hours,
      start: new Date(start).toISOString(),
      end: new Date(now).toISOString(),
      records: records.length,
      decisions,
      taintSignals: events.filter((event) => overviewHasAny(event.text, ["taint", "untrusted", "pollut", "污染", "不可信", "external sink"])).length,
      activeSessions: new Set(events.map((event) => event.run_id).filter(Boolean)).size,
      alerts: alerts.length,
      risks,
      trend: dashboardDecisionTrend(events, start, now),
    };
  }
  return {
    ok: true,
    generated_at: new Date(now).toISOString(),
    limit,
    totalRecords: store.count(),
    ranges: output,
  };
}

function dashboardRiskBars(records: AgentSentryRecord[], alerts: Array<Record<string, unknown>>): Array<[string, number, string]> {
  const groups: Array<[string, RegExp, string]> = [
    ["提示注入", /prompt.?injection|注入|hidden|calendar|workspace_injection|外发|taint|external.?sink/i, "warn"],
    ["工具劫持", /hijack|backdoor|manifest|unregistered|后门|process_sales|deeptrap_r3|恶意.?skill/i, "danger"],
    ["记忆污染", /memory.?poison|memory_write|记忆污染|记忆投毒|deeptrap_r2|env-auditor|假 SOP/i, "danger"],
  ];
  const values = records.map((record) => `${record.title} ${record.summary} ${record.layer} ${safeJson(record.payload)}`);
  const bars: Array<[string, number, string]> = groups.map(([label, matcher, tone]) => {
    const count = values.filter((value) => matcher.test(value)).length
      + alerts.filter((alert) => matcher.test(`${String(alert.rule || "")} ${String(alert.type || "")} ${String(alert.reason || "")}`)).length;
    return [label, Math.min(100, count ? Math.max(8, Math.round(count / Math.max(1, records.length) * 100)) : 0), tone];
  });
  return bars.filter(([, value]) => value > 0);
}

function dashboardDecisionTrend(events: OverviewEvent[], start: number, end: number): { allow: number[]; ask: number[]; deny: number[] } {
  const result = { allow: Array(12).fill(0), ask: Array(12).fill(0), deny: Array(12).fill(0) };
  const span = Math.max(1, end - start);
  for (const event of events) {
    const key = event.decision === "ALLOW" ? "allow" : event.decision === "ASK" ? "ask" : event.decision === "BLOCK" ? "deny" : "";
    if (!key) continue;
    const timestamp = new Date(event.created_at).getTime();
    if (!Number.isFinite(timestamp)) continue;
    const index = Math.min(11, Math.max(0, Math.floor(((timestamp - start) / span) * 12)));
    result[key][index] += 1;
  }
  return result;
}

function dashboardRecordDecision(record: AgentSentryRecord): "allow" | "ask" | "deny" | "" {
  const payload = record.payload || {};
  const value = String(payload.decision || payload.verdict || payload.action || "").toLowerCase();
  if (["allow", "pass", "allowed", "success"].includes(value)) return "allow";
  if (["ask", "review", "require_approval", "approval"].includes(value)) return "ask";
  if (["deny", "block", "blocked", "reject"].includes(value)) return "deny";
  return "";
}

function sendJson(req: IncomingMessage, res: ServerResponse, body: unknown, status = 200): void {
  sendJsonBody(req, res, JSON.stringify(body), status);
}

function sendRawJson(req: IncomingMessage, res: ServerResponse, body: string, status = 200): void {
  sendJsonBody(req, res, body, status);
}

function sendJsonBody(req: IncomingMessage, res: ServerResponse, body: string, status = 200): void {
  const acceptsGzip = body.length >= 1024 && /\bgzip\b/i.test(String(req.headers["accept-encoding"] || ""));
  const headers: Record<string, string> = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };
  if (acceptsGzip) {
    headers["Content-Encoding"] = "gzip";
    headers.Vary = "Accept-Encoding";
    res.writeHead(status, headers);
    const gzip = createGzip();
    gzip.pipe(res);
    gzip.end(body);
    return;
  }
  headers["Content-Length"] = String(Buffer.byteLength(body));
  res.writeHead(status, headers);
  res.end(body);
}

function proxyJson(host: string, port: number, path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host,
        port,
        path,
        method: "GET",
        headers: { Accept: "application/json" },
        timeout: 10000,
      },
      (upstream) => {
        const chunks: Buffer[] = [];
        upstream.on("data", (chunk: Buffer) => chunks.push(chunk));
        upstream.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          if ((upstream.statusCode || 500) >= 400) {
            reject(new Error(`upstream ${upstream.statusCode}: ${body.slice(0, 180)}`));
            return;
          }
          resolve(body);
        });
      },
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy(new Error("upstream timeout"));
    });
    req.end();
  });
}

function readJsonBody(req: IncomingMessage, maxBytes: number): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("error", reject);
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8").trim();
      if (!text) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(text) as Record<string, unknown>);
      } catch {
        reject(new Error("invalid JSON body"));
      }
    });
  });
}

function sendDownload(res: ServerResponse, contentType: string, filename: string, body: string): void {
  res.writeHead(200, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Content-Disposition": `attachment; filename="${filename}"`,
  });
  res.end(body);
}

function sendText(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(body);
}

function clampInt(value: string | null, min: number, max: number, defaultValue: number): number {
  if (value === null || value.trim() === "") return defaultValue;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return defaultValue;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function recordsToCsv(records: AgentSentryRecord[]): string {
  const headers = ["id", "created_at", "severity", "type", "layer", "title", "summary", "run_id", "session_key", "payload"];
  const rows = records.map((record) => [
    record.id,
    record.created_at,
    record.severity,
    record.type,
    record.layer,
    record.title,
    record.summary,
    record.run_id,
    record.session_key,
    JSON.stringify(record.payload),
  ]);
  return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n") + "\n";
}

function csvCell(value: unknown): string {
  const text = String(value ?? "");
  return `"${text.replace(/"/g, '""')}"`;
}

function dateStamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

type OverviewEvent = {
  id: string;
  run_id: string;
  source: string;
  type: string;
  layer: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
  decision: "BLOCK" | "ASK" | "ALLOW" | "";
  tool: string;
  title: string;
  reason: string;
  rule: string;
  score: number;
  created_at: string;
  text: string;
  causal_chain: string[];
  causal_graph: OverviewCausalGraph | null;
};

export type OverviewCausalGraph = {
  version: number;
  trace_kind: "attack" | "authorized" | "enforcement_bypass";
  path_id: string;
  risk: string;
  verdict: string;
  certainty: string;
  confidence: number;
  session_node_count: number;
  session_edge_count: number;
  session_path_count: number;
  snapshot_truncated: boolean;
  projection_truncated: boolean;
  path_node_ids: string[];
  path_edge_ids: string[];
  nodes: Array<Record<string, unknown>>;
  edges: Array<Record<string, unknown>>;
};

const OVERVIEW_CAUSAL_PATH_NODE_LIMIT = 12;
const OVERVIEW_CAUSAL_TOTAL_NODE_LIMIT = 16;
const OVERVIEW_CAUSAL_EDGE_LIMIT = 24;

const OVERVIEW_LAYERS: Array<[string, string]> = [
  ["Context Provenance", "上下文溯源"],
  ["State Integrity", "状态完整性"],
  ["Intent Authorization", "意图授权"],
  ["Tool Boundary", "工具边界"],
  ["Evidence Feedback", "证据回流"],
];
const OVERVIEW_TOOLS = ["webpage", "file", "email", "api", "search", "memory", "read_file", "write_file", "shell", "database"];
const OVERVIEW_MODES: Array<[string, string]> = [
  ["full", "#35f29b"],
  ["no_deterministic", "#f8b84e"],
  ["no_sentry", "#ff4d5e"],
  ["no_feedback", "#a77cff"],
  ["none", "#b64045"],
];

const alertCountCache = new Map<string, { totalRecords: number; count: number; updatedAt: number }>();

function cachedOpenClawSecurityOverview(store: RecordStore, limit: number): Record<string, unknown> {
  const stats = store.stats(Math.min(limit, 500));
  const signature = [
    store.recordsPath,
    limit,
    stats.totalRecords || 0,
    stats.latest || "",
    stats.windowRecords || 0,
  ].join(":");
  const key = `${store.recordsPath}:${limit}`;
  const cached = overviewCache.get(key);
  if (cached && cached.signature === signature && cached.expiresAt > Date.now()) {
    return cached.value;
  }
  const value = buildOpenClawSecurityOverview(store, limit);
  overviewCache.set(key, {
    signature,
    value,
    expiresAt: Date.now() + 2500,
  });
  return value;
}

function buildOpenClawSecurityOverview(store: RecordStore, limit: number): Record<string, unknown> {
  const records = store.list(limit);
  const totalRecords = store.count();
  const events = records
    .map(overviewEvent)
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;
  const current = events.filter((event) => new Date(event.created_at).getTime() >= now - dayMs);
  const previous = events.filter((event) => {
    const ts = new Date(event.created_at).getTime();
    return ts >= now - dayMs * 2 && ts < now - dayMs;
  });
  const decisions = events.filter((event) => event.decision === "ALLOW" || event.decision === "ASK" || event.decision === "BLOCK");
  const blocked = decisions.filter((event) => event.decision === "BLOCK");
  const asked = decisions.filter((event) => event.decision === "ASK");
  const allowed = decisions.filter((event) => event.decision === "ALLOW");
  const dangerous = events.filter((event) => event.severity === "CRITICAL" || event.severity === "HIGH");
  const taints = events.filter((event) => overviewHasAny(event.text, ["taint", "untrusted", "pollut", "污染", "不可信"]));
  const drift = events.filter((event) => overviewHasAny(event.text, ["drift", "taskspec", "intent", "scope", "deviat", "越权", "偏离"]));
  const memory = events.filter((event) => overviewHasAny(event.text, ["memory", "poison", "记忆", "投毒"]));
  const toolEvents = events.filter((event) => event.tool !== "agent" || overviewHasAny(event.text, ["tool", "工具", "read", "write", "call"]));
  const protectionIndex = overviewProtectionIndex(decisions, dangerous, taints);
  const riskAlerts = overviewAlerts(events);
  const alerts = overviewAlerts(events, { includeAuthorizedTrace: true });
  const allAlertCount = records.length === totalRecords ? riskAlerts.length : cachedAlertCount(store, totalRecords);
  const timeline = overviewTimeline(events);
  return {
    generated_at: new Date().toISOString(),
    source: {
      mode: "openclaw",
      primary: "OpenClaw plugin records",
      local_event_count: 0,
      openclaw_event_count: events.length,
      total_records: totalRecords,
      window_records: events.length,
      window_limit: limit,
      openclaw_available: true,
      openclaw_source: store.recordsPath,
      window: `showing latest ${events.length} of ${totalRecords} OpenClaw plugin records`,
    },
    metrics: [
      overviewMetric("total", "⌁", totalRecords, "总事件数", "Total Events", "cyan", overviewTrend(current.length, previous.length)),
      overviewMetric("blocks", "⬟", blocked.length, "高危拦截", "High Risk Blocks", "red", overviewTrendDecision(current, previous, "BLOCK")),
      overviewMetric("tools", "⚒", toolEvents.length, "工具调用", "Tool Calls", "cyan", overviewTrendTools(current, previous)),
      overviewMetric("taint", "☣", taints.length, "污染传播", "Taint Flows", "amber", overviewTrendText(current, previous, ["taint", "untrusted", "pollut", "污染", "不可信"])),
      overviewMetric("drift", "⌖", drift.length, "意图漂移", "Drift Alerts", "amber", overviewTrendText(current, previous, ["drift", "taskspec", "intent", "scope", "deviat", "越权", "偏离"])),
      overviewMetric("memory", "◇", memory.length, "记忆投毒", "Memory Poisoning", "red", overviewTrendText(current, previous, ["memory", "poison", "记忆", "投毒"])),
      overviewMetric("allowed", "✓", allowed.length, "策略放行", "Allowed", "green", overviewTrendDecision(current, previous, "ALLOW")),
      overviewMetric("pending", "?", asked.length, "待审批", "Ask / Pending", "amber", overviewTrendDecision(current, previous, "ASK")),
    ],
    lifecycle: overviewLifecycle(events),
    modes: OVERVIEW_MODES.map(([mode, color]) => [`${mode}${mode === "full" ? "（当前）" : ""}`, 0, color, [0, 0, 0, 0, 0]]),
    alerts: alerts.slice(0, 200),
    alertCount: allAlertCount,
    stages: overviewStages(events),
    rules: overviewRules(events),
    timeline,
    timelineCounts: overviewTimelineCounts(events),
    timelineLabels: overviewTimelineLabels(timeline),
    nodes: overviewNodes(events),
    meshMeta: overviewMeshMeta(events),
    protectionIndex,
    blockedHighRisk: blocked.length,
    summary: overviewSummary(events.length, blocked.length, dangerous.length, taints.length, protectionIndex),
    recentOperations: overviewOperations(events),
    runs: overviewRuns(events),
  };
}

function cachedAlertCount(store: RecordStore, totalRecords: number): number {
  const key = store.recordsPath;
  const cached = alertCountCache.get(key);
  if (cached && cached.totalRecords === totalRecords && Date.now() - cached.updatedAt < 5000) return cached.count;
  const previousTotal = cached?.totalRecords || 0;
  if (cached && totalRecords > previousTotal) {
    const addedRecords = totalRecords - previousTotal;
    const newEvents = store.list(addedRecords).map(overviewEvent);
    const count = cached.count + overviewAlerts(newEvents).length;
    alertCountCache.set(key, { totalRecords, count, updatedAt: Date.now() });
    return count;
  }
  const count = overviewAlerts(store.list(totalRecords).map(overviewEvent)).length;
  alertCountCache.set(key, { totalRecords, count, updatedAt: Date.now() });
  return count;
}

function buildOpenClawAlertPage(store: RecordStore, page: number, pageSize: number, limit: number): Record<string, unknown> {
  const records = store.list(limit);
  const totalRecords = store.count();
  const events = records
    .map(overviewEvent)
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  const consoleState = readDashboardConsoleState(store);
  const alerts = overviewAlerts(events).map((alert) => {
    const id = String(alert.id || "");
    const operation = consoleState.alerts[id];
    const derivedStatus = alert.action === "ASK" ? "investigating" : alert.action === "BLOCK" ? "open" : "resolved";
    return {
      ...alert,
      status: operation?.status || derivedStatus,
      unread: operation ? !operation.read : true,
      read: operation?.read || false,
      note: operation?.note || "",
      status_updated_at: operation?.updatedAt || null,
      status_source: operation?.status ? "operator" : "decision",
    };
  });
  const pages = Math.max(1, Math.ceil(alerts.length / pageSize));
  const safePage = Math.max(1, Math.min(pages, page));
  const start = (safePage - 1) * pageSize;
  return {
    ok: true,
    generated_at: new Date().toISOString(),
    alerts: alerts.slice(start, start + pageSize),
    page: safePage,
    pageSize,
    pages,
    totalAlerts: alerts.length,
    totalRecords,
    windowRecords: events.length,
    windowLimit: limit,
    start: alerts.length ? start + 1 : 0,
    end: Math.min(alerts.length, start + pageSize),
    source: {
      mode: "openclaw",
      primary: "OpenClaw plugin records",
      openclaw_source: store.recordsPath,
      window: `showing latest ${events.length} of ${totalRecords} OpenClaw plugin records`,
    },
  };
}

function currentAlertIds(store: RecordStore): Set<string> {
  const limit = Math.max(1, store.count());
  const page = buildOpenClawAlertPage(store, 1, Math.max(1, limit), limit);
  return new Set(Array.isArray(page.alerts) ? page.alerts.map((alert) => String(recordParam(alert)?.id || "")).filter(Boolean) : []);
}

function overviewEvent(record: AgentSentryRecord): OverviewEvent {
  const payload = record.payload && typeof record.payload === "object" ? record.payload : {};
  const text = overviewText(record, payload);
  const causalGraph = overviewCausalGraph(payload);
  return {
    id: record.id,
    run_id: record.run_id || record.session_key || "",
    source: "OpenClaw",
    type: record.type || "record",
    layer: overviewLayer(record.layer || String(payload.layer || record.type), text),
    severity: overviewSeverity(record, payload, text),
    decision: overviewDecision(record, payload, text),
    tool: overviewTool(record, payload, text),
    title: record.title || record.type || "OpenClaw Event",
    reason: overviewReason(record, payload),
    rule: overviewRule(record, payload),
    score: overviewScore(payload),
    created_at: record.created_at || new Date().toISOString(),
    text,
    causal_chain: overviewCausalChain(payload),
    causal_graph: causalGraph,
  };
}

function overviewText(record: AgentSentryRecord, payload: Record<string, unknown>): string {
  return `${record.title || ""} ${record.summary || ""} ${record.layer || ""} ${safeJson(payload)}`.toLowerCase();
}

function overviewMetric(key: string, icon: string, num: number, cn: string, en: string, type: string, trend: number): Record<string, unknown> {
  return { key, icon, num, cn, en, type, trend: Math.round(trend * 10) / 10 };
}

function overviewTrend(current: number, previous: number): number {
  if (previous <= 0) return 0;
  return ((current - previous) / previous) * 100;
}

function overviewTrendDecision(current: OverviewEvent[], previous: OverviewEvent[], decision: OverviewEvent["decision"]): number {
  return overviewTrend(current.filter((event) => event.decision === decision).length, previous.filter((event) => event.decision === decision).length);
}

function overviewTrendTools(current: OverviewEvent[], previous: OverviewEvent[]): number {
  const count = (rows: OverviewEvent[]) => rows.filter((event) => event.tool !== "agent" || overviewHasAny(event.text, ["tool", "工具", "read", "write", "call"])).length;
  return overviewTrend(count(current), count(previous));
}

function overviewTrendText(current: OverviewEvent[], previous: OverviewEvent[], markers: string[]): number {
  return overviewTrend(current.filter((event) => overviewHasAny(event.text, markers)).length, previous.filter((event) => overviewHasAny(event.text, markers)).length);
}

function overviewProtectionIndex(decisions: OverviewEvent[], dangerous: OverviewEvent[], taints: OverviewEvent[]): number {
  if (!decisions.length) return 0;
  const blocked = decisions.filter((event) => event.decision === "BLOCK").length;
  const asked = decisions.filter((event) => event.decision === "ASK").length;
  const risky = Math.max(1, dangerous.length + taints.length);
  const containment = Math.min(1, (blocked + asked * 0.6) / risky);
  const cleanAllows = decisions.filter((event) => event.decision === "ALLOW" && event.severity === "INFO").length;
  const businessFactor = cleanAllows / Math.max(1, decisions.length);
  return Math.max(0, Math.min(100, Math.round(containment * 74 + businessFactor * 24)));
}

export function overviewAlerts(
  events: OverviewEvent[],
  options: { includeAuthorizedTrace?: boolean } = {},
): Array<Record<string, unknown>> {
  let includedAuthorizedTrace = false;
  return events
    .filter((event) => {
      const isAuthorizedTrace = event.decision === "ALLOW" && event.causal_graph?.trace_kind === "authorized";
      if (isAuthorizedTrace) {
        if (includedAuthorizedTrace || !options.includeAuthorizedTrace) return false;
        includedAuthorizedTrace = true;
        return true;
      }
      return isOverviewAlertEvent(event);
    })
    .map((event) => ({
      id: event.id,
      severity: event.severity,
      type: event.causal_graph?.trace_kind === "authorized"
        ? "精确授权放行"
        : event.causal_graph?.trace_kind === "enforcement_bypass"
          ? "阻断后执行"
          : overviewAttackType(event),
      tool: event.tool,
      action: event.decision || "INFO",
      created_at: event.created_at,
      time: overviewFormatTime(event.created_at),
      reason: event.reason,
      source: event.source,
      rule: event.rule,
      score: event.score,
      causal_chain: event.causal_chain,
      causal_graph: event.causal_graph,
    }));
}

export function overviewCausalChain(payload: Record<string, unknown>): string[] {
  const candidates: unknown[] = [payload];
  if (Array.isArray(payload.findings)) candidates.push(...payload.findings);
  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;
    const row = candidate as Record<string, unknown>;
    const evidence = row.evidence && typeof row.evidence === "object" && !Array.isArray(row.evidence)
      ? row.evidence as Record<string, unknown>
      : row;
    if (!Array.isArray(evidence.causal_chain)) continue;
    const steps = evidence.causal_chain
      .filter((step): step is string => typeof step === "string" && Boolean(step.trim()))
      .map((step) => step.trim().slice(0, 180));
    if (steps.length) return overviewGraphBoundaries(steps, 12);
  }
  return [];
}

type OverviewGraphTrace = {
  traceKind: OverviewCausalGraph["trace_kind"];
  pathId: string;
  risk: string;
  verdict: string;
  certainty: string;
  confidence: number;
  nodeIds: string[];
  edgeIds: string[];
  supportNodeIds: string[];
  supportEdgeIds: string[];
};

function overviewGraphTrace(
  payload: Record<string, unknown>,
  snapshot: Record<string, unknown>,
  graphNodes: Array<Record<string, unknown>>,
  graphEdges: Array<Record<string, unknown>>,
  attackPaths: Array<Record<string, unknown>>,
  nodeById: Map<string, Record<string, unknown>>,
): OverviewGraphTrace | null {
  return overviewEnforcementBypassTrace(payload, snapshot, graphNodes, graphEdges, nodeById)
    || overviewAttackTrace(payload, attackPaths)
    || overviewAuthorizedTrace(payload, graphNodes, graphEdges, nodeById);
}

function overviewAttackTrace(
  payload: Record<string, unknown>,
  attackPaths: Array<Record<string, unknown>>,
): OverviewGraphTrace | null {
  const evidence = overviewCausalEvidence(payload);
  if (!evidence) return null;
  const pathId = overviewGraphText(evidence.path_id, 96);
  const snapshotPath = attackPaths.find((path) => overviewGraphText(path.id, 96) === pathId);
  const snapshotNodeIds = overviewGraphIds(snapshotPath?.nodeIds, 128);
  const snapshotEdgeIds = overviewGraphIds(snapshotPath?.edgeIds, 128);
  return {
    traceKind: "attack",
    pathId,
    risk: overviewGraphText(evidence.risk ?? snapshotPath?.risk, 80),
    verdict: overviewGraphText(evidence.path_verdict ?? snapshotPath?.verdict ?? "review", 24),
    certainty: overviewGraphText(evidence.path_certainty ?? snapshotPath?.certainty, 24),
    confidence: overviewGraphConfidence(evidence.path_confidence ?? snapshotPath?.confidence),
    nodeIds: snapshotNodeIds.length ? snapshotNodeIds : overviewGraphIds(evidence.node_ids, 128),
    edgeIds: snapshotEdgeIds.length ? snapshotEdgeIds : overviewGraphIds(evidence.edge_ids, 128),
    supportNodeIds: [],
    supportEdgeIds: [],
  };
}

function overviewAuthorizedTrace(
  payload: Record<string, unknown>,
  graphNodes: Array<Record<string, unknown>>,
  graphEdges: Array<Record<string, unknown>>,
  nodeById: Map<string, Record<string, unknown>>,
): OverviewGraphTrace | null {
  if (overviewGraphText(payload.decision, 24).toLowerCase() !== "allow") return null;
  const requestedTools = new Set([
    overviewGraphText(payload.normalized_tool, 96).toLowerCase(),
    overviewGraphText(payload.toolName, 96).toLowerCase(),
  ].filter(Boolean));
  if (!requestedTools.size) return null;

  const callId = typeof payload.toolCallId === "string" ? payload.toolCallId.trim() : "";
  const callIdHash = callId ? createHash("sha256").update(callId).digest("hex").slice(0, 24) : "";
  let actions = graphNodes.filter((node) => {
    if (node.kind !== "action" || node.authorized !== true) return false;
    if (overviewGraphText(node.decision, 24).toLowerCase() !== "allow") return false;
    if (overviewGraphText(node.status, 24).toLowerCase() !== "executing") return false;
    const tool = overviewGraphText(node.tool, 96).toLowerCase();
    const originalTool = overviewGraphText(node.originalTool, 96).toLowerCase();
    return requestedTools.has(tool) || requestedTools.has(originalTool);
  });
  if (callIdHash) {
    actions = actions.filter((node) => overviewGraphText(node.callIdHash, 32) === callIdHash);
  }
  const action = actions.sort((left, right) => overviewGraphSequence(right) - overviewGraphSequence(left))[0];
  if (!action) return null;
  const actionId = overviewGraphText(action.id, 96);

  const authorizes = graphEdges.find((edge) =>
    overviewGraphText(edge.to, 96) === actionId
    && overviewGraphText(edge.kind, 32) === "authorizes"
    && nodeById.get(overviewGraphText(edge.from, 96))?.kind === "capability"
  );
  if (!authorizes) return null;
  const capabilityId = overviewGraphText(authorizes.from, 96);
  const capability = nodeById.get(capabilityId);
  if (capability?.authorized !== true) return null;
  const declares = graphEdges.find((edge) =>
    overviewGraphText(edge.to, 96) === capabilityId
    && overviewGraphText(edge.kind, 32) === "declares"
    && nodeById.get(overviewGraphText(edge.from, 96))?.kind === "intent"
  );
  const targets = graphEdges.find((edge) =>
    overviewGraphText(edge.from, 96) === actionId
    && overviewGraphText(edge.kind, 32) === "targets"
    && nodeById.get(overviewGraphText(edge.to, 96))?.kind === "sink"
  );
  if (!declares || !targets) return null;
  const intentId = overviewGraphText(declares.from, 96);
  const sinkId = overviewGraphText(targets.to, 96);
  const pathEdges = [declares, authorizes, targets];
  return {
    traceKind: "authorized",
    pathId: overviewGraphText(`authorized:${actionId}`, 96),
    risk: "authorized_tool_execution",
    verdict: "allow",
    certainty: "observed",
    confidence: overviewGraphMinimumConfidence(pathEdges),
    nodeIds: [intentId, capabilityId, actionId, sinkId],
    edgeIds: pathEdges.map((edge) => overviewGraphText(edge.id, 96)),
    supportNodeIds: [],
    supportEdgeIds: [],
  };
}

function overviewEnforcementBypassTrace(
  payload: Record<string, unknown>,
  snapshot: Record<string, unknown>,
  graphNodes: Array<Record<string, unknown>>,
  graphEdges: Array<Record<string, unknown>>,
  nodeById: Map<string, Record<string, unknown>>,
): OverviewGraphTrace | null {
  const evidence = overviewEnforcementBypassEvidence(payload);
  if (!evidence) return null;
  const blockedActionId = overviewGraphText(evidence.action_node_id, 96);
  const blockedAction = nodeById.get(blockedActionId);
  if (blockedAction?.kind !== "action" || blockedAction.status !== "blocked") return null;
  const blockedCallHash = overviewGraphText(blockedAction.callIdHash, 32);
  const evidenceCallHash = overviewGraphText(evidence.call_id_hash, 32);
  if (!blockedCallHash || (evidenceCallHash && evidenceCallHash !== blockedCallHash)) return null;
  const hasLifecycleAnomaly = Array.isArray(snapshot.lifecycle_anomalies)
    && snapshot.lifecycle_anomalies.some((item) => {
      const anomaly = recordParam(item);
      return overviewGraphText(anomaly?.actionNodeId, 96) === blockedActionId
        && anomaly?.from === "blocked"
        && anomaly?.to === "succeeded";
    });
  if (!hasLifecycleAnomaly) return null;

  const blockedTool = overviewGraphText(blockedAction.tool, 96);
  const observedAction = graphNodes
    .filter((node) => node.kind === "action"
      && node.status === "observed"
      && node.authorizationReason === "post_block_execution"
      && node.synthetic === true
      && overviewGraphText(node.callIdHash, 32) === blockedCallHash
      && (!blockedTool || overviewGraphText(node.tool, 96) === blockedTool)
      && overviewGraphSequence(node) > overviewGraphSequence(blockedAction))
    .sort((left, right) => overviewGraphSequence(right) - overviewGraphSequence(left))[0];
  if (!observedAction) return null;
  const observedActionId = overviewGraphText(observedAction.id, 96);

  const blockedTargets = graphEdges.filter((edge) =>
    overviewGraphText(edge.from, 96) === blockedActionId
    && overviewGraphText(edge.kind, 32) === "targets"
  );
  const blockedSinkIds = new Set(blockedTargets.map((edge) => overviewGraphText(edge.to, 96)));
  const observedTarget = graphEdges.find((edge) =>
    overviewGraphText(edge.from, 96) === observedActionId
    && overviewGraphText(edge.kind, 32) === "targets"
    && blockedSinkIds.has(overviewGraphText(edge.to, 96))
    && nodeById.get(overviewGraphText(edge.to, 96))?.kind === "sink"
  );
  if (!observedTarget) return null;
  const sinkId = overviewGraphText(observedTarget.to, 96);
  const blockedTarget = blockedTargets.find((edge) => overviewGraphText(edge.to, 96) === sinkId);
  if (!blockedTarget) return null;

  const governs = graphEdges.find((edge) =>
    overviewGraphText(edge.to, 96) === observedActionId
    && overviewGraphText(edge.kind, 32) === "governs"
    && nodeById.get(overviewGraphText(edge.from, 96))?.kind === "intent"
  );
  const pathEdges = governs ? [governs, observedTarget] : [observedTarget];
  const pathNodes = governs
    ? [overviewGraphText(governs.from, 96), observedActionId, sinkId]
    : [observedActionId, sinkId];
  return {
    traceKind: "enforcement_bypass",
    pathId: overviewGraphText(`enforcement-bypass:${blockedActionId}`, 96),
    risk: "execution_after_block",
    verdict: "critical",
    certainty: "observed",
    confidence: 1,
    nodeIds: pathNodes,
    edgeIds: pathEdges.map((edge) => overviewGraphText(edge.id, 96)),
    supportNodeIds: [blockedActionId],
    supportEdgeIds: [overviewGraphText(blockedTarget.id, 96)],
  };
}

function overviewEnforcementBypassEvidence(payload: Record<string, unknown>): Record<string, unknown> | null {
  const candidates: unknown[] = [payload];
  if (Array.isArray(payload.findings)) candidates.push(...payload.findings);
  for (const candidate of candidates) {
    const row = recordParam(candidate);
    const evidence = recordParam(row?.evidence) || row;
    if (!evidence) continue;
    if (evidence.event === "enforcement_bypass"
      && evidence.execution_status === "executed_after_block"
      && overviewGraphText(evidence.action_node_id, 96)) return evidence;
  }
  return null;
}

function overviewGraphSequence(node: Record<string, unknown>): number {
  const sequence = Number(node.sequence);
  return Number.isFinite(sequence) ? Math.max(0, Math.trunc(sequence)) : 0;
}

function overviewGraphMinimumConfidence(edges: Array<Record<string, unknown>>): number {
  return edges.reduce((minimum, edge) => Math.min(minimum, overviewGraphConfidence(edge.confidence)), 1);
}

export function overviewCausalGraph(payload: Record<string, unknown>): OverviewCausalGraph | null {
  const trust = recordParam(payload.trust);
  const snapshot = recordParam(trust?.semantic_action_graph);
  if (!snapshot || Number(snapshot.version) !== 2) return null;

  const graphNodes = Array.isArray(snapshot.nodes)
    ? snapshot.nodes.map(recordParam).filter((node): node is Record<string, unknown> => Boolean(node))
    : [];
  const graphEdges = Array.isArray(snapshot.edges)
    ? snapshot.edges.map(recordParam).filter((edge): edge is Record<string, unknown> => Boolean(edge))
    : [];
  const attackPaths = Array.isArray(snapshot.attack_paths)
    ? snapshot.attack_paths.map(recordParam).filter((path): path is Record<string, unknown> => Boolean(path))
    : [];
  const nodeById = new Map(graphNodes.map((node) => [overviewGraphText(node.id, 96), node]));
  const trace = overviewGraphTrace(payload, snapshot, graphNodes, graphEdges, attackPaths, nodeById);
  if (!trace) return null;
  const fullPathNodeIds = trace.nodeIds;
  const fullPathEdgeIds = trace.edgeIds;
  if (fullPathNodeIds.length < 2 || fullPathNodeIds.some((id) => !nodeById.has(id))) return null;

  const pathProjection = overviewGraphPathProjection(fullPathNodeIds, fullPathEdgeIds, nodeById, graphEdges);
  const pathNodeSet = new Set(pathProjection.nodeIds);
  const includedNodeIds = new Set([
    ...pathProjection.nodeIds.filter((id) => nodeById.has(id)),
    ...trace.supportNodeIds.filter((id) => nodeById.has(id)),
  ]);
  const supportEdgeKinds = new Set(["governs", "authorizes", "constrains", "requests"]);
  for (const edge of graphEdges) {
    const from = overviewGraphText(edge.from, 96);
    const to = overviewGraphText(edge.to, 96);
    const kind = overviewGraphText(edge.kind, 32);
    if (!includedNodeIds.has(to) || !supportEdgeKinds.has(kind)) continue;
    const support = nodeById.get(from);
    if (support?.kind === "intent" || support?.kind === "capability") includedNodeIds.add(from);
  }
  for (const edge of graphEdges) {
    const from = overviewGraphText(edge.from, 96);
    const to = overviewGraphText(edge.to, 96);
    if (overviewGraphText(edge.kind, 32) === "declares" && includedNodeIds.has(to)) includedNodeIds.add(from);
  }

  const supportLimit = Math.max(0, OVERVIEW_CAUSAL_TOTAL_NODE_LIMIT - pathProjection.nodeIds.length);
  const supportIds = graphNodes
    .map((node) => overviewGraphText(node.id, 96))
    .filter((id) => includedNodeIds.has(id) && !pathNodeSet.has(id))
    .slice(0, supportLimit);
  const allowedNodeIds = new Set([...pathProjection.nodeIds, ...supportIds]);
  const syntheticNodeById = new Map(pathProjection.syntheticNodes.map((node) => [String(node.id), node]));
  const nodes = [
    ...pathProjection.nodeIds.map((id) => {
      const synthetic = syntheticNodeById.get(id);
      if (synthetic) return synthetic;
      return overviewGraphNode(nodeById.get(id)!);
    }),
    ...supportIds
      .map((id) => nodeById.get(id))
      .filter((node): node is Record<string, unknown> => Boolean(node))
      .map(overviewGraphNode),
  ];
  const projectedPathEdgeIds = new Set(pathProjection.edgeIds);
  const originalPathEdgeIds = new Set(fullPathEdgeIds);
  const explicitSupportEdgeIds = new Set(trace.supportEdgeIds);
  const supportEdges = graphEdges
    .filter((edge) => {
      const id = overviewGraphText(edge.id, 96);
      const from = overviewGraphText(edge.from, 96);
      const to = overviewGraphText(edge.to, 96);
      const kind = overviewGraphText(edge.kind, 32);
      return !projectedPathEdgeIds.has(id)
        && allowedNodeIds.has(from)
        && allowedNodeIds.has(to)
        && (supportEdgeKinds.has(kind) || kind === "declares" || explicitSupportEdgeIds.has(id));
    })
    .slice(0, Math.max(0, OVERVIEW_CAUSAL_EDGE_LIMIT - pathProjection.edges.length))
    .map((edge) => overviewGraphEdge(edge, originalPathEdgeIds));
  const edges = [...pathProjection.edges, ...supportEdges];

  const connected = pathProjection.nodeIds.slice(1).every((to, index) => {
    const from = pathProjection.nodeIds[index];
    return pathProjection.edges.some((edge) => edge.from === from && edge.to === to && edge.on_path === true);
  });
  if (nodes.length < 2 || !edges.length || !connected) return null;
  return {
    version: 2,
    trace_kind: trace.traceKind,
    path_id: trace.pathId,
    risk: trace.risk,
    verdict: trace.verdict,
    certainty: trace.certainty,
    confidence: trace.confidence,
    session_node_count: overviewGraphCount(snapshot.node_count, graphNodes.length),
    session_edge_count: overviewGraphCount(snapshot.edge_count, graphEdges.length),
    session_path_count: overviewGraphCount(snapshot.path_count, attackPaths.length),
    snapshot_truncated: snapshot.snapshot_truncated === true,
    projection_truncated: snapshot.snapshot_truncated === true
      || pathProjection.syntheticNodes.length > 0
      || fullPathNodeIds.length > pathProjection.nodeIds.length
      || graphNodes.length > nodes.length
      || graphEdges.length > edges.length,
    path_node_ids: pathProjection.nodeIds,
    path_edge_ids: pathProjection.edgeIds,
    nodes,
    edges,
  };
}

type OverviewGraphPathProjection = {
  nodeIds: string[];
  edgeIds: string[];
  syntheticNodes: Array<Record<string, unknown>>;
  edges: Array<Record<string, unknown>>;
};

function overviewGraphPathProjection(
  fullNodeIds: string[],
  fullEdgeIds: string[],
  nodeById: Map<string, Record<string, unknown>>,
  graphEdges: Array<Record<string, unknown>>,
): OverviewGraphPathProjection {
  const collapsed = fullNodeIds.length > OVERVIEW_CAUSAL_PATH_NODE_LIMIT;
  const retainedOriginalLimit = collapsed ? OVERVIEW_CAUSAL_PATH_NODE_LIMIT - 1 : fullNodeIds.length;
  const headCount = collapsed ? Math.ceil(retainedOriginalLimit / 2) : fullNodeIds.length;
  const tailCount = collapsed ? Math.floor(retainedOriginalLimit / 2) : 0;
  const tailStart = collapsed ? fullNodeIds.length - tailCount : fullNodeIds.length;
  const occupiedNodeIds = new Set(nodeById.keys());
  const occupiedEdgeIds = new Set(graphEdges.map((edge) => overviewGraphText(edge.id, 96)).filter(Boolean));
  const originalPathEdgeIds = new Set(fullEdgeIds);
  const entries: Array<{ id: string; originalIndex: number | null }> = fullNodeIds
    .slice(0, headCount)
    .map((id, originalIndex) => ({ id, originalIndex }));
  const syntheticNodes: Array<Record<string, unknown>> = [];
  let omittedNodeCount = 0;
  let omittedEdgeCount = 0;

  if (collapsed) {
    omittedNodeCount = fullNodeIds.length - retainedOriginalLimit;
    omittedEdgeCount = tailStart - headCount + 1;
    const collapsedId = overviewGraphUniqueProjectionId("projection-collapsed", occupiedNodeIds);
    entries.push({ id: collapsedId, originalIndex: null });
    syntheticNodes.push({
      id: collapsedId,
      kind: "collapsed",
      label: `COLLAPSED PATH (${omittedNodeCount} omitted nodes)`,
      sequence: Math.max(0, headCount),
      effect: "display_only",
      display_only: true,
      synthetic: true,
      projection: "collapsed",
      omitted_node_count: omittedNodeCount,
      omitted_edge_count: omittedEdgeCount,
    });
    entries.push(...fullNodeIds.slice(tailStart).map((id, offset) => ({
      id,
      originalIndex: tailStart + offset,
    })));
  }

  const projectedEdges: Array<Record<string, unknown>> = [];
  for (let index = 0; index < entries.length - 1; index += 1) {
    const from = entries[index];
    const to = entries[index + 1];
    const consecutive = from.originalIndex !== null
      && to.originalIndex !== null
      && to.originalIndex === from.originalIndex + 1;
    const graphEdge = consecutive
      ? overviewGraphPathEdge(from.id, to.id, from.originalIndex!, fullEdgeIds, graphEdges)
      : null;
    if (graphEdge) {
      const projected = overviewGraphEdge(graphEdge, originalPathEdgeIds);
      projected.on_path = true;
      projectedEdges.push(projected);
      continue;
    }

    const projection = from.originalIndex === null || to.originalIndex === null ? "collapsed" : "missing_edge";
    const edgeId = overviewGraphUniqueProjectionId(`projection-summary-${index + 1}`, occupiedEdgeIds);
    const syntheticEdge: Record<string, unknown> = {
      id: edgeId,
      from: from.id,
      to: to.id,
      kind: "summary",
      on_path: true,
      basis: "conservative",
      confidence: 0,
      display_only: true,
      synthetic: true,
      projection,
    };
    if (projection === "collapsed") {
      syntheticEdge.omitted_node_count = omittedNodeCount;
      syntheticEdge.omitted_edge_count = omittedEdgeCount;
    }
    projectedEdges.push(syntheticEdge);
  }

  return {
    nodeIds: entries.map((entry) => entry.id),
    edgeIds: projectedEdges.map((edge) => String(edge.id)),
    syntheticNodes,
    edges: projectedEdges,
  };
}

function overviewGraphPathEdge(
  from: string,
  to: string,
  originalIndex: number,
  pathEdgeIds: string[],
  graphEdges: Array<Record<string, unknown>>,
): Record<string, unknown> | null {
  const expectedEdgeId = pathEdgeIds[originalIndex];
  const expected = expectedEdgeId
    ? graphEdges.find((edge) => overviewGraphText(edge.id, 96) === expectedEdgeId)
    : null;
  if (expected && overviewGraphText(expected.from, 96) === from && overviewGraphText(expected.to, 96) === to) {
    return expected;
  }
  const pathEdgeIdSet = new Set(pathEdgeIds);
  return graphEdges.find((edge) => pathEdgeIdSet.has(overviewGraphText(edge.id, 96))
    && overviewGraphText(edge.from, 96) === from
    && overviewGraphText(edge.to, 96) === to) || null;
}

function overviewGraphUniqueProjectionId(base: string, occupiedIds: Set<string>): string {
  let candidate = base;
  let suffix = 2;
  while (occupiedIds.has(candidate)) {
    candidate = `${base}-${suffix}`;
    suffix += 1;
  }
  occupiedIds.add(candidate);
  return candidate;
}

function overviewCausalEvidence(payload: Record<string, unknown>): Record<string, unknown> | null {
  const candidates: unknown[] = [payload];
  if (Array.isArray(payload.findings)) candidates.push(...payload.findings);
  const matches: Record<string, unknown>[] = [];
  for (const candidate of candidates) {
    const row = recordParam(candidate);
    const evidence = recordParam(row?.evidence) || row;
    if (!evidence) continue;
    if (overviewGraphText(evidence.path_id, 96) && (Array.isArray(evidence.node_ids) || Array.isArray(evidence.causal_chain))) {
      matches.push(evidence);
    }
  }
  return matches.sort((left, right) => overviewCausalEvidenceScore(right) - overviewCausalEvidenceScore(left))[0] || null;
}

function overviewCausalEvidenceScore(evidence: Record<string, unknown>): number {
  const verdict = overviewGraphText(evidence.path_verdict ?? evidence.verdict, 24).toLowerCase();
  const certainty = overviewGraphText(evidence.path_certainty ?? evidence.certainty, 24).toLowerCase();
  const verdictScore = verdict === "block" || verdict === "deny" ? 300 : verdict === "review" || verdict === "require_approval" ? 200 : 100;
  const certaintyScore = certainty === "observed" ? 20 : 0;
  return verdictScore + certaintyScore + overviewGraphConfidence(evidence.path_confidence ?? evidence.confidence);
}

function overviewGraphNode(node: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {
    id: overviewGraphText(node.id, 96),
    kind: overviewGraphText(node.kind, 24),
    label: overviewGraphText(node.label, 96),
    sequence: Number.isFinite(Number(node.sequence)) ? Math.max(0, Math.trunc(Number(node.sequence))) : 0,
  };
  for (const key of ["tool", "status", "decision", "path", "source", "confidentiality", "integrity", "sink", "effect"] as const) {
    const value = overviewGraphText(node[key], key === "path" || key === "source" ? 160 : 96);
    if (value) result[key] = value;
  }
  const originalTool = overviewGraphText(node.originalTool, 96);
  const authorizationReason = overviewGraphText(node.authorizationReason, 96);
  const provenanceId = overviewGraphText(node.provenanceId, 96);
  if (originalTool) result.original_tool = originalTool;
  if (authorizationReason) result.authorization_reason = authorizationReason;
  if (node.kind === "capability" && result.source) result.authorization_actor = result.source;
  if (provenanceId) result.provenance_id = provenanceId;
  if (Array.isArray(node.transformations)) {
    const transformations = node.transformations
      .map((item) => overviewGraphText(item, 64))
      .filter(Boolean)
      .slice(-8);
    if (transformations.length) result.transformations = transformations;
  }
  if (typeof node.authorized === "boolean") result.authorized = node.authorized;
  if (node.synthetic === true) result.synthetic = true;
  return result;
}

function overviewGraphEdge(edge: Record<string, unknown>, pathEdgeIds: Set<string>): Record<string, unknown> {
  const id = overviewGraphText(edge.id, 96);
  const result: Record<string, unknown> = {
    id,
    from: overviewGraphText(edge.from, 96),
    to: overviewGraphText(edge.to, 96),
    kind: overviewGraphText(edge.kind, 32),
    on_path: pathEdgeIds.has(id),
    basis: overviewGraphText(edge.basis, 24) || "observed",
    confidence: overviewGraphConfidence(edge.confidence),
  };
  const argPath = overviewGraphText(edge.argPath, 160);
  const match = overviewGraphText(edge.match, 80);
  if (argPath) result.arg_path = argPath;
  if (match) result.match = match;
  return result;
}

function overviewGraphIds(value: unknown, limit: number): string[] {
  if (!Array.isArray(value)) return [];
  return Array.from(new Set(value
    .map((item) => overviewGraphText(item, 96))
    .filter(Boolean)))
    .slice(0, limit);
}

function overviewGraphBoundaries<T>(values: T[], limit: number): T[] {
  if (limit <= 0) return [];
  if (values.length <= limit) return [...values];
  const head = Math.ceil(limit / 2);
  const tail = Math.floor(limit / 2);
  return [...values.slice(0, head), ...values.slice(-tail)];
}

function overviewGraphText(value: unknown, limit: number): string {
  return typeof value === "string"
    ? value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, limit)
    : "";
}

function overviewGraphConfidence(value: unknown): number {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(1, number)) : 0;
}

function overviewGraphCount(value: unknown, fallback = 0): number {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.trunc(number)) : Math.max(0, fallback);
}

function isOverviewAlertEvent(event: OverviewEvent): boolean {
  if (event.decision === "BLOCK" || event.decision === "ASK") return true;
  if (event.type === "runtime" && event.run_id.startsWith("dashboard_")) return false;
  if (event.decision === "ALLOW" && event.severity === "INFO") return false;
  return event.severity === "CRITICAL" || event.severity === "HIGH" || event.severity === "MEDIUM";
}

function overviewLifecycle(events: OverviewEvent[]): Array<[string, number, number]> {
  return OVERVIEW_LAYERS.map(([layer, label]) => {
    const rows = events.filter((event) => event.layer === layer);
    const risky = rows.filter((event) => event.severity !== "INFO" || event.decision === "BLOCK" || event.decision === "ASK").length;
    const contained = rows.filter((event) => event.decision === "BLOCK" || event.decision === "ASK").length;
    const pct = risky ? Math.round((contained / risky) * 100) : rows.length ? 100 : 0;
    return [label, pct, rows.length];
  });
}

function overviewStages(events: OverviewEvent[]): Array<[string, number, string, number, string]> {
  const defs: Array<[string, string]> = [
    ["溯源污染", "Context Provenance"],
    ["状态篡改", "State Integrity"],
    ["授权偏离", "Intent Authorization"],
    ["边界触发", "Tool Boundary"],
    ["证据回流", "Evidence Feedback"],
  ];
  const rows = defs.map(([name, layer]) => {
    const matched = events.filter((event) => event.layer === layer);
    const high = matched.filter((event) => event.severity !== "INFO" || event.decision === "BLOCK" || event.decision === "ASK");
    const blocked = matched.filter((event) => event.decision === "BLOCK" || event.decision === "ASK");
    return { name, matched, high, blocked };
  });
  const total = rows.reduce((sum, row) => sum + row.matched.length, 0) || 1;
  return rows.map((row) => [
    row.name,
    row.matched.length,
    `${(row.matched.length / total * 100).toFixed(1)}%`,
    row.high.length,
    `${row.high.length ? Math.round(row.blocked.length / row.high.length * 100) : 0}%`,
  ]);
}

function overviewRules(events: OverviewEvent[]): Array<[string, number, number]> {
  const counts = new Map<string, number>();
  const risky = new Map<string, number>();
  for (const event of events) {
    if (!event.rule) continue;
    counts.set(event.rule, (counts.get(event.rule) || 0) + 1);
    if (event.decision === "BLOCK" || event.decision === "ASK" || event.severity !== "INFO") risky.set(event.rule, (risky.get(event.rule) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([rule, hits]) => [rule, hits, Math.round(((risky.get(rule) || 0) / hits) * 1000) / 10]);
}

function overviewTimeline(events: OverviewEvent[]): Array<Record<string, unknown>> {
  const latest = events.slice(0, 240);
  if (!latest.length) return [];
  const times = latest.map((event) => new Date(event.created_at).getTime()).filter((value) => Number.isFinite(value));
  const start = Math.min(...times);
  const end = Math.max(...times);
  const span = Math.max(1, end - start);
  return latest.map((event) => {
    const ts = new Date(event.created_at).getTime();
    return {
      id: event.id,
      x: Math.round(((Number.isFinite(ts) ? ts - start : 0) / span) * 10000) / 10000,
      row: event.decision ? event.decision.toLowerCase() : "info",
      severity: event.severity,
      tool: event.tool,
      time: overviewFormatTime(event.created_at),
      source: event.source,
    };
  });
}

function overviewTimelineCounts(events: OverviewEvent[]): Record<string, number> {
  const counts: Record<string, number> = { block: 0, ask: 0, allow: 0, info: 0 };
  for (const event of events) {
    const key = event.decision ? event.decision.toLowerCase() : "info";
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function overviewTimelineLabels(points: Array<Record<string, unknown>>): string[] {
  const times = points.map((point) => String(point.time || "").slice(0, 5)).filter(Boolean);
  if (!times.length) return ["开始", "", "", "", "", "", "", "现在"];
  const first = times[times.length - 1];
  const last = times[0];
  return first === last ? [first, "", "", "", "", "", "", "现在"] : [first, "", "", "", "", "", last, "现在"];
}

function overviewNodes(events: OverviewEvent[]): Array<Record<string, unknown>> {
  return OVERVIEW_TOOLS.map((tool) => {
    const rows = events.filter((event) => overviewToolName(event.tool) === tool);
    const high = rows.filter((event) => event.severity === "CRITICAL" || event.severity === "HIGH" || event.decision === "BLOCK").length;
    const medium = rows.filter((event) => event.severity === "MEDIUM" || event.decision === "ASK").length;
    const risk = high ? "high" : medium ? "medium" : "low";
    return {
      name: tool,
      count: rows.length,
      risk,
      riskText: risk === "high" ? "高风险" : risk === "medium" ? "中风险" : "低风险",
      blocked: rows.filter((event) => event.decision === "BLOCK").length,
      asked: rows.filter((event) => event.decision === "ASK").length,
      allowed: rows.filter((event) => event.decision === "ALLOW").length,
    };
  });
}

function overviewMeshMeta(events: OverviewEvent[]): Record<string, unknown> {
  const apiEvents = events.filter((event) => event.tool === "api");
  const unblockedApi = apiEvents.filter((event) => event.decision !== "BLOCK").length;
  const rate = apiEvents.length ? Math.round((unblockedApi / apiEvents.length) * 1000) / 10 : 0;
  return {
    api_calls: apiEvents.length,
    success_rate: rate,
    unblocked_rate: rate,
    pollution_events: events.filter((event) => overviewHasAny(event.text, ["taint", "untrusted", "pollut", "污染", "不可信"])).length,
    policy_hits: events.filter((event) => event.rule).length,
    decision_events: events.filter((event) => event.decision).length,
  };
}

function overviewOperations(events: OverviewEvent[]): Array<Record<string, unknown>> {
  return events.slice(0, 20).map((event) => ({
    time: overviewFormatTime(event.created_at),
    source: event.source,
    type: event.type,
    tool: event.tool,
    decision: event.decision || "INFO",
    severity: event.severity,
    reason: event.reason,
  }));
}

function overviewRuns(events: OverviewEvent[]): Array<Record<string, unknown>> {
  const byRun = new Map<string, { id: string; event_count: number; created_at: string; scenario: string; task: string }>();
  for (const event of events) {
    const item = byRun.get(event.run_id) || { id: event.run_id, event_count: 0, created_at: event.created_at, scenario: "", task: "" };
    item.event_count += 1;
    if (new Date(event.created_at) > new Date(item.created_at)) item.created_at = event.created_at;
    if (!item.scenario && event.text.includes("scenario")) item.scenario = event.type;
    if (!item.task) item.task = event.title;
    byRun.set(event.run_id, item);
  }
  return [...byRun.values()].slice(0, 20).map((item) => ({
    id: item.id,
    scenario: item.scenario || "openclaw",
    defense_mode: "full",
    task: item.task,
    event_count: item.event_count,
    created_at: item.created_at,
  }));
}

function overviewSummary(total: number, blocked: number, dangerous: number, taints: number, index: number): string {
  if (!total) return "当前还没有可展示的真实审计事件。运行一次攻防用例或打开 OpenClaw 后，大屏会自动汇总工具调用、告警和策略裁决。";
  return `当前汇总 ${total} 条真实审计事件，识别 ${dangerous} 条高危/严重事件，已阻断 ${blocked} 次风险动作，跟踪 ${taints} 条污染/不可信传播记录。综合防护指数为 ${index}/100，主统计口径来自 OpenClaw plugin records。`;
}

function overviewSeverity(record: AgentSentryRecord, payload: Record<string, unknown>, text: string): OverviewEvent["severity"] {
  const raw = String(record.severity || payload.severity || "").toLowerCase();
  const score = overviewScore(payload);
  if (raw === "critical" || score >= 95 || overviewHasAny(text, ["critical", "严重"])) return "CRITICAL";
  if (raw === "danger" || raw === "high" || score >= 80 || overviewHasAny(text, [
    "high-risk",
    "高危",
    "rce",
    "exfil",
    "leak",
    "secret",
    "credential",
    "api_key",
    "private key",
    "id_rsa",
    "sensitive asset",
    "敏感",
    "外发",
    "越权",
  ])) return "HIGH";
  if (raw === "warning" || raw === "medium" || score >= 45 || overviewHasAny(text, [
    "require_approval",
    "approval",
    "ask",
    "中危",
    "warning",
    "outside taskspec",
    "deviat",
    "taint",
    "untrusted",
    "pollut",
    "不可信",
    "污染",
  ])) return "MEDIUM";
  return "INFO";
}

function overviewDecision(record: AgentSentryRecord, payload: Record<string, unknown>, text: string): OverviewEvent["decision"] {
  const raw = String(payload.decision || payload.original_decision || payload.verdict || payload.action || payload.execution_status || "").toLowerCase();
  if (overviewHasAny(raw, ["deny", "block", "blocked"]) || overviewHasAny(text, ["decision\":\"deny", "verdict\":\"block"])) return "BLOCK";
  if (overviewHasAny(raw, ["ask", "approval", "pending", "require", "skipped"])) return "ASK";
  if (overviewHasAny(raw, ["allow", "pass", "executed"])) return "ALLOW";
  if (record.type === "alert" && record.severity === "danger") return "BLOCK";
  return "";
}

function overviewLayer(raw: string, text: string): string {
  const value = raw.toLowerCase();
  if (value.includes("context") || value.includes("provenance") || value.includes("provenance")) return "Context Provenance";
  if (value.includes("state") || value.includes("integrity")) return "State Integrity";
  if (value.includes("intent") || value.includes("authorization")) return "Intent Authorization";
  if (value.includes("tool") || value.includes("execution") || value.includes("preflight") || value.includes("boundary")) return "Tool Boundary";
  if (value.includes("evidence") || value.includes("feedback") || value.includes("result") || value.includes("runtime")) return "Evidence Feedback";
  if (value.includes("input") || value.includes("message") || value.includes("llm") || overviewHasAny(text, ["prompt", "injection", "sanitize", "webpage"])) return "Context Provenance";
  if (value.includes("cognition") || value.includes("sentry") || overviewHasAny(text, ["memory", "poison", "assistant"])) return "State Integrity";
  if (value.includes("decision") || overviewHasAny(text, ["taskspec", "intent", "approval", "policy"])) return "Intent Authorization";
  if (overviewHasAny(text, ["result", "runtime", "sink", "secret", "exfil", "leak"])) return "Evidence Feedback";
  return "Tool Boundary";
}

function overviewTool(record: AgentSentryRecord, payload: Record<string, unknown>, text: string): string {
  const raw = String(payload.normalized_tool || payload.toolName || payload.tool || "");
  const joined = `${raw} ${record.title || ""} ${record.summary || ""} ${text}`.toLowerCase();
  if (overviewHasAny(joined, ["read_email", "read_pdf", "analyze_image", "read_webpage", "browser", "webpage"])) return "webpage";
  if (joined.includes("write_file")) return "write_file";
  if (joined.includes("read_file")) return "read_file";
  if (overviewHasAny(joined, ["send_email", "email", "mail"])) return "email";
  if (overviewHasAny(joined, ["call_api", " api", "fetch", "http", "request"])) return "api";
  if (overviewHasAny(joined, ["shell_exec", "shell", "command", "terminal", "cmd"])) return "shell";
  if (overviewHasAny(joined, ["memory", "remember"])) return "memory";
  if (overviewHasAny(joined, ["search", "query"])) return "search";
  if (overviewHasAny(joined, ["file"])) return "file";
  if (overviewHasAny(joined, ["sqlite", "database", "records", "runtime"])) return "database";
  return "agent";
}

function overviewToolName(tool: string): string {
  if (OVERVIEW_TOOLS.includes(tool)) return tool;
  if (tool === "agent") return "database";
  return tool;
}

function overviewReason(record: AgentSentryRecord, payload: Record<string, unknown>): string {
  const violations = Array.isArray(payload.violations) ? payload.violations.map(String).filter(Boolean) : [];
  if (violations.length) return violations.slice(0, 3).join("; ");
  const reason = String(payload.reason || payload.summary || record.summary || record.title || record.type || "");
  return reason.slice(0, 260);
}

function overviewRule(record: AgentSentryRecord, payload: Record<string, unknown>): string {
  const violations = Array.isArray(payload.violations) ? payload.violations.map(String).filter(Boolean) : [];
  if (violations.length) return violations[0].slice(0, 90);
  const reason = String(payload.reason || record.title || "");
  return reason.slice(0, 90);
}

function overviewScore(payload: Record<string, unknown>): number {
  for (const key of ["risk_score", "sentry_score", "score"]) {
    const value = payload[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }
  if (Array.isArray(payload.findings)) {
    return Math.max(0, ...payload.findings.map((item) => {
      if (item && typeof item === "object") {
        const score = (item as Record<string, unknown>).score;
        return typeof score === "number" ? score : 0;
      }
      return 0;
    }));
  }
  return 0;
}

function overviewAttackType(event: OverviewEvent): string {
  const text = `${event.text} ${event.reason || ""} ${event.rule || ""}`;
  if (overviewHasAny(text, ["enoent", "no such file", "file not found", "not found", "找不到文件", "文件不存在", "路径不存在"])) return "文件访问异常";
  if (overviewHasAny(text, ["id_rsa", ".env", "private key", "ssh", "sensitive path", "sensitive asset", "敏感路径", "敏感文件"])) return "敏感文件访问";
  if (overviewHasAny(text, ["gatewayurl", "gateway url", "evil gateway", "tool shadow", "tool poisoning", "name collision", "shadowing", "openclaw.json", "auth token", "malicious skill", "恶意 skill", "网关劫持"])) return "工具调用劫持";
  if (overviewHasAny(text, ["tool call mismatches task", "tool mismatch", "outside taskspec", "out-of-scope", "scope violation", "deviates from task intent", "任务边界", "意图偏离"])) return "任务边界偏离";
  if (overviewHasAny(text, ["memory", "webhook", "poison", "remember", "startup", "记忆", "投毒", "持久化"])) return "记忆/配置持久化";
  if (overviewHasAny(text, ["taint", "untrusted", "pollut", "contaminated", "不可信", "污染"])) return "上下文污染传播";
  if (overviewHasAny(text, ["hidden", "prompt injection", "indirect injection", "pdf", "image", "webpage", "隐藏", "注入"])) return "外部内容注入";
  if (overviewHasAny(text, ["secret", "token", "api_key", "credential", "exfil", "leak", "外发", "泄露"])) return "数据外泄风险";
  if (overviewHasAny(text, ["shell", "sudo", "chmod", "chown", "rm -", "curl ", "wget ", "命令执行"])) return "命令执行风险";
  if (event.decision === "ASK") return "人工审批事件";
  if (event.decision === "BLOCK") return "策略阻断事件";
  return "运行风险事件";
}

function overviewHasAny(text: string, markers: string[]): boolean {
  const value = String(text || "").toLowerCase();
  return markers.some((marker) => value.includes(marker.toLowerCase()));
}

function overviewFormatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value || "").slice(11, 19);
  return date.toISOString().slice(11, 19);
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

type LoggerLike = {
  info: (message: string) => void;
};
