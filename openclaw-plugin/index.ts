import { spawnSync } from "node:child_process";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { ConfigSchema, PluginConfig } from "./config.ts";
import { ApprovalCache, approvalCachePath } from "./core/approval-cache.ts";
import { handleAgentSentryCommand } from "./core/commands.ts";
import { detectMessageContent, detectToolCall, serializeToolParams } from "./core/detect.ts";
import { clearFoundationScanCache, scanFoundation } from "./core/foundation.ts";
import { computeOperationKey, formatApprovalDescription } from "./core/operation.ts";
import {
  createPolicyState,
  normalizeAction,
  policyTrustSnapshot,
  resultFindings,
  updateAfterDecision,
  updateAfterMessage,
  updateTaskSpec,
  type PolicyState,
} from "./core/policy.ts";
import { clampText, redactObject, safeStringify } from "./core/redact.ts";
import { newId, RecordStore, runIdForSession, type RecordSeverity } from "./core/records.ts";
import { deleteRuntimeConfig, loadRuntimeConfig, runtimeConfigPath, saveRuntimeConfig } from "./core/runtime-config.ts";
import { semanticJudgeMemoryWrite, semanticJudgeMessage, semanticJudgeToolCall } from "./core/semantic.ts";
import { auditRuntimeEventsSince, ebpfLogCheckpoint, systemMonitorStatus, type EbpfLogCheckpoint } from "./core/system-monitor.ts";
import { startDashboard, type DashboardServer } from "./server/dashboard.ts";

type SessionState = {
  runId: string;
  sessionKey: string;
  messageCount: number;
  toolCount: number;
  coverNextAssistantResponse: boolean;
  policyState: PolicyState;
  runtimeCheckpoints: Map<string, { checkpoint: EbpfLogCheckpoint | null; toolName: string; params: Record<string, unknown> }>;
};

const plugin = {
  id: "agent-sentry",
  name: "AgentSentry",
  description: "AgentSentry records OpenClaw lifecycle telemetry and exposes a local dashboard.",
  configSchema: ConfigSchema,
  config: null as PluginConfig | null,
  store: null as RecordStore | null,
  approvalCache: null as ApprovalCache | null,
  dashboard: null as DashboardServer | null,
  startupConfig: null as PluginConfig | null,
  sessions: new Map<string, SessionState>(),

  register(api: OpenClawPluginApi) {
    const baseConfig = PluginConfig.fromPluginConfig(api.pluginConfig);
    plugin.startupConfig = structuredClone(baseConfig);
    plugin.config = loadRuntimeConfig(baseConfig);
    plugin.store = new RecordStore(plugin.config);
    plugin.approvalCache = new ApprovalCache(plugin.config);

    api.registerService({
      id: "agent-sentry-dashboard",
      start: async () => {
        if (!plugin.config!.dashboard.enabled) return;
        plugin.dashboard = await startDashboard(plugin.config!, plugin.store!, api.logger, {
          getConfig: () => plugin.config!,
          setConfig: (nextConfig) => {
            plugin.config = nextConfig;
          },
        });
        recordRuntime("AgentSentry dashboard started", plugin.dashboard.url, { url: plugin.dashboard.url });
      },
      stop: async () => {
        if (plugin.dashboard) {
          await plugin.dashboard.close();
          plugin.dashboard = null;
        }
      },
    });

    api.registerCommand({
      name: "agentsentry",
      description: "Show AgentSentry dashboard and records location",
      acceptsArgs: true,
      requireAuth: true,
      handler: (ctx) => {
        const dashboard = plugin.dashboard?.url || `http://${plugin.config!.dashboard.host}:${plugin.config!.dashboard.port}`;
        return handleAgentSentryCommand(ctx, plugin.config!, plugin.startupConfig!, {
          dashboardUrl: dashboard,
          recordsPath: plugin.store!.recordsPath,
          runtimeConfigPath: runtimeConfigPath(plugin.config!),
          approvalCachePath: approvalCachePath(plugin.config!),
          sessionCount: plugin.sessions.size,
          approvalCacheCount: plugin.approvalCache!.size(),
          resetRecords: () => plugin.store!.reset(),
          clearFoundationCache: () => clearFoundationScanCache(),
          clearApprovalCache: () => {
            plugin.approvalCache!.reset();
          },
          setConfig: (nextConfig) => {
            plugin.config = nextConfig;
          },
          persistConfig: (nextConfig) => saveRuntimeConfig(nextConfig),
          resetRuntimeConfig: () => deleteRuntimeConfig(plugin.config!),
        });
      },
    });

    api.on("before_prompt_build", async (event, ctx) => {
      const state = getSession(ctx);
      const messageCount = Array.isArray(event?.messages) ? event.messages.length : 0;
      state.messageCount = messageCount;
      updateTaskSpec(state.policyState, event?.messages, plugin.config!);
      const workspaceDir = typeof ctx.workspaceDir === "string" ? ctx.workspaceDir : "";
      const foundation = workspaceDir ? await scanFoundation(workspaceDir, plugin.config!) : null;
      if (foundation) {
        state.policyState.foundationBlocked = foundation.blocked;
        state.policyState.foundationFindings = foundation.findings;
        const foundationSeverity = foundation.blocked ? "danger" : foundation.findings.length ? "warning" : "success";
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "foundation_scan",
          layer: "Foundation",
          severity: foundationSeverity,
          title: foundation.blocked ? "Foundation scan blocked workspace" : "Foundation scan completed",
          summary: `${foundation.findings.length} findings; ${foundation.scannedFiles} files scanned${foundation.cached ? "; cached" : ""}`,
          payload: {
            workspaceDir,
            scannedFiles: foundation.scannedFiles,
            skippedFiles: foundation.skippedFiles,
            cached: foundation.cached,
            blocked: foundation.blocked,
            findings: foundation.findings,
          },
        });
        for (const finding of foundation.findings) {
          addFinding(state, finding, { workspaceDir });
        }
        if (foundation.blocked) {
          addAlert(state, "Foundation scan found blocking workspace risk", foundation.findings.map((finding) => finding.reason).join("; "), {
            workspaceDir,
            findings: foundation.findings,
          });
          sendProactiveNotification(ctx, "danger", "Foundation scan found blocking workspace risk", foundation.findings.map((finding) => finding.reason).join("; "));
        }
      }
      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        type: "session_start",
        layer: "Foundation",
        severity: state.policyState.foundationBlocked ? "warning" : "info",
        title: "OpenClaw prompt build",
        summary: `${messageCount} messages in context; task tools: ${state.policyState.taskSpec.allowed_tools.join(", ")}`,
        payload: {
          workspaceDir,
          messageProvider: ctx.messageProvider || "",
          messageCount,
          task_spec: state.policyState.taskSpec,
          contaminated: state.policyState.contaminated,
          foundationBlocked: state.policyState.foundationBlocked,
          trust: policyTrustSnapshot(state.policyState),
          system_monitor: systemMonitorStatus(),
        },
      });
    });

    api.on("llm_input", (event, ctx) => {
      const state = getSession(ctx);
      const systemPromptPreview = plugin.config!.capture.includeSystemPromptPreview
        ? clampText(event?.systemPrompt || "", plugin.config!.capture.previewChars)
        : "[disabled]";
      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        type: "llm_input",
        layer: "LLM Input",
        severity: "info",
        title: "LLM input prepared",
        summary: plugin.config!.capture.includeSystemPromptPreview ? "system prompt preview captured" : "system prompt preview disabled",
        payload: {
          systemPromptPreview,
        },
      });
    });

    api.on("before_message_write", async (event, ctx) => {
      const state = getSession(ctx);
      const message = event?.message || {};
      const role = typeof message.role === "string" ? message.role : "unknown";
      const preview = plugin.config!.capture.includeMessageText
        ? clampText(message.content ?? message, plugin.config!.capture.previewChars)
        : "[disabled]";
      const ruleFindings = detectMessageContent(message.content ?? message, plugin.config!);
      const semanticFindings = await semanticJudgeMessage(message.content ?? message, plugin.config!);
      const findings = [...ruleFindings, ...semanticFindings];
      const severity = findings.length ? "warning" : role === "assistant" ? "success" : "info";

      if (shouldCoverAssistantResponse(state, role)) {
        state.coverNextAssistantResponse = false;
        const coverMessage = plugin.config!.responseCover.message;
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "response_cover",
          layer: "Input Sanitization",
          severity: "warning",
          title: "Assistant response covered",
          summary: "Contaminated tool output was detected earlier in this turn.",
          payload: {
            role,
            originalPreview: preview,
            replacement: coverMessage,
          },
        });
        return {
          block: false,
          message: {
            ...message,
            content: [{ type: "text", text: coverMessage }],
          },
        };
      }

      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        type: "message_write",
        layer: findings.length ? "Input Sanitization" : "Message Write",
        severity,
        title: `Message write: ${role}`,
        summary: findings.length ? findings.map((finding) => finding.reason).join("; ") : preview,
        payload: {
          role,
          preview,
          stopReason: message.stopReason || "",
          findings,
        },
      });

      updateAfterMessage(state.policyState, findings);
      for (const finding of findings) {
        addFinding(state, finding, { role });
      }
    });

    api.on("before_tool_call", async (event, ctx) => {
      const state = getSession(ctx);
      state.toolCount += 1;
      const params = (event?.params || {}) as Record<string, unknown>;
      const operationKey = computeOperationKey(event.toolName, params);
      const normalizedTool = normalizeAction(event.toolName, params).tool;
      const semanticFindings = [
        ...await semanticJudgeToolCall(event.toolName, params, state.policyState.currentTask, plugin.config!),
        ...(normalizedTool === "memory_write"
          ? await semanticJudgeMemoryWrite(params, state.policyState.currentTask, plugin.config!)
          : []),
      ];
      const result = detectToolCall(event.toolName, params, plugin.config!, state.policyState, semanticFindings);
      const cachedApproval = plugin.approvalCache!.has(operationKey) && result.decision === "ask" && !result.policy.deterministic_block;
      const effectiveDecision = cachedApproval ? "allow" : result.decision;
      const effectivePolicy = cachedApproval ? { ...result.policy, decision: "allow" as const } : result.policy;
      const cacheEntry = cachedApproval ? plugin.approvalCache!.recordHit(operationKey) : null;
      const severity = severityForDecision(effectiveDecision);
      const payload = {
        toolName: event.toolName,
        normalized_tool: result.policy.action.tool,
        toolCallId: event.toolCallId || "",
        params: serializeToolParams(params, plugin.config!),
        decision: effectiveDecision,
        original_decision: result.decision,
        enforcement_mode: plugin.config!.enforcement.mode,
        operation_key: operationKey,
        approval_cache_hit: cachedApproval,
        approval_cache_size: plugin.approvalCache!.size(),
        risk_score: result.risk_score,
        sentry_score: result.policy.sentry_score,
        deterministic_block: result.policy.deterministic_block,
        reasons: result.policy.reasons,
        violations: result.policy.violations,
        verdict: result.policy.findings.some((finding) => finding.verdict === "block")
          ? "block"
          : result.policy.findings.some((finding) => finding.verdict === "require_approval")
            ? "require_approval"
            : "pass",
        task_spec: result.policy.task_spec,
        contaminated: state.policyState.contaminated,
        risk_vector: result.policy.risk_vector,
        trust: policyTrustSnapshot(state.policyState),
        system_monitor: systemMonitorStatus(),
        findings: result.findings,
      };

      if (plugin.config!.runtimeIsolation.auditAfterExecution && effectiveDecision === "allow") {
        const checkpointKey = runtimeCheckpointKey(event.toolCallId || "", event.toolName);
        state.runtimeCheckpoints.set(checkpointKey, {
          checkpoint: ebpfLogCheckpoint(),
          toolName: event.toolName,
          params,
        });
        trimRuntimeCheckpoints(state);
      }

      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        type: "tool_decision",
        layer: "Execution Control",
        severity,
        title: `Tool call: ${event.toolName}`,
        summary: cachedApproval ? `allow-always cache hit; ${result.summary}` : result.summary,
        payload,
      });

      if (cachedApproval) {
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "approval_cache_hit",
          layer: "Execution Control",
          severity: "success",
          title: `Allow-always cache: ${event.toolName}`,
          summary: `Exact operation approved from cache after ${cacheEntry?.hits ?? 0} hit(s).`,
          payload: {
            toolName: event.toolName,
            toolCallId: event.toolCallId || "",
            operation_key: operationKey,
            original_decision: result.decision,
            risk_score: result.risk_score,
            cache_entry: cacheEntry,
          },
        });
      }

      for (const finding of result.findings) {
        addFinding(state, finding, { toolName: event.toolName, toolCallId: event.toolCallId || "" });
      }

      updateAfterDecision(state.policyState, effectivePolicy);

      if (effectiveDecision === "deny") {
        addAlert(state, `High-risk tool call: ${event.toolName}`, result.summary, payload);
        sendProactiveNotification(ctx, "danger", `High-risk tool call: ${event.toolName}`, result.summary);
      } else if (effectiveDecision === "ask") {
        sendProactiveNotification(ctx, "warning", `Review tool call: ${event.toolName}`, result.summary);
      }

      if (plugin.config!.enforcement.mode === "block" && effectiveDecision === "deny") {
        return {
          block: true,
          blockReason: `AgentSentry blocked this tool call: ${result.summary}`,
        };
      }

      if (plugin.config!.enforcement.mode === "approval" && (effectiveDecision === "deny" || effectiveDecision === "ask")) {
        const description = formatApprovalDescription({
          toolName: event.toolName,
          toolCallId: event.toolCallId || "",
          paramPreview: serializeToolParams(params, plugin.config!),
          riskScore: result.risk_score,
          reasons: result.policy.reasons,
          violations: result.policy.violations,
          maxChars: 240,
        });
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "approval_request",
          layer: "Execution Control",
          severity: "warning",
          title: `Approval requested: ${event.toolName}`,
          summary: description,
          payload: {
            toolName: event.toolName,
            toolCallId: event.toolCallId || "",
            decision: effectiveDecision,
            original_decision: result.decision,
            enforcement_mode: plugin.config!.enforcement.mode,
            operation_key: operationKey,
            risk_score: result.risk_score,
            deterministic_block: result.policy.deterministic_block,
            reasons: result.policy.reasons,
            violations: result.policy.violations,
            summary: result.summary,
          },
        });
        return {
          requireApproval: {
            title: `AgentSentry: ${event.toolName}`,
            description,
            severity: "warning",
            timeoutMs: plugin.config!.enforcement.approvalTimeoutMs,
            timeoutBehavior: "deny",
            onResolution: (decision: string) => {
              if (decision === "allow-always") plugin.approvalCache!.add(operationKey, event.toolName);
              plugin.store!.add({
                run_id: state.runId,
                session_key: state.sessionKey,
                type: "approval_resolution",
                layer: "Execution Control",
                severity: decision.startsWith("allow") ? "success" : "warning",
                title: `Approval ${decision}: ${event.toolName}`,
                summary: decision === "allow-always" ? "Exact operation added to allow-always cache." : `Operator decision: ${decision}`,
                payload: {
                  decision,
                  toolName: event.toolName,
                  toolCallId: event.toolCallId || "",
                  operation_key: operationKey,
                  cache_size: plugin.approvalCache!.size(),
                  cache_path: plugin.approvalCache!.path,
                  risk_score: result.risk_score,
                  summary: result.summary,
                },
              });
            },
          },
        };
      }
    });

    api.on("after_tool_call", (event, ctx) => {
      const state = getSession(ctx);
      const findings = resultFindings(event?.toolCallId || "", event?.result, state.policyState, plugin.config!, event?.toolName || "");
      const checkpointKey = runtimeCheckpointKey(event?.toolCallId || "", event?.toolName || "");
      const runtimeCheckpoint = state.runtimeCheckpoints.get(checkpointKey) || null;
      if (runtimeCheckpoint) state.runtimeCheckpoints.delete(checkpointKey);
      const runtimeAudit = plugin.config!.runtimeIsolation.auditAfterExecution
        ? auditRuntimeEventsSince(
          runtimeCheckpoint?.checkpoint || null,
          runtimeCheckpoint?.toolName || event?.toolName || "",
          runtimeCheckpoint?.params || {},
          { previewChars: plugin.config!.capture.previewChars },
        )
        : null;
      const runtimeFindings = runtimeAudit?.findings || [];
      const allFindings = [...findings, ...runtimeFindings];
      const severity: RecordSeverity = event?.error ? "danger" : "success";
      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        type: "tool_result",
        layer: runtimeFindings.length ? "Runtime Isolation" : findings.length ? "Input Sanitization" : "Tool Result",
        severity: allFindings.length ? "warning" : severity,
        title: event?.error ? "Tool call failed" : "Tool call completed",
        summary: event?.error
          ? clampText(event.error, plugin.config!.capture.previewChars)
          : allFindings.length
            ? allFindings.map((finding) => finding.reason).join("; ")
            : "tool result returned",
        payload: {
          toolCallId: event?.toolCallId || "",
          error: event?.error ? clampText(event.error, plugin.config!.capture.previewChars) : "",
          result: plugin.config!.capture.includeMessageText ? redactObject(event?.result, plugin.config!.capture.previewChars) : "[disabled]",
          label: state.policyState.toolResultLabels.get(event?.toolCallId || "") || null,
          trust: policyTrustSnapshot(state.policyState),
          system_monitor: systemMonitorStatus(),
          runtime_audit: runtimeAudit ? {
            enabled: runtimeAudit.enabled,
            scanned_bytes: runtimeAudit.scanned_bytes,
            event_count: runtimeAudit.event_count,
            interesting_events: runtimeAudit.interesting_events.slice(0, 8),
            checkpoint: runtimeAudit.checkpoint ? {
              log_path: runtimeAudit.checkpoint.log_path,
              size: runtimeAudit.checkpoint.size,
              created_at: runtimeAudit.checkpoint.created_at,
            } : null,
          } : null,
          findings: allFindings,
        },
      });

      updateAfterMessage(state.policyState, allFindings);
      for (const finding of allFindings) {
        addFinding(state, finding, { toolCallId: event?.toolCallId || "" });
      }
      if (findings.length) {
        if (plugin.config!.responseCover.enabled && plugin.config!.responseCover.coverAssistantAfterContamination) {
          state.coverNextAssistantResponse = true;
        }
        sendProactiveNotification(ctx, "warning", "Tool result contamination detected", findings.map((finding) => finding.reason).join("; "));
      }
      if (runtimeFindings.length) {
        addAlert(state, "eBPF runtime audit finding", runtimeFindings.map((finding) => finding.reason).join("; "), {
          toolName: event?.toolName || "",
          toolCallId: event?.toolCallId || "",
          runtime_audit: runtimeAudit,
          findings: runtimeFindings,
        });
        sendProactiveNotification(ctx, "warning", "eBPF runtime audit finding", runtimeFindings.map((finding) => finding.reason).join("; "));
      }
    });

    function getSession(ctx: Record<string, unknown>): SessionState {
      const sessionKey = typeof ctx.sessionKey === "string" ? ctx.sessionKey : "unknown";
      let state = plugin.sessions.get(sessionKey);
      if (!state) {
        state = {
          sessionKey,
          runId: runIdForSession(sessionKey),
          messageCount: 0,
          toolCount: 0,
          coverNextAssistantResponse: false,
          policyState: createPolicyState(),
          runtimeCheckpoints: new Map(),
        };
        plugin.sessions.set(sessionKey, state);
      }
      return state;
    }

    function runtimeCheckpointKey(toolCallId: string, toolName: string): string {
      return toolCallId || `last:${toolName || "unknown"}`;
    }

    function trimRuntimeCheckpoints(state: SessionState): void {
      const limit = 80;
      while (state.runtimeCheckpoints.size > limit) {
        const first = state.runtimeCheckpoints.keys().next().value;
        if (!first) break;
        state.runtimeCheckpoints.delete(first);
      }
    }

    function addFinding(state: SessionState, finding: Record<string, unknown>, extra: Record<string, unknown>): void {
      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        type: "guard_finding",
        layer: String(finding.layer || "Runtime"),
        severity: severityForVerdict(String(finding.verdict || "pass")),
        title: String(finding.reason || "AgentSentry finding"),
        summary: safeStringify(finding.evidence || {}).slice(0, plugin.config!.capture.previewChars),
        payload: {
          ...finding,
          ...extra,
        },
      });
    }

    function addAlert(state: SessionState, title: string, summary: string, payload: Record<string, unknown>): void {
      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        type: "alert",
        layer: "Execution Control",
        severity: "danger",
        title,
        summary,
        payload,
      });
    }

    function recordRuntime(title: string, summary: string, payload: Record<string, unknown>): void {
      plugin.store!.add({
        run_id: newId("runtime"),
        session_key: "runtime",
        type: "runtime",
        layer: "Runtime",
        severity: "info",
        title,
        summary,
        payload,
      });
    }

    function sendProactiveNotification(ctx: Record<string, unknown>, severity: "warning" | "danger", title: string, summary: string): void {
      if (!shouldNotify(severity)) return;
      const route = notificationRoute(ctx);
      if (!route) return;
      const message = clampText(
        [
          `AgentSentry ${severity.toUpperCase()}`,
          title,
          summary,
          `Dashboard: ${plugin.dashboard?.url || `http://${plugin.config!.dashboard.host}:${plugin.config!.dashboard.port}`}`,
        ].join("\n"),
        plugin.config!.notifications.maxMessageChars,
      );
      try {
        spawnSync("openclaw", ["message", "send", "--channel", route.channel, "--target", route.target, "--message", message], {
          stdio: "ignore",
        });
      } catch {
        // Notification is best-effort; records remain the source of truth.
      }
    }
  },
};

function severityForDecision(decision: string): RecordSeverity {
  if (decision === "deny") return "danger";
  if (decision === "ask") return "warning";
  return "success";
}

function shouldCoverAssistantResponse(state: SessionState, role: string): boolean {
  return Boolean(
    plugin.config?.responseCover.enabled
    && plugin.config.responseCover.coverAssistantAfterContamination
    && state.coverNextAssistantResponse
    && role === "assistant",
  );
}

function severityForVerdict(verdict: string): RecordSeverity {
  if (verdict === "block") return "danger";
  if (verdict === "require_approval") return "warning";
  return "info";
}

function shouldNotify(severity: "warning" | "danger"): boolean {
  if (!plugin.config?.notifications.enableProactiveNotifications) return false;
  if (plugin.config.notifications.minSeverity === "danger") return severity === "danger";
  return true;
}

function notificationRoute(ctx: Record<string, unknown>): { channel: string; target: string } | null {
  const provider = typeof ctx.messageProvider === "string" ? ctx.messageProvider.toLowerCase() : "";
  const sessionKey = typeof ctx.sessionKey === "string" ? ctx.sessionKey : "";
  const target = sessionKey.split(":").pop() || "";
  if (!target) return null;
  if (provider === "feishu") return { channel: "feishu", target };
  if (provider === "qqbot") return { channel: "qqbot", target };
  return null;
}

export default plugin;
