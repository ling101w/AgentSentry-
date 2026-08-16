import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { ConfigSchema, PluginConfig } from "./config.ts";
import { ApprovalCache, approvalCachePath } from "./core/approval-cache.ts";
import { handleAgentSentryCommand } from "./core/commands.ts";
import { detectMessageContent, detectToolCall, serializeToolParams } from "./core/detect.ts";
import { annotateUserInputForRisk } from "./core/input-annotation.ts";
import { foundationFindingBlocksSession, scanInitializationSurface } from "./core/init-defense.ts";
import { annotateActiveSkills } from "./core/skill-context.ts";
import {
  buildPersistentMemoryLabel,
  loadPersistentMemoryLabels,
  upsertPersistentMemoryLabel,
  type PersistentMemoryLabel,
} from "./core/memory-ifc.ts";
import { clearProvenanceScanCache, scanProvenance } from "./core/provenance.ts";
import { computeOperationKey, formatApprovalDescription } from "./core/operation.ts";
import {
  notificationRoute,
  provenanceRootsFor,
  severityForDecision,
  severityForVerdict,
  shouldCoverAssistantResponse,
  shouldNotify,
  shouldReturnJudgeAnalysis,
} from "./core/plugin-helpers.ts";
import {
  createPolicyState,
  checkpointPolicyState,
  hydratePersistentMemoryLabels,
  policyTrustSnapshot,
  resultFindings,
  restorePolicyStateCheckpoint,
  updateActionGraphEnforcement,
  updateAfterDecision,
  updateAfterMessage,
  updateAfterRuntimeFindings,
  updateTaskSpec,
  type PolicyState,
  type PolicyStateCheckpoint,
} from "./core/policy.ts";
import { clampText, redactObject, safeStringify } from "./core/redact.ts";
import {
  newId,
  RecordStore,
  runIdForSession,
  type AgentSentryDecision,
  type AgentSentryDisposition,
  type AgentSentryExecutionStatus,
  type RecordSeverity,
} from "./core/records.ts";
import { RollbackManager, type OperationCheckpoint, type RollbackSnapshot } from "./core/rollback.ts";
import { deleteRuntimeConfig, loadRuntimeConfig, runtimeConfigPath, saveRuntimeConfig } from "./core/runtime-config.ts";
import {
  semanticJudgeAmbiguousAction,
  semanticJudgeMemoryWrite,
  semanticJudgeMessage,
  semanticJudgeTaskSpec,
  semanticJudgeToolCall,
} from "./core/semantic.ts";
import { SessionRegistry } from "./core/session-registry.ts";
import { auditRuntimeEventsSince, ebpfLogCheckpoint, systemMonitorStatus, type EbpfLogCheckpoint } from "./core/system-monitor.ts";
import { startDashboard, type DashboardServer } from "./server/dashboard.ts";
import { refineTaskSpecWithLLM } from "./core/task-spec/index.ts";
import { configureToolManifestSigning } from "./core/tool-manifest.ts";
import { configureAgentTrust, sealAgentMessageParameters } from "./core/agent-trust.ts";
import {
  commitSandboxWorkspace,
  createShellSandboxTransaction,
  discardSandboxWorkspace,
  type SandboxTransaction,
} from "./core/sandbox.ts";

type PendingToolAudit = {
  toolName: string;
  toolCallId: string;
  params: Record<string, unknown>;
  paramsSha256: string;
  decision: AgentSentryDecision;
  disposition: AgentSentryDisposition;
  agentId: string;
  openclawRunId: string;
};

type SessionState = {
  runId: string;
  sessionKey: string;
  sourceSessionKey: string;
  sessionId: string;
  messageCount: number;
  toolCount: number;
  workspaceDir: string;
  coverNextAssistantResponse: boolean;
  lastAccessedAt: number;
  policyState: PolicyState;
  runtimeCheckpoints: Map<string, {
    checkpoint: EbpfLogCheckpoint | null;
    toolName: string;
    params: Record<string, unknown>;
    operationKey?: string;
    operationCheckpoint?: OperationCheckpoint | null;
    policyCheckpoint?: PolicyStateCheckpoint | null;
    rollbackSnapshots?: RollbackSnapshot[];
    sandbox?: SandboxTransaction | null;
  }>;
  pendingToolAudits: Map<string, PendingToolAudit[]>;
  lastFoundationDigest?: string;
};

function sessionCanEvict(state: SessionState): boolean {
  return state.policyState.semanticActionGraph.pendingCalls.size === 0
    && state.runtimeCheckpoints.size === 0
    && state.pendingToolAudits.size === 0;
}

const plugin = {
  id: "agent-sentry",
  name: "AgentSentry",
  description: "AgentSentry records OpenClaw lifecycle telemetry and exposes a local dashboard.",
  configSchema: ConfigSchema,
  config: null as PluginConfig | null,
  store: null as RecordStore | null,
  approvalCache: null as ApprovalCache | null,
  rollback: null as RollbackManager | null,
  dashboard: null as DashboardServer | null,
  startupConfig: null as PluginConfig | null,
  sessions: new SessionRegistry<SessionState>({ canEvict: sessionCanEvict }),

  register(api: OpenClawPluginApi) {
    const baseConfig = PluginConfig.fromPluginConfig(api.pluginConfig);
    plugin.startupConfig = structuredClone(baseConfig);
    plugin.config = loadRuntimeConfig(baseConfig);
    plugin.store = new RecordStore(plugin.config);
    plugin.approvalCache = new ApprovalCache(plugin.config);
    plugin.rollback = new RollbackManager(plugin.config);
    configureToolManifestSigning(plugin.config);
    configureAgentTrust(plugin.config);
    plugin.sessions = new SessionRegistry<SessionState>({
      idleTtlMs: plugin.config.storage.sessionIdleTtlMs,
      maxSessions: plugin.config.storage.maxSessions,
      canEvict: sessionCanEvict,
    });

    api.registerService({
      id: "agent-sentry-dashboard",
      start: async () => {
        if (!plugin.config!.dashboard.enabled) return;
        plugin.dashboard = await startDashboard(plugin.config!, plugin.store!, api.logger, {
          getConfig: () => plugin.config!,
          setConfig: (nextConfig) => {
            plugin.config = nextConfig;
            plugin.approvalCache = new ApprovalCache(nextConfig);
            plugin.rollback = new RollbackManager(nextConfig);
            configureToolManifestSigning(nextConfig);
            configureAgentTrust(nextConfig);
          },
          getRollback: () => plugin.rollback,
        });
        recordRuntime("AgentSentry dashboard started", plugin.dashboard.url, { url: plugin.dashboard.url });
      },
      stop: async () => {
        if (plugin.dashboard) {
          await plugin.dashboard.close();
          plugin.dashboard = null;
        }
        await plugin.store?.close();
        plugin.sessions.clear();
      },
    });

    api.registerCommand({
      name: "agentsentry",
      description: "Show AgentSentry dashboard and records location",
      acceptsArgs: true,
      requireAuth: true,
      handler: (ctx) => {
        const dashboard = plugin.dashboard?.accessUrl || `http://${plugin.config!.dashboard.host}:${plugin.config!.dashboard.port}`;
        return handleAgentSentryCommand(ctx, plugin.config!, plugin.startupConfig!, {
          dashboardUrl: dashboard,
          recordsPath: plugin.store!.recordsPath,
          runtimeConfigPath: runtimeConfigPath(plugin.config!),
          approvalCachePath: approvalCachePath(plugin.config!),
          sessionCount: plugin.sessions.size,
          approvalCacheCount: plugin.approvalCache!.size(),
          resetRecords: () => plugin.store!.reset(),
          clearProvenanceCache: () => clearProvenanceScanCache(),
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
      const promptText = typeof event?.prompt === "string" ? event.prompt : "";
      const workspaceDir = workspaceDirFor(ctx, state);
      if (workspaceDir) state.workspaceDir = workspaceDir;
      updateTaskSpec(
        state.policyState,
        [
          ...(Array.isArray(event?.messages) ? event.messages : []),
          ...(promptText.trim() ? [{ role: "user", content: promptText }] : []),
        ],
        plugin.config!,
      );
      const taskSpecRefinement = await refineTaskSpecWithLLM(state.policyState.taskSpec, plugin.config!);
      if (taskSpecRefinement.findings.length) {
        state.policyState.taskSpec = taskSpecRefinement.taskSpec;
        state.policyState.authorizationState.taskSpec = taskSpecRefinement.taskSpec;
        updateAfterMessage(state.policyState, taskSpecRefinement.findings);
        for (const finding of taskSpecRefinement.findings) {
          addFinding(state, finding, { role: "user", task_spec_refinement: true });
        }
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "guard_finding",
          layer: "Intent Authorization",
          severity: taskSpecRefinement.findings.some((finding) => finding.verdict === "block") ? "danger" : "warning",
          title: "LLM structured TaskSpec refinement",
          summary: taskSpecRefinement.findings.map((finding) => finding.reason).join("; "),
          payload: {
            applied: taskSpecRefinement.applied,
            task_spec: state.policyState.taskSpec,
            findings: taskSpecRefinement.findings,
          },
        });
      }
      void semanticJudgeTaskSpec(state.policyState.taskSpec, plugin.config!, {
        policyState: state.policyState,
        relatedFindings: promptText.trim() ? detectMessageContent(promptText, plugin.config!) : [],
      }).then((taskSpecFindings) => {
        if (!taskSpecFindings.length) return;
        updateAfterMessage(state.policyState, taskSpecFindings);
        for (const finding of taskSpecFindings) {
          addFinding(state, finding, { role: "user", task_spec: true });
        }
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "guard_finding",
          layer: "Intent Authorization",
          severity: taskSpecFindings.some((finding) => finding.verdict === "block") ? "danger" : "warning",
          title: "LLM-Judge task spec finding",
          summary: taskSpecFindings.map((finding) => finding.reason).join("; "),
          payload: {
            task_spec: state.policyState.taskSpec,
            findings: taskSpecFindings,
          },
        });
      }).catch((error) => {
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "guard_finding",
          layer: "Intent Authorization",
          severity: "warning",
          title: "LLM-Judge task spec check failed",
          summary: String(error instanceof Error ? error.message : error),
          payload: {
            task_spec: state.policyState.taskSpec,
          },
        });
      });
      const promptFindings = promptText.trim() ? detectMessageContent(promptText, plugin.config!) : [];
      const promptAnnotation = promptText.trim()
        ? annotateUserInputForRisk(promptText, promptFindings, plugin.config!)
        : null;
      const provenanceScans = [];
      for (const scanRoot of provenanceRootsFor(workspaceDir)) {
        const scan = await scanProvenance(scanRoot, plugin.config!);
        provenanceScans.push({
          ...scan,
          findings: scan.findings.map((finding) => ({
            ...finding,
            evidence: { ...finding.evidence, scan_root: scan.workspaceDir },
          })),
        });
      }
      if (provenanceScans.length) {
        state.policyState.provenanceFindings = provenanceScans.flatMap((scan) => scan.findings);
        state.policyState.provenanceBlocked = provenanceScans.some((scan) => scan.blocked);
        for (const provenance of provenanceScans) {
          if (provenance.cached) continue;
          const provenanceSeverity = provenance.blocked ? "danger" : provenance.findings.length ? "warning" : "success";
          plugin.store!.add({
            run_id: state.runId,
            session_key: state.sessionKey,
            type: "provenance_scan",
            layer: "Context Provenance",
            severity: provenanceSeverity,
            title: provenance.blocked ? "Provenance scan blocked a source root" : "Provenance scan completed",
            summary: `${provenance.findings.length} findings; ${provenance.scannedFiles} files scanned`,
            payload: {
              workspaceDir,
              scanRoot: provenance.workspaceDir,
              scannedFiles: provenance.scannedFiles,
              skippedFiles: provenance.skippedFiles,
              cached: provenance.cached,
              blocked: provenance.blocked,
              findings: provenance.findings,
            },
          });
          for (const finding of provenance.findings) {
            addFinding(state, finding, { workspaceDir, scanRoot: provenance.workspaceDir });
          }
          if (provenance.blocked) {
            addAlert(state, "Provenance scan found blocking risk", provenance.findings.map((finding) => finding.reason).join("; "), {
              workspaceDir,
              scanRoot: provenance.workspaceDir,
              findings: provenance.findings,
            });
            sendProactiveNotification(ctx, "danger", "Provenance scan found blocking risk", provenance.findings.map((finding) => finding.reason).join("; "));
          }
        }
      }
      const foundation = scanInitializationSurface(workspaceDir, plugin.config!);
      const foundationDigest = digestForFoundationScan(foundation);
      if (foundationDigest !== state.lastFoundationDigest) {
        state.lastFoundationDigest = foundationDigest;
        // A quarantined Skill or plugin is component-local. Global session blocking
        // is reserved for a compromised configuration, memory, or workspace source.
        if (foundation.findings.some(foundationFindingBlocksSession)) state.policyState.provenanceBlocked = true;
        for (const finding of foundation.findings) addFinding(state, finding, { workspaceDir, foundation_scan: true });
        const severity: RecordSeverity = foundation.blocked ? "danger" : foundation.findings.length ? "warning" : "success";
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "foundation_scan",
          layer: "Foundation Integrity",
          severity,
          title: foundation.blocked ? "初始化防线发现高危组件" : "初始化防线完成组件盘点",
          summary: `${foundation.components.length} components; ${foundation.findings.length} findings`,
          payload: {
            roots: foundation.roots,
            scanned_at: foundation.scanned_at,
            blocked: foundation.blocked,
            component_count: foundation.components.length,
            components: foundation.components.slice(0, 80),
            admissions: foundation.components.reduce<Record<string, number>>((counts, component) => {
              counts[component.admission] = (counts[component.admission] || 0) + 1;
              return counts;
            }, {}),
            omitted_components: Math.max(0, foundation.components.length - 80),
            findings: foundation.findings,
          },
        });
      }
      const skillAnnotations = annotateActiveSkills(
        foundation,
        event as Record<string, unknown>,
        ctx as Record<string, unknown>,
        promptText,
      );
      for (const annotation of skillAnnotations) {
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "skill_context_annotation",
          layer: "Foundation Integrity",
          severity: "info",
          title: "Skill baseline annotation attached",
          summary: `${annotation.skillName}; ${annotation.admission}; ${annotation.skillPath}`,
          payload: {
            component_id: annotation.componentId,
            skill_name: annotation.skillName,
            skill_path: annotation.skillPath,
            admission: annotation.admission,
          },
        });
      }
      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        type: "session_start",
        layer: "Context Provenance",
        severity: state.policyState.provenanceBlocked ? "warning" : "info",
        title: "OpenClaw prompt build",
        summary: `${messageCount} messages in context; task tools: ${state.policyState.taskSpec.allowed_tools.join(", ")}`,
        payload: {
          workspaceDir,
          messageProvider: ctx.messageProvider || "",
          messageCount,
          task_spec: state.policyState.taskSpec,
          contaminated: state.policyState.contaminated,
          provenanceBlocked: state.policyState.provenanceBlocked,
          trust: policyTrustSnapshot(state.policyState),
          system_monitor: systemMonitorStatus(),
        },
      });
      if (promptAnnotation) {
        updateAfterMessage(state.policyState, promptFindings);
        for (const finding of promptFindings) {
          addFinding(state, finding, { role: "user", prompt_annotation: true });
        }
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "input_annotation",
          layer: "Context Provenance",
          severity: promptAnnotation.recommendedAction === "Deny" ? "danger" : "warning",
          title: "User request risk annotation",
          summary: `${promptAnnotation.overall}; ${promptAnnotation.recommendedAction}; ${promptAnnotation.entries.length} marked item(s)`,
          payload: {
            role: "user",
            originalPreview: clampText(promptText, plugin.config!.capture.previewChars),
            annotatedPreview: clampText(promptAnnotation.annotated, plugin.config!.capture.previewChars),
            entries: promptAnnotation.entries,
            overall: promptAnnotation.overall,
            recommended_action: promptAnnotation.recommendedAction,
          },
        });
      }
      const appendedContext = [promptAnnotation?.annotated, ...skillAnnotations.map((annotation) => annotation.text)]
        .filter((item): item is string => Boolean(item?.trim()))
        .join("\n\n");
      if (appendedContext) return { appendContext: appendedContext };
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
        layer: "Context Provenance",
        severity: "info",
        title: "LLM input prepared",
        summary: plugin.config!.capture.includeSystemPromptPreview ? "system prompt preview captured" : "system prompt preview disabled",
        payload: {
          systemPromptPreview,
        },
      });
    });

    api.on("before_message_write", (event, ctx) => {
      const state = getSession(ctx);
      const message = event?.message || {};
      const role = typeof message.role === "string" ? message.role : "unknown";
      const preview = plugin.config!.capture.includeMessageText
        ? clampText(message.content ?? message, plugin.config!.capture.previewChars)
        : "[disabled]";
      const ruleFindings = detectMessageContent(message.content ?? message, plugin.config!);
      if (role === "user") {
        updateTaskSpec(state.policyState, [{ role: "user", content: message.content ?? message }], plugin.config!);
        void semanticJudgeMessage(message.content ?? message, plugin.config!, {
          policyState: state.policyState,
          relatedFindings: ruleFindings,
        }).then((semanticMessageFindings) => {
          if (!semanticMessageFindings.length) return;
          updateAfterMessage(state.policyState, semanticMessageFindings);
          for (const finding of semanticMessageFindings) {
            addFinding(state, finding, { role, semantic_message: true });
          }
          plugin.store!.add({
            run_id: state.runId,
            session_key: state.sessionKey,
            type: "guard_finding",
            layer: "Context Provenance",
            severity: semanticMessageFindings.some((finding) => finding.verdict === "block") ? "danger" : "warning",
            title: "LLM-Judge message finding",
            summary: semanticMessageFindings.map((finding) => finding.reason).join("; "),
            payload: {
              role,
              findings: semanticMessageFindings,
            },
          });
        }).catch((error) => {
          plugin.store!.add({
            run_id: state.runId,
            session_key: state.sessionKey,
            type: "guard_finding",
            layer: "Context Provenance",
            severity: "warning",
            title: "LLM-Judge message check failed",
            summary: String(error instanceof Error ? error.message : error),
            payload: { role },
          });
        });
      }
      const findings = ruleFindings;
      const severity = findings.length ? "warning" : role === "assistant" ? "success" : "info";

      if (shouldCoverAssistantResponse(plugin.config!.responseCover, state.coverNextAssistantResponse, role)) {
        state.coverNextAssistantResponse = false;
        const coverMessage = plugin.config!.responseCover.message;
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "response_cover",
          layer: "Context Provenance",
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

      const inputAnnotation = role === "user"
        ? annotateUserInputForRisk(message.content ?? message, findings, plugin.config!)
        : null;
      if (inputAnnotation) {
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "input_annotation",
          layer: "Context Provenance",
          severity: inputAnnotation.recommendedAction === "Deny" ? "danger" : "warning",
          title: "User request risk annotation",
          summary: `${inputAnnotation.overall}; ${inputAnnotation.recommendedAction}; ${inputAnnotation.entries.length} marked item(s)`,
          payload: {
            role,
            originalPreview: preview,
            annotatedPreview: clampText(inputAnnotation.annotated, plugin.config!.capture.previewChars),
            entries: inputAnnotation.entries,
            overall: inputAnnotation.overall,
            recommended_action: inputAnnotation.recommendedAction,
          },
        });
        updateAfterMessage(state.policyState, findings);
        for (const finding of findings) {
          addFinding(state, finding, { role, input_annotation: true });
        }
        return {
          block: false,
          message: {
            ...message,
            content: inputAnnotation.annotated,
          },
        };
      }

      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        type: "message_write",
        layer: findings.length ? "Context Provenance" : "Context Provenance",
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
      const rawParams = (event?.params || {}) as Record<string, unknown>;
      const params = event.toolName === "sessions_send"
        ? sealAgentMessageParameters(rawParams, plugin.config!)
        : rawParams;
      const operationKey = computeOperationKey(event.toolName, params, {
        profile: plugin.config!.profile,
        policy: plugin.config!.policy,
        detection: plugin.config!.detection,
        semantic: plugin.config!.semantic,
        provenanceScan: plugin.config!.provenanceScan,
        runtimeIsolation: plugin.config!.runtimeIsolation,
        enforcement: plugin.config!.enforcement.mode,
        taskSpec: state.policyState.taskSpec,
      });
      const detectionContext = {
        toolCallId: event.toolCallId || "",
        workspaceDir: workspaceDirFor(ctx, state),
      };
      const preliminary = detectToolCall(event.toolName, params, plugin.config!, state.policyState, [], detectionContext);
      const action = preliminary.policy.action;
      const semanticToolFindings = await semanticJudgeToolCall(event.toolName, params, state.policyState.currentTask, plugin.config!, {
        policyState: state.policyState,
        relatedFindings: preliminary.policy.findings,
      });
      const memoryContent = action.tool === "memory_write"
        ? firstToolString(params, ["content", "body", "text", "value", "payload", "new_string", "replacement", "patch"]) || params
        : "";
      const semanticMemoryFindings = action.tool === "memory_write"
        ? await semanticJudgeMemoryWrite(memoryContent, state.policyState.currentTask, plugin.config!, {
          policyState: state.policyState,
          relatedFindings: preliminary.policy.findings,
        })
        : [];
      const semanticAmbiguousFindings = await semanticJudgeAmbiguousAction({
        action: preliminary.policy.action,
        taskSpec: preliminary.policy.task_spec,
        policyState: state.policyState,
        preliminary: preliminary.policy,
      }, plugin.config!);
      const semanticFindings = [...semanticToolFindings, ...semanticMemoryFindings, ...semanticAmbiguousFindings];
      const result = semanticFindings.length
        ? detectToolCall(event.toolName, params, plugin.config!, state.policyState, semanticFindings, detectionContext)
        : preliminary;
      const cachedApproval = plugin.approvalCache!.has(operationKey) && result.decision === "ask" && !result.policy.deterministic_block;
      const effectiveDecision = cachedApproval ? "allow" : result.decision;
      const effectivePolicy = cachedApproval
        ? {
          ...result.policy,
          decision: "allow" as const,
          intervention: result.policy.intervention
            ? {
              ...result.policy.intervention,
              decision: "allow" as const,
              overridden: true,
              approval_cache_override: true,
            }
            : undefined,
        }
        : result.policy;
      const cacheEntry = cachedApproval ? plugin.approvalCache!.recordHit(operationKey) : null;
      const severity = severityForDecision(effectiveDecision);
      const agentId = contextString(ctx, "agentId");
      const openclawRunId = contextString(event, "runId") || contextString(ctx, "runId");
      const toolCallId = contextString(event, "toolCallId");
      const auditParams = auditToolParams(params, plugin.config!.capture.previewChars);
      const paramsSha256 = auditParamsSha256(auditParams);
      const disposition = toolDisposition(plugin.config!.enforcement.mode, effectiveDecision);
      const executionStatus: AgentSentryExecutionStatus = disposition === "blocked" ? "blocked" : "pending";
      const graphStatus = plugin.config!.enforcement.mode === "approval" && (effectiveDecision === "deny" || effectiveDecision === "ask")
        ? "awaiting_approval"
        : plugin.config!.enforcement.mode === "block" && effectiveDecision === "deny"
          ? "blocked"
          : "executing";
      updateAfterDecision(state.policyState, effectivePolicy, plugin.config!);
      persistAllowedMemoryLabel(state, effectivePolicy.action.tool, params, effectiveDecision);
      updateActionGraphEnforcement(state.policyState, effectivePolicy, graphStatus);
      const sandbox = effectiveDecision !== "deny"
        ? createShellSandboxTransaction(
          plugin.config!,
          detectionContext.workspaceDir,
          firstToolString(effectivePolicy.action.args, ["command", "cmd", "script", "input"]),
        )
        : null;
      const executionParams = sandbox ? paramsWithSandboxCommand(params, sandbox.wrappedCommand) : params;
      const payload = {
        toolName: event.toolName,
        normalized_tool: effectivePolicy.action.tool,
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
        intervention: effectivePolicy.intervention,
        reasons: effectivePolicy.reasons,
        violations: effectivePolicy.violations,
        verdict: effectiveDecision === "deny" ? "block" : effectiveDecision === "ask" ? "require_approval" : "pass",
        original_verdict: result.policy.findings.some((finding) => finding.verdict === "block")
          ? "block"
          : result.policy.findings.some((finding) => finding.verdict === "require_approval")
            ? "require_approval"
            : "pass",
        task_spec: effectivePolicy.task_spec,
        contaminated: state.policyState.contaminated,
        risk_vector: effectivePolicy.risk_vector,
        trust: policyTrustSnapshot(state.policyState),
        system_monitor: systemMonitorStatus(),
        sandbox: sandbox ? {
          enabled: true,
          type: "workspace-shadow-commit",
          temp_dir: sandbox.tempDir,
          network_isolation: sandbox.useBestEffortNetworkIsolation ? "best-effort-unshare" : "host-network-fallback",
        } : null,
        findings: effectivePolicy.findings,
      };
      const operationCheckpoint = effectiveDecision === "allow"
        ? plugin.rollback!.checkpointOperation({
          action: effectivePolicy.action,
          workspaceDir: detectionContext.workspaceDir,
          operationKey,
          sessionState: checkpointPolicyState(state.policyState) as unknown as Record<string, unknown>,
        })
        : null;
      const rollbackSnapshots = operationCheckpoint?.file_snapshots || [];

      const pendingAudit: PendingToolAudit = {
        toolName: event.toolName,
        toolCallId,
        params: auditParams,
        paramsSha256,
        decision: effectiveDecision,
        disposition,
        agentId,
        openclawRunId,
      };
      if (disposition !== "blocked") {
        enqueuePendingToolAudit(state, pendingToolAuditKey(toolCallId, event.toolName), pendingAudit);
        trimPendingToolAudits(state);
      }

      if (plugin.config!.runtimeIsolation.auditAfterExecution && effectiveDecision === "allow") {
        const checkpointKey = runtimeCheckpointKey(event.toolCallId || "", event.toolName);
        state.runtimeCheckpoints.set(checkpointKey, {
          checkpoint: ebpfLogCheckpoint(),
          toolName: event.toolName,
          params: executionParams,
          operationKey,
          operationCheckpoint,
          policyCheckpoint: checkpointPolicyState(state.policyState),
          rollbackSnapshots,
          sandbox,
        });
        trimRuntimeCheckpoints(state);
      }

      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        session_id: state.sessionId,
        agent_id: agentId,
        openclaw_run_id: openclawRunId,
        tool_name: event.toolName,
        tool_call_id: toolCallId,
        params: auditParams,
        params_sha256: paramsSha256,
        decision: effectiveDecision,
        disposition,
        execution_status: executionStatus,
        type: "tool_decision",
        layer: "Tool Boundary",
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
          layer: "Tool Boundary",
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
        const includeJudgeAnalysis = shouldReturnJudgeAnalysis(result.findings, result.risk_score, effectiveDecision);
        const description = formatApprovalDescription({
          toolName: event.toolName,
          toolCallId: event.toolCallId || "",
          paramPreview: serializeToolParams(params, plugin.config!),
          riskScore: result.risk_score,
          reasons: result.policy.reasons,
          violations: result.policy.violations,
          decision: effectiveDecision,
          findings: result.findings,
          includeJudgeAnalysis,
          maxChars: 240,
        });
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          session_id: state.sessionId,
          agent_id: agentId,
          openclaw_run_id: openclawRunId,
          tool_name: event.toolName,
          tool_call_id: toolCallId,
          params: auditParams,
          params_sha256: paramsSha256,
          decision: effectiveDecision,
          disposition: "approval_required",
          execution_status: "pending",
          type: "approval_request",
          layer: "Tool Boundary",
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
            judge_analysis_returned_to_openclaw: includeJudgeAnalysis,
            reasons: result.policy.reasons,
            violations: result.policy.violations,
            summary: result.summary,
            approval_description: description,
          },
        });
	        return {
	          ...(sandbox ? { params: executionParams } : {}),
	          requireApproval: {
            title: `AgentSentry: ${event.toolName}`,
            description,
            severity: "warning",
            timeoutMs: plugin.config!.enforcement.approvalTimeoutMs,
            timeoutBehavior: "deny",
            onResolution: (decision: string) => {
              const cacheEligible = result.decision === "ask" && !result.policy.deterministic_block;
              if (decision === "allow-always" && cacheEligible) plugin.approvalCache!.add(operationKey, event.toolName);
              const approved = decision.startsWith("allow");
              const resolutionDisposition = approvalDisposition(decision);
              const resolutionStatus: AgentSentryExecutionStatus = approved ? "pending" : "skipped";
              const pendingAuditKey = pendingToolAuditKey(toolCallId, event.toolName);
              if (approved) {
                pendingAudit.disposition = resolutionDisposition;
              } else {
                removePendingToolAudit(state, pendingAuditKey, pendingAudit);
              }
              const approvedOperationCheckpoint = approved
                ? plugin.rollback!.checkpointOperation({
                  action: result.policy.action,
                  workspaceDir: detectionContext.workspaceDir,
                  operationKey,
                  sessionState: checkpointPolicyState(state.policyState) as unknown as Record<string, unknown>,
                })
                : null;
              const approvedRollbackSnapshots = approvedOperationCheckpoint?.file_snapshots || [];
              if (approved && plugin.config!.runtimeIsolation.auditAfterExecution) {
                const checkpointKey = runtimeCheckpointKey(event.toolCallId || "", event.toolName);
	                state.runtimeCheckpoints.set(checkpointKey, {
	                  checkpoint: ebpfLogCheckpoint(),
	                  toolName: event.toolName,
	                  params: executionParams,
	                  operationKey,
                    operationCheckpoint: approvedOperationCheckpoint,
                    policyCheckpoint: checkpointPolicyState(state.policyState),
	                  rollbackSnapshots: approvedRollbackSnapshots,
	                  sandbox,
	                });
                trimRuntimeCheckpoints(state);
              }
              updateActionGraphEnforcement(
                state.policyState,
                { ...result.policy, decision: approved ? "allow" : "deny" },
                approved ? "executing" : "blocked",
              );
              plugin.store!.add({
                run_id: state.runId,
                session_key: state.sessionKey,
                session_id: state.sessionId,
                agent_id: agentId,
                openclaw_run_id: openclawRunId,
                tool_name: event.toolName,
                tool_call_id: toolCallId,
                params: auditParams,
                params_sha256: paramsSha256,
                decision: effectiveDecision,
                disposition: resolutionDisposition,
                execution_status: resolutionStatus,
                type: "approval_resolution",
                layer: "Tool Boundary",
                severity: decision.startsWith("allow") ? "success" : "warning",
                title: `Approval ${decision}: ${event.toolName}`,
                summary: decision === "allow-always" && cacheEligible
                  ? "Exact operation added to allow-always cache."
                  : `Operator decision: ${decision}`,
                payload: {
                  decision,
                  approval_cache_eligible: cacheEligible,
                  toolName: event.toolName,
                  toolCallId: event.toolCallId || "",
                  operation_key: operationKey,
                  cache_size: plugin.approvalCache!.size(),
                  cache_path: plugin.approvalCache!.path,
                  rollback_checkpoint_count: approvedRollbackSnapshots.length,
                  risk_score: result.risk_score,
                  summary: result.summary,
                },
              });
            },
          },
        };
	      }
      if (sandbox || params !== rawParams) return { params: executionParams };
	    });

    api.on("after_tool_call", (event, ctx) => {
      const state = getSession(ctx);
      const auditKey = pendingToolAuditKey(event?.toolCallId || "", event?.toolName || "");
      const pendingAudit = dequeuePendingToolAudit(state, auditKey);
      const resultParams = pendingAudit?.params || auditToolParams((event?.params || {}) as Record<string, unknown>, plugin.config!.capture.previewChars);
      const resultParamsSha256 = pendingAudit?.paramsSha256 || auditParamsSha256(resultParams);
      const resultDecision = pendingAudit?.decision;
      const resultDisposition = pendingAudit?.disposition;
      const resultExecutionStatus: AgentSentryExecutionStatus = event?.error ? "failed" : "executed";
      const findings = resultFindings(
        event?.toolCallId || "",
        event?.result,
        state.policyState,
        plugin.config!,
        event?.toolName || "",
        { error: event?.error, toolArgs: (event?.params || {}) as Record<string, unknown> },
      );
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
      const unsafeRuntimeOutcome = Boolean(event?.error) || runtimeFindings.some((finding) =>
        finding.verdict === "block" || finding.score >= 90
      );
      const policyRollback = unsafeRuntimeOutcome && runtimeCheckpoint?.policyCheckpoint
        ? restorePolicyStateCheckpoint(state.policyState, runtimeCheckpoint.policyCheckpoint)
        : false;
      updateAfterRuntimeFindings(state.policyState, event?.toolName || "", runtimeFindings);
      const runtimeRollback = runtimeCheckpoint?.operationKey && unsafeRuntimeOutcome
        ? plugin.rollback!.restoreOperation(runtimeCheckpoint.operationKey)
        : null;
      const sandboxOutcome = runtimeCheckpoint?.sandbox
        ? (() => {
          const unsafe = Boolean(event?.error) || runtimeFindings.length > 0;
          if (unsafe) {
            discardSandboxWorkspace(runtimeCheckpoint.sandbox!);
            return {
              action: "discarded",
              reason: event?.error ? "tool execution failed" : "runtime audit produced findings",
              temp_dir: runtimeCheckpoint.sandbox!.tempDir,
            };
          }
          const committed = commitSandboxWorkspace(runtimeCheckpoint.sandbox!);
          discardSandboxWorkspace(runtimeCheckpoint.sandbox!);
          return {
            action: committed.committed ? "committed" : "commit_failed",
            reason: committed.reason || "",
            temp_dir: runtimeCheckpoint.sandbox!.tempDir,
          };
        })()
        : null;
      const severity: RecordSeverity = event?.error ? "danger" : "success";
      plugin.store!.add({
        run_id: state.runId,
        session_key: state.sessionKey,
        session_id: state.sessionId,
        agent_id: pendingAudit?.agentId || contextString(ctx, "agentId"),
        openclaw_run_id: pendingAudit?.openclawRunId || contextString(event, "runId") || contextString(ctx, "runId"),
        tool_name: pendingAudit?.toolName || event?.toolName || "",
        tool_call_id: pendingAudit?.toolCallId || event?.toolCallId || "",
        params: resultParams,
        params_sha256: resultParamsSha256,
        decision: resultDecision,
        disposition: resultDisposition,
        execution_status: resultExecutionStatus,
        type: "tool_result",
        layer: runtimeFindings.length ? "Tool Boundary" : findings.length ? "Context Provenance" : "Evidence Feedback",
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
          rollback: runtimeRollback ? {
            restored_count: runtimeRollback.restored.length,
            errors: runtimeRollback.errors,
            checkpoint_count: runtimeCheckpoint?.rollbackSnapshots?.length || 0,
            operation_checkpoint_id: runtimeCheckpoint?.operationCheckpoint?.id || runtimeRollback.checkpoint?.id || "",
            policy_state_restored: policyRollback,
          } : null,
          sandbox: sandboxOutcome,
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
          rollback: runtimeRollback,
          findings: runtimeFindings,
        });
        sendProactiveNotification(ctx, "warning", "eBPF runtime audit finding", runtimeFindings.map((finding) => finding.reason).join("; "));
      }
      trimSessions();
    });

    function getSession(ctx: Record<string, unknown>): SessionState {
      const sessionKey = typeof ctx.sessionKey === "string" ? ctx.sessionKey : "unknown";
      const sessionId = typeof ctx.sessionId === "string" && ctx.sessionId.trim() ? ctx.sessionId.trim() : "default";
      const sessionMaterial = JSON.stringify([sessionKey, sessionId]);
      const sessionHash = createHash("sha256").update(sessionMaterial).digest("hex");
      const sessionIdentity = `session:${sessionHash}`;
      const auditSessionKey = sessionId === "default" ? sessionKey : `${sessionKey}#${sessionHash.slice(0, 12)}`;
      let state = plugin.sessions.get(sessionIdentity);
      if (!state) {
        state = {
          sessionKey: auditSessionKey,
          sourceSessionKey: sessionKey,
          sessionId,
          runId: runIdForSession(sessionMaterial),
          messageCount: 0,
          toolCount: 0,
          coverNextAssistantResponse: false,
          lastAccessedAt: Date.now(),
          policyState: createPolicyState(),
          runtimeCheckpoints: new Map(),
          pendingToolAudits: new Map(),
          workspaceDir: "",
        };
        hydratePersistentMemoryLabels(state.policyState, loadPersistentMemoryLabels(plugin.config!));
        plugin.sessions.set(sessionIdentity, state);
      }
      const workspaceDir = typeof ctx.workspaceDir === "string" && ctx.workspaceDir.trim() ? ctx.workspaceDir.trim() : "";
      if (workspaceDir) state.workspaceDir = workspaceDir;
      return state;
    }

    function workspaceDirFor(ctx: Record<string, unknown>, state: SessionState): string {
      const fromContext = typeof ctx.workspaceDir === "string" && ctx.workspaceDir.trim() ? ctx.workspaceDir.trim() : "";
      if (fromContext) return fromContext;
      return state.workspaceDir || "";
    }

    function trimSessions(): void {
      plugin.sessions.evictExpired();
    }

    function runtimeCheckpointKey(toolCallId: string, toolName: string): string {
      return toolCallId || `last:${toolName || "unknown"}`;
    }

    function pendingToolAuditKey(toolCallId: string, toolName: string): string {
      return toolCallId || `last:${toolName || "unknown"}`;
    }

    function enqueuePendingToolAudit(state: SessionState, key: string, audit: PendingToolAudit): void {
      const queue = state.pendingToolAudits.get(key) || [];
      queue.push(audit);
      if (queue.length > 256) queue.shift();
      state.pendingToolAudits.set(key, queue);
    }

    function dequeuePendingToolAudit(state: SessionState, key: string): PendingToolAudit | null {
      const queue = state.pendingToolAudits.get(key);
      const audit = queue?.shift() || null;
      if (!queue?.length) state.pendingToolAudits.delete(key);
      return audit;
    }

    function removePendingToolAudit(state: SessionState, key: string, audit: PendingToolAudit): void {
      const queue = state.pendingToolAudits.get(key);
      if (!queue) return;
      const index = queue.indexOf(audit);
      if (index >= 0) queue.splice(index, 1);
      if (!queue.length) state.pendingToolAudits.delete(key);
    }

    function trimPendingToolAudits(state: SessionState): void {
      let count = [...state.pendingToolAudits.values()].reduce((total, queue) => total + queue.length, 0);
      while (count > 256) {
        const oldestKey = state.pendingToolAudits.keys().next().value;
        if (typeof oldestKey !== "string") break;
        const queue = state.pendingToolAudits.get(oldestKey);
        queue?.shift();
        count -= 1;
        if (!queue?.length) state.pendingToolAudits.delete(oldestKey);
      }
    }

    function contextString(value: unknown, key: string): string {
      if (!value || typeof value !== "object") return "";
      const candidate = (value as Record<string, unknown>)[key];
      return typeof candidate === "string" ? candidate.trim() : "";
    }

    function auditToolParams(params: Record<string, unknown>, previewChars: number): Record<string, unknown> {
      const redacted = redactObject(params, previewChars);
      return redacted && typeof redacted === "object" && !Array.isArray(redacted)
        ? redacted as Record<string, unknown>
        : { value: redacted };
    }

    function auditParamsSha256(params: Record<string, unknown>): string {
      return createHash("sha256").update(safeStringify(params)).digest("hex");
    }

    function toolDisposition(mode: string, decision: AgentSentryDecision): AgentSentryDisposition {
      if (mode === "observe") return "observe_only";
      if (mode === "block" && decision === "deny") return "blocked";
      if (mode === "approval" && decision !== "allow") return "approval_required";
      return "allowed";
    }

    function approvalDisposition(decision: string): AgentSentryDisposition {
      if (decision === "allow-once" || decision === "allow-always") return "approval_granted";
      if (decision === "timeout") return "approval_timeout";
      if (decision === "cancelled") return "approval_cancelled";
      return "approval_denied";
    }

    function firstToolString(params: Record<string, unknown>, keys: string[]): string {
      for (const key of keys) {
        const value = params[key];
        if (typeof value === "string" && value.trim()) return value.trim();
        if (Array.isArray(value) && value.length) {
          const item = String(value[0] ?? "").trim();
          if (item) return item;
        }
      }
      return "";
    }

    function paramsWithSandboxCommand(params: Record<string, unknown>, command: string): Record<string, unknown> {
      const out = { ...params };
      for (const key of ["command", "cmd", "script", "input"]) {
        if (typeof out[key] === "string" && out[key].trim()) {
          out[key] = command;
          return out;
        }
      }
      out.command = command;
      return out;
    }

    function digestForFoundationScan(scan: ReturnType<typeof scanInitializationSurface>): string {
      return createHash("sha256").update(JSON.stringify({
        roots: scan.roots,
        components: scan.components.map((component) => ({
          id: component.id,
          sha256: component.sha256,
          trust: component.trust,
          risk: component.risk,
          admission: component.admission,
        })),
        findings: scan.findings.map((finding) => ({
          layer: finding.layer,
          verdict: finding.verdict,
          reason: finding.reason,
          score: finding.score,
        })),
      })).digest("hex");
    }

    function persistAllowedMemoryLabel(
      state: SessionState,
      normalizedTool: string,
      params: Record<string, unknown>,
      decision: "allow" | "ask" | "deny",
    ): void {
      if (decision === "deny" || normalizedTool !== "memory_write") return;
      const content = firstToolValue(params, ["content", "body", "text", "value", "payload", "new_string", "replacement", "patch"]) ?? params;
      const key = memoryKeyFromToolParams(params);
      const sourceClass = memorySourceClassFromToolParams(params);
      try {
        const label = buildPersistentMemoryLabel({
          key,
          content,
          context: state.policyState.currentTask,
          sourceClass,
          sessionId: state.sessionId,
          tenant: state.sourceSessionKey || "default",
          config: plugin.config!,
        });
        upsertPersistentMemoryLabel(plugin.config!, label);
        hydratePersistentMemoryLabels(state.policyState, [label]);
      } catch (error) {
        plugin.store!.add({
          run_id: state.runId,
          session_key: state.sessionKey,
          type: "guard_finding",
          layer: "Memory IFC",
          severity: "warning",
          title: "Memory IFC label persistence failed",
          summary: error instanceof Error ? error.message : String(error),
          payload: { key },
        });
      }
    }

    function firstToolValue(params: Record<string, unknown>, keys: string[]): unknown {
      for (const key of keys) {
        if (typeof params[key] !== "undefined") return params[key];
      }
      return undefined;
    }

    function memoryKeyFromToolParams(params: Record<string, unknown>): string {
      const raw = firstToolString(params, ["key", "name", "path", "file"]) || "memory";
      const normalized = raw.replace(/\\/g, "/");
      const memoryFile = normalized.match(/(?:^|\/)memory\/([^/]+\.md)$/i);
      if (memoryFile?.[1]) return `memory/${memoryFile[1]}`;
      const namedMemory = normalized.match(/(?:^|\/)(user\.md|soul\.md|memory\.md|agents\.md)$/i);
      if (namedMemory?.[1]) return namedMemory[1].toLowerCase();
      return raw;
    }

    function memorySourceClassFromToolParams(params: Record<string, unknown>): PersistentMemoryLabel["source_class"] | undefined {
      const raw = firstToolString(params, ["source_class", "sourceClass", "source", "origin"]).toLowerCase();
      if (!raw) return undefined;
      if (raw === "user_directive" || raw === "user" || raw === "direct_user") return "user_directive";
      if (raw === "agent_inference" || raw === "agent" || raw === "self") return "agent_inference";
      if (raw === "external_web" || raw === "web" || raw === "pdf" || raw === "image" || raw === "email") return "external_web";
      if (raw === "tool_result" || raw === "tool") return "tool_result";
      if (raw === "webhook" || raw.includes("hooks/wake")) return "webhook";
      return "unknown";
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
      if (String(finding.verdict || "pass") === "pass") return;
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
        layer: "Tool Boundary",
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
        layer: "Evidence Feedback",
        severity: "info",
        title,
        summary,
        payload,
      });
    }

    function sendProactiveNotification(ctx: Record<string, unknown>, severity: "warning" | "danger", title: string, summary: string): void {
      if (!shouldNotify(plugin.config!.notifications, severity)) return;
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
        execFile("openclaw", ["message", "send", "--channel", route.channel, "--target", route.target, "--message", message], {
          timeout: 5000,
          windowsHide: true,
        }, () => undefined);
      } catch {
        // Notification is best-effort; records remain the source of truth.
      }
    }
  },
};

export default plugin;
