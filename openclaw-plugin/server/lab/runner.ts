import type { PluginConfig } from "../../config.ts";
import { detectMessageContent } from "../../core/detect.ts";
import { policyTrustSnapshot, resultFindings, updateAfterMessage, updateAfterRuntimeFindings, updateTaskSpec } from "../../core/policy.ts";
import type { RecordSeverity, RecordStore } from "../../core/records.ts";
import { supervisionService } from "../../core/supervision-service.ts";
import { systemMonitorStatus } from "../../core/system-monitor.ts";
import { performance } from "node:perf_hooks";
import { buildProductionGraphInput, createGraphTrainingEnvelope, type ProductionGraphInput, type GraphTrainingEnvelope } from "../../core/graph-learning/production-graph.ts";
import type { GraphShadowScore } from "../../core/graph-learning/shadow-router.ts";
import { TOOL_CALL_PERFORMANCE_SCHEMA_VERSION, roundDurationMs, type ToolCallPerformanceSample } from "../../core/performance-metrics.ts";

import type { SemanticJudgeOverride } from "../semantic-config.ts";
import { configWithSemanticOverride, semanticJudgeProfile } from "../semantic-config.ts";
import { severityForDecision, severityForVerdict } from "../dashboard-utils.ts";
import type { LabAction, BusinessExecution, ExecutionStatus } from "./contracts.ts";
import { openClawWorkspaceRoot } from "./workspace.ts";
import { policySessionsFor } from "../policy-sessions.ts";
import { labPolicyActionFor, authorizeLabDemoBusiness, authorizeLabScenarioIngress, adversarialFromExecution } from "./scenarios.ts";
import { executeBusinessTool, redactExecution, isLabDemoWorkspaceTool } from "./executor.ts";
export async function executeLabActions(input: {
  store: RecordStore;
  config: PluginConfig;
  command: string;
  scenario: string;
  runId: string;
  sessionKey: string;
  commandId: string;
  actions: LabAction[];
  resetSession?: boolean;
  semanticJudge?: SemanticJudgeOverride;
  semanticTimeoutMs?: number;
  recordPerformanceSample?: (sample: ToolCallPerformanceSample) => void;
  scoreGraphShadow?: (input: ProductionGraphInput) => Promise<GraphShadowScore | null>;
}): Promise<{ processed: boolean; decisions: Array<Record<string, unknown>>; session: Record<string, unknown> }> {
  return policySessionsFor(input.store).run(input.sessionKey, { reset: input.resetSession }, async (labSession) => {
    const semanticMode = input.semanticJudge ?? "default";
    const config = configWithSemanticOverride(input.config, semanticMode, input.semanticTimeoutMs);
    const semanticProfile = semanticJudgeProfile(semanticMode, config);
    const policyState = labSession.state;
    updateTaskSpec(policyState, [{ role: "user", content: input.command }], config);
    authorizeLabScenarioIngress(policyState, input.actions);
    authorizeLabDemoBusiness(policyState, input.scenario, input.command);
    const messageFindings = [
      ...detectMessageContent(input.command, config),
    ];
    updateAfterMessage(policyState, messageFindings);
    for (const finding of messageFindings) {
      addLabFinding(input.store, config, input.runId, input.sessionKey, finding, {
        command_id: input.commandId,
        scenario: input.scenario,
        source: "command-lab",
        semantic_judge: semanticProfile,
      });
    }

    const decisions: Array<Record<string, unknown>> = [];
    for (const [index, action] of input.actions.entries()) {
      const callStartedAt = performance.now();
      const recordedAt = new Date().toISOString();
      const toolCallId = `lab_${labSession.turn}_${input.commandId}_${index + 1}`;
      const context = { toolCallId, workspaceDir: openClawWorkspaceRoot() };
      const policyAction = labPolicyActionFor(action, input.scenario);
      let graphLearning: GraphTrainingEnvelope | null = null;
      let graphTrainingProjectionMs = 0;
      let graphShadowScore: GraphShadowScore | null = null;
      const evaluation = await supervisionService.evaluate({
        toolName: policyAction.toolName, params: policyAction.params, state: policyState, config, context,
        onPreliminary: async (preliminary) => {
          const graphProjectionStartedAt = performance.now();
          try {
            const graphInput = buildProductionGraphInput({
              graph: preliminary.policy.effects?.semanticActionGraph || policyState.semanticActionGraph,
              currentActionNodeId: preliminary.policy.action_graph_node_id,
              taskMode: preliminary.policy.task_spec.task_mode,
              taskFamily: preliminary.policy.task_spec.task_family,
            });
            graphLearning = createGraphTrainingEnvelope({ sampleId: `lab_graph_${input.commandId}_${index + 1}`, capturedAt: recordedAt, graphInput });
          } catch {
            // Training telemetry is optional and cannot change enforcement.
          }
          graphTrainingProjectionMs = performance.now() - graphProjectionStartedAt;
          graphShadowScore = graphLearning && input.scoreGraphShadow
            ? await input.scoreGraphShadow(graphLearning.input)
            : null;
        },
      });
      const { result } = evaluation;
      graphLearning = graphLearning as GraphTrainingEnvelope | null;
      const { preliminaryPolicyMs, semanticAmbiguousMs, finalPolicyMs } = evaluation.timings;
      const { ambiguousJudgeRouted } = evaluation.routes;
      const severity = severityForDecision(result.decision);
      const normalizedAction: LabAction = {
        toolName: result.policy.action.tool,
        params: result.policy.action.args,
      };
      const performanceSample: ToolCallPerformanceSample = {
        schema_version: TOOL_CALL_PERFORMANCE_SCHEMA_VERSION,
        recorded_at: recordedAt,
        stages_ms: {
          preprocessing: 0,
          preliminary_policy: roundDurationMs(preliminaryPolicyMs),
          semantic_action_graph: 0,
          graph_training_projection: roundDurationMs(graphTrainingProjectionMs),
          semantic_tool_judge: 0,
          semantic_memory_judge: 0,
          semantic_ambiguous_judge: roundDurationMs(semanticAmbiguousMs),
          final_policy: roundDurationMs(finalPolicyMs),
          decision_ready: roundDurationMs(performance.now() - callStartedAt),
          effects_and_checkpoint: 0,
          total_until_audit: 0,
        },
        semantic_action_graph_evaluations: 0,
        judge_routes: { tool: false, memory: false, ambiguous: ambiguousJudgeRouted, total: Number(ambiguousJudgeRouted) },
        graph_projection: {
          nodes: graphLearning?.input.graph.nodes.length || 0,
          edges: graphLearning?.input.graph.edges.length || 0,
          truncated: graphLearning?.input.graph.projection_truncated ?? true,
        },
        decision: result.decision,
        deterministic_disposition: result.policy.deterministic_disposition,
      };
      performanceSample.stages_ms.effects_and_checkpoint = roundDurationMs(performance.now() - callStartedAt);
      performanceSample.stages_ms.total_until_audit = roundDurationMs(performance.now() - callStartedAt);
      supervisionService.commit(policyState, result.policy, config, result.decision === "allow" ? "executing" : "blocked");
      const payload = {
        toolName: action.toolName,
        normalized_tool: result.policy.action.tool,
        toolCallId,
        params: action.params,
        decision: result.decision,
        original_decision: result.decision,
        raw_decision: result.policy.intervention?.raw_decision || result.decision,
        intervention: result.policy.intervention || null,
        intervention_mode: result.policy.intervention?.mode || config.intervention.mode,
        risk_score: result.risk_score,
        sentry_score: result.policy.sentry_score,
        deterministic_block: result.policy.deterministic_block,
        deterministic_disposition: result.policy.deterministic_disposition,
        reasons: result.policy.reasons,
        violations: result.policy.violations,
        verdict: result.policy.findings.some((finding) => finding.verdict === "block")
          ? "block"
          : result.policy.findings.some((finding) => finding.verdict === "require_approval")
            ? "require_approval"
            : "pass",
        task_spec: result.policy.task_spec,
        contaminated: policyState.contaminated,
        risk_vector: result.policy.risk_vector,
        trust: policyTrustSnapshot(policyState),
        system_monitor: systemMonitorStatus(),
        semantic_judge: semanticProfile,
        lab_session: {
          turn: labSession.turn,
          reset: Boolean(input.resetSession),
        },
        findings: result.findings,
        command_id: input.commandId,
        scenario: input.scenario,
        source: "command-lab",
        graph_learning: graphLearning,
        graph_shadow: graphShadowScore,
        performance: performanceSample,
      };
      input.store.add({
        run_id: input.runId,
        session_key: input.sessionKey,
        type: "tool_decision",
        layer: "Tool Boundary",
        severity,
        title: `Business tool decision: ${action.toolName}`,
        summary: result.summary,
        payload,
      });
      input.recordPerformanceSample?.(performanceSample);
      for (const finding of result.findings) {
        addLabFinding(input.store, config, input.runId, input.sessionKey, finding, {
          toolName: action.toolName,
          toolCallId,
          command_id: input.commandId,
          scenario: input.scenario,
          source: "command-lab",
          semantic_judge: semanticProfile,
        });
      }
      if (result.decision === "deny" || result.decision === "ask") {
        input.store.add({
          run_id: input.runId,
          session_key: input.sessionKey,
          type: "alert",
          layer: "Tool Boundary",
          severity: result.decision === "deny" ? "danger" : "warning",
          title: `Lab policy ${result.decision}: ${action.toolName}`,
          summary: result.summary,
          payload,
        });
        addToolResultRecord(input, normalizedAction, toolCallId, result.decision === "deny" ? "blocked" : "skipped", {
          ok: false,
          reason: result.summary,
        });
      } else {
        const executionAction = isLabDemoWorkspaceTool(action.toolName) ? action : normalizedAction;
        const execution = await executeBusinessTool(executionAction, config, `${input.scenario}\n${input.command}`);
        addToolResultRecord(input, normalizedAction, toolCallId, execution.ok ? "executed" : "failed", execution);
        const executionFindings = Array.isArray(execution.findings) ? execution.findings as Array<Record<string, unknown>> : [];
        if (executionFindings.length) {
          const runtimeFindings = executionFindings.filter((finding) => String(finding.layer || "") === "Tool Boundary");
          const nonRuntimeFindings = executionFindings.filter((finding) => String(finding.layer || "") !== "Tool Boundary");
          updateAfterRuntimeFindings(policyState, normalizedAction.toolName, runtimeFindings as never);
          updateAfterMessage(policyState, executionFindings as never);
          for (const finding of executionFindings) {
            addLabFinding(input.store, config, input.runId, input.sessionKey, finding, {
              toolName: normalizedAction.toolName,
              toolCallId,
              command_id: input.commandId,
              scenario: input.scenario,
              source: String(finding.layer || "") === "Tool Boundary" ? "ebpf-runtime-audit" : "memory-guard-storage",
              semantic_judge: semanticProfile,
            });
          }
          if (nonRuntimeFindings.length) {
            input.store.add({
              run_id: input.runId,
              session_key: input.sessionKey,
              type: "alert",
              layer: "State Integrity",
              severity: nonRuntimeFindings.some((finding) => finding.verdict === "block") ? "danger" : "warning",
              title: `Memory Guard finding: ${normalizedAction.toolName}`,
              summary: nonRuntimeFindings.map((finding) => String(finding.reason || "memory guard finding")).join("; "),
              payload: {
                toolName: normalizedAction.toolName,
                toolCallId,
                command_id: input.commandId,
                scenario: input.scenario,
                memory_guard: execution.memory_guard,
                findings: nonRuntimeFindings,
              },
            });
          }
          if (runtimeFindings.length) {
            input.store.add({
              run_id: input.runId,
              session_key: input.sessionKey,
              type: "alert",
              layer: "Tool Boundary",
              severity: "warning",
              title: `eBPF runtime audit finding: ${normalizedAction.toolName}`,
              summary: runtimeFindings.map((finding) => String(finding.reason || "runtime audit finding")).join("; "),
              payload: {
                toolName: normalizedAction.toolName,
                toolCallId,
                command_id: input.commandId,
                scenario: input.scenario,
                runtime_audit: execution.runtime_audit,
                findings: runtimeFindings,
              },
            });
          }
        }
        if (execution.ok) {
          const resultContent = execution.output ?? execution;
          const toolResultFindings = resultFindings(toolCallId, resultContent, policyState, config, normalizedAction.toolName);
          updateAfterMessage(policyState, toolResultFindings);
          for (const finding of toolResultFindings) {
            addLabFinding(input.store, config, input.runId, input.sessionKey, finding, {
              toolName: normalizedAction.toolName,
              toolCallId,
              command_id: input.commandId,
              scenario: input.scenario,
              source: "command-lab",
              semantic_judge: semanticProfile,
            });
          }
          if (toolResultFindings.length) {
            input.store.add({
              run_id: input.runId,
              session_key: input.sessionKey,
              type: "alert",
              layer: "Context Provenance",
              severity: "warning",
              title: `Tool result tainted: ${normalizedAction.toolName}`,
              summary: toolResultFindings.map((finding) => finding.reason).join("; "),
              payload: {
                toolName: normalizedAction.toolName,
                toolCallId,
                command_id: input.commandId,
                scenario: input.scenario,
                trust: policyTrustSnapshot(policyState),
                findings: toolResultFindings,
              },
            });
          }
        } else {
          resultFindings(
            toolCallId,
            null,
            policyState,
            config,
            normalizedAction.toolName,
            { error: execution.error || execution.reason || "tool execution failed" },
          );
        }
      }
      decisions.push({
        toolName: action.toolName,
        normalized_tool: result.policy.action.tool,
        decision: result.decision,
        raw_decision: result.policy.intervention?.raw_decision || result.decision,
        intervention: result.policy.intervention || null,
        risk_score: result.risk_score,
        violations: result.policy.violations,
        findings: result.findings.length,
        finding_types: Array.from(new Set(result.findings.map((finding) => finding.finding_type))),
        semantic_judge_called: result.findings.some((finding) => finding.finding_type === "semantic"),
        semantic_judge: semanticProfile,
      });
    }
    return {
      processed: true,
      decisions,
      session: {
        key: input.sessionKey,
        turn: labSession.turn,
        contaminated: policyState.contaminated,
        trust: policyTrustSnapshot(policyState),
        semantic_judge: semanticProfile,
      },
    };
  });
}

function addToolResultRecord(
  input: {
    store: RecordStore;
    config: PluginConfig;
    runId: string;
    sessionKey: string;
    commandId: string;
    scenario: string;
  },
  action: LabAction,
  toolCallId: string,
  executionStatus: ExecutionStatus,
  execution: BusinessExecution,
): void {
  const severity: RecordSeverity = executionStatus === "executed"
    ? "success"
    : executionStatus === "failed"
      ? "warning"
      : executionStatus === "blocked"
        ? "danger"
        : "info";
  input.store.add({
    run_id: input.runId,
    session_key: input.sessionKey,
    type: "tool_result",
    layer: "Evidence Feedback",
    severity,
    title: `Business tool ${executionStatus}: ${action.toolName}`,
    summary: execution.ok
      ? `${action.toolName} completed`
      : execution.reason || execution.error || `${action.toolName} did not execute`,
    payload: {
      toolName: action.toolName,
      toolCallId,
      params: action.params,
      execution_status: executionStatus,
      ok: execution.ok,
      result: redactExecution(execution, input.config.capture.previewChars),
      command_id: input.commandId,
      scenario: input.scenario,
      source: "command-lab",
      adversarial_input: adversarialFromExecution(action, execution) || undefined,
      trust_runtime: systemMonitorStatus(),
    },
  });
}

function addLabFinding(
  store: RecordStore,
  config: PluginConfig,
  runId: string,
  sessionKey: string,
  finding: Record<string, unknown>,
  extra: Record<string, unknown>,
): void {
  store.add({
    run_id: runId,
    session_key: sessionKey,
    type: "guard_finding",
    layer: String(finding.layer || "Runtime"),
    severity: severityForVerdict(String(finding.verdict || "pass")),
    title: String(finding.reason || "AgentSentry finding"),
    summary: JSON.stringify(finding.evidence || {}).slice(0, config.capture.previewChars),
    payload: {
      ...finding,
      ...extra,
    },
  });
}
