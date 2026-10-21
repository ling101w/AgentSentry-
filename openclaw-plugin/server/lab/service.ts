import { randomUUID } from "node:crypto";
import type { PluginConfig } from "../../config.ts";
import type { RecordStore } from "../../core/records.ts";
import { executeLabActions } from "./runner.ts";
import { labActionsFromCommand, labAdversarialInput } from "./scenarios.ts";
import { policySessionsFor } from "../policy-sessions.ts";
import { optionalInt } from "../dashboard-utils.ts";
import { parseSemanticJudgeOverride, configWithSemanticOverride, semanticJudgeProfile } from "../semantic-config.ts";

type LabRuntime = Pick<Parameters<typeof executeLabActions>[0], "recordPerformanceSample" | "scoreGraphShadow">;

export async function runLabCommand(body: Record<string, unknown>, store: RecordStore, config: PluginConfig, runtime: LabRuntime = {}) {
  const command = String(body.command || "").trim();
  if (!command) throw new Error("command is required");
  const clientId = String(body.clientId || "browser").replace(/[^\w:.-]/g, "_").slice(0, 80);
  const scenario = String(body.scenario || "manual").slice(0, 80);
  const copied = Boolean(body.copied);
  const resetSession = Boolean(body.resetSession);
  const semanticJudge = parseSemanticJudgeOverride(body.semanticJudge);
  const semanticTimeoutMs = optionalInt(body.semanticTimeoutMs, 1000, 30000);
  const benchmarkCaseId = String(body.benchmarkCaseId || "").trim().slice(0, 180);
  const benchmarkSource = String(body.benchmarkSource || "").trim().slice(0, 120);
  const runId = `lab_${randomUUID()}`;

  const actions = labActionsFromCommand(command, scenario, body);
  const effectiveConfig = configWithSemanticOverride(config, semanticJudge, semanticTimeoutMs);
  const semanticProfile = semanticJudgeProfile(semanticJudge, effectiveConfig);
  return policySessionsFor(store).runClient(clientId, runId, resetSession, async (sessionKey) => {
    const record = store.add({
      run_id: runId,
      session_key: sessionKey,
      type: "lab_command",
      layer: "Evidence Feedback",
      severity: "info",
      title: "OpenClaw business test request",
      summary: command.slice(0, 240),
      payload: {
        command,
        scenario,
        copied,
        reset_session: resetSession,
        semantic_judge: semanticProfile,
        benchmark_case_id: benchmarkCaseId || undefined,
        benchmark_source: benchmarkSource || undefined,
        lab_session_state: resetSession ? "reset" : "continued",
        source: "command-lab",
        adversarial_input: labAdversarialInput(scenario) || undefined,
        business_actions: actions.map((action) => ({
          toolName: action.toolName,
          params: action.params,
        })),
      },
    });
    const outcome = await executeLabActions({
      store,
      config: effectiveConfig,
      command,
      scenario,
      runId,
      sessionKey,
      commandId: record.id,
      actions,
      resetSession,
      semanticJudge,
      semanticTimeoutMs,
      recordPerformanceSample: runtime.recordPerformanceSample,
      scoreGraphShadow: runtime.scoreGraphShadow,
    });
    return { ok: true, record, ...outcome };
  });
}
