import type { PluginConfig } from "../config.ts";
import { detectMessageContent } from "../core/detect.ts";
import { policyTrustSnapshot, updateAfterMessage, updateTaskSpec } from "../core/policy.ts";
import type { RecordStore } from "../core/records.ts";
import { supervisionService } from "../core/supervision-service.ts";

import { policySessionsFor } from "./policy-sessions.ts";
import { recordParam, optionalInt, severityForDecision } from "./dashboard-utils.ts";
import { parseSemanticJudgeOverride, configWithSemanticOverride, semanticJudgeProfile } from "./semantic-config.ts";
export async function evaluateSidecarPolicy(
  body: Record<string, unknown>,
  store: RecordStore,
  config: PluginConfig,
): Promise<Record<string, unknown>> {
  const toolName = String(body.toolName || body.tool || "").trim();
  if (!toolName) return { ok: false, error: "toolName is required" };
  const params = recordParam(body.params) || {};
  const task = String(body.task || body.userTask || body.command || "").trim();
  const sessionKey = String(body.sessionKey || "sidecar:default").replace(/[^\w:.-]/g, "_").slice(0, 100);
  const resetSession = Boolean(body.resetSession);
  const workspaceDir = String(body.workspaceDir || "").trim();
  const commitState = body.commitState !== false;
  const semanticJudge = parseSemanticJudgeOverride(body.semanticJudge);
  const effectiveConfig = configWithSemanticOverride(config, semanticJudge, optionalInt(body.semanticTimeoutMs, 1000, 30000));
  const semanticProfile = semanticJudgeProfile(semanticJudge, effectiveConfig);
  const runId = `sidecar_${Date.now().toString(36)}`;
  return policySessionsFor(store).run(sessionKey, { reset: resetSession, commit: commitState }, async (session) => {
    const policyState = session.state;

    if (task) {
      updateTaskSpec(policyState, [{ role: "user", content: task }], effectiveConfig);
      const messageFindings = detectMessageContent(task, effectiveConfig);
      updateAfterMessage(policyState, messageFindings);
    }

    const { result } = await supervisionService.evaluate({
      toolName, params, config: effectiveConfig, state: policyState,
      context: { toolCallId: String(body.toolCallId || ""), workspaceDir },
    });
    if (commitState) {
      supervisionService.commit(policyState, result.policy, effectiveConfig,
        result.decision === "allow" ? "executing" : result.decision === "deny" ? "blocked" : "awaiting_approval");
    }

    const payload = {
      sidecar: true,
      sessionKey,
      turn: session.turn,
      commit_state: commitState,
      toolName,
      normalized_tool: result.policy.action.tool,
      params,
      task,
      decision: result.decision,
      raw_decision: result.policy.intervention?.raw_decision || result.decision,
      intervention: result.policy.intervention || null,
      risk_score: result.risk_score,
      deterministic_block: result.policy.deterministic_block,
      deterministic_disposition: result.policy.deterministic_disposition,
      reasons: result.policy.reasons,
      violations: result.policy.violations,
      findings: result.policy.findings,
      semantic_judge: semanticProfile,
      task_spec: result.policy.task_spec,
      trust: policyTrustSnapshot(policyState),
    };
    store.add({
      run_id: runId,
      session_key: sessionKey,
      type: "sidecar_policy_decision",
      layer: "Policy Sidecar",
      severity: severityForDecision(result.decision),
      title: `Sidecar policy: ${toolName}`,
      summary: `${result.decision}; risk=${result.risk_score}`,
      payload,
    });
    return { ok: true, ...payload };
  });
}
