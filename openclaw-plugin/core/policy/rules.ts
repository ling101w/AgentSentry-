import { PluginConfig } from "../../config.ts";
import { agentCommunicationFindings } from "../agent-trust.ts";
import type { DetectionFinding } from "../detect.ts";
import { dynamicSecurityFindingsFor } from "../dynamic-security.ts";
import { decisionFromRisk, mergeDecision } from "../judge/decision-merge.ts";
import { normalizeMemoryKey } from "../memory-ifc.ts";
import { assessAction, assessActionWithSensitiveAssets, isSensitivePath, isTrustSensitiveSink, shouldHardBlockTaskMismatch, sinkForAction, type ActionAssessment } from "./action-assessment.ts";
import { applyInterventionGate } from "./intervention-gate.ts";
import { evaluateAbacDataFlow } from "./abac.ts";
import { behaviorAnomalyFindingsFor } from "./behavior-baseline.ts";
import { containsAny, flattenText as flattenValueText, hostFromUrl, isLabeledValue, readFirstString, unique } from "./value-utils.ts";
import { targetAllowed } from "../security/url.ts";
import { canonicalizePath, matchAllowedWritePath, matchWorkspaceReadPath } from "../path-security.ts";
import { isAbsolute, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { beginSemanticAction, setSemanticActionDecision, type SemanticProvenanceLink } from "../semantic-action-graph.ts";
import type { DataProvenance } from "../taint/provenance-graph.ts";
import { authorizeCapability, isSideEffectToolCall, type CapabilityAuthorization, type TaskSpec } from "../task-spec/index.ts";
import { resolveToolManifest, type ToolSecurityManifest } from "../tool-manifest.ts";
import { analyzeTrustContent, mergeRiskVectors, riskMax, sourceFromTool, type TrustLabel } from "../trust.ts";
import type { AgentSentryAction, Label, RuntimeFeedbackProfile, PolicyState, PolicyDecision, PolicyDecisionContext } from "./contracts.ts";
import { rememberDataProvenance, normalizePolicyAction, normalizeFindingInput, finding, riskVectorFromFindings, normalizeToolName, toolFrequencyKey, subjectScopesForAction, readValuesAtField, confidentialityRank, publicPersistentMemoryLabel, safeStringify, normalizeExposureText, flattenText, matchExposure, provenanceEvidenceForMatch } from "./support.ts";

const EXPLICIT_NO_EMAIL = ["do not email", "don't email", "no email", "不要发", "别发", "不要发送", "不要给任何人发"];

export function evaluateMutable(
  action: AgentSentryAction,
  state: PolicyState,
  config: PluginConfig,
  incomingFindings: DetectionFinding[],
  context: PolicyDecisionContext,
): PolicyDecision {
  if (context.provenanceAdditions?.length) rememberDataProvenance(state, context.provenanceAdditions);
  const normalizedAction = normalizePolicyAction(action);
  action = normalizedAction.action;
  const normalizedFindings = normalizeFindingInput(incomingFindings);
  const findings = [...normalizedFindings.findings];
  if (normalizedAction.issue) {
    findings.push(finding("Tool Boundary", "deterministic", "block", "tool action input could not be safely analyzed; policy failed closed", 100, {
      issue: normalizedAction.issue,
      tool: action.tool,
    }));
  }
  if (normalizedFindings.invalidCount) {
    findings.push(finding("Tool Boundary", "deterministic", "block", "security finding input failed validation; policy failed closed", 100, {
      invalid_findings: normalizedFindings.invalidCount,
    }));
  }
  const reasons: string[] = [];
  const violations: string[] = [];
  const riskScoringEnabled = config.detection.enabled;
  let risk = riskScoringEnabled ? baseToolRisk(action.tool) : 0;

  const taskSpec = state.taskSpec;
  const assessment = assessPolicyAction(action, config);
  const extractedAuthorization = authorizeCapability(taskSpec, action, { taskMode: taskSpec.task_mode });
  // Capability contracts can prove that a call is a caller-bound, read-only
  // query. Treat that as a scoped authorization so downstream risk, graph and
  // dynamic-security stages do not repeatedly reinterpret an already proven
  // safe read as an unknown high-impact action.
  const implicitManifestRead = !extractedAuthorization.authorized && manifestAllowsImplicitRead(action, taskSpec);
  const capabilityAuthorization: CapabilityAuthorization = implicitManifestRead
    ? { action: "allow", authorized: true, reason: "manifest_bound_read" }
    : extractedAuthorization;
  let actionGraphNodeId = "";
  const actionGraphStartedAt = performance.now();
  try {
    const graphAttempt = beginSemanticAction(state.semanticActionGraph, {
      toolCallId: context.toolCallId,
      tool: action.tool,
      originalTool: action.originalTool,
      authorization: capabilityAuthorization,
      sink: sinkForAction(action, assessment),
      effects: {
        external: assessment.externalSink,
        persistence: assessment.persistence || assessment.systemMutation,
        execution: action.tool === "shell_exec" || assessment.dangerousCommand,
        sensitive: assessment.sensitive,
        sideEffect: isSideEffectToolCall(action),
      },
      semantic: context.semanticGraph,
      provenance: state.dataProvenance,
      consumes: context.provenanceLinks,
    });
    actionGraphNodeId = graphAttempt.actionNodeId;
    for (const violation of graphAttempt.violations) {
      const observedPath = violation.path.certainty === "observed";
      const blockingPath = violation.path.verdict === "block";
      findings.push(finding(
        "Semantic Action Graph",
        observedPath ? "deterministic" : "heuristic",
        blockingPath ? "block" : "require_approval",
        violation.reason,
        blockingPath ? 100 : 65,
        {
        graph_version: state.semanticActionGraph.version,
        path_id: violation.path.id,
        risk: violation.path.risk,
        path_verdict: violation.path.verdict,
        path_certainty: violation.path.certainty,
        path_confidence: violation.path.confidence,
        source_node_id: violation.path.sourceNodeId,
        action_node_id: violation.path.actionNodeId,
        sink_node_id: violation.path.sinkNodeId,
        node_count: violation.path.nodeIds.length,
        edge_count: violation.path.edgeIds.length,
        node_ids: compactEvidenceList(violation.path.nodeIds, 32),
        edge_ids: compactEvidenceList(violation.path.edgeIds, 32),
        causal_chain: compactEvidenceList(violation.path.steps, 24),
        },
      ));
      if (blockingPath) violations.push(violation.reason);
    }
  } catch {
    findings.push(finding("Semantic Action Graph", "deterministic", "block", "semantic action graph evaluation failed; policy failed closed", 100, {
      tool: action.tool,
    }));
    violations.push("semantic action graph evaluation failed");
  } finally {
    try {
      context.onPerformance?.("semantic_action_graph", performance.now() - actionGraphStartedAt);
    } catch {
      // Observability must never affect enforcement.
    }
  }
  if (!capabilityAuthorization.authorized && !allowsImplicitLowRiskRead(action, assessment, capabilityAuthorization.reason)) {
    const verdict = capabilityAuthorization.action === "deny" ? "block" : "require_approval";
    const reason = capabilityAuthorizationReason(capabilityAuthorization.reason, action.tool);
    findings.push(finding("Intent Authorization", "deterministic", verdict, reason, verdict === "block" ? 100 : 45, {
      tool: action.tool,
      authorization_reason: capabilityAuthorization.reason,
      expected_target: capabilityAuthorization.expectedTarget || "",
      actual_target: capabilityAuthorization.actualTarget || "",
      capability: capabilityAuthorization.capability || null,
    }));
    if (verdict === "block") violations.push(reason);
  }
  if (riskScoringEnabled && action.tool === "shell_exec" && !assessment.highRisk) {
    risk = 8;
  }
  const directProvenanceRisk = config.policy.deterministic && state.provenanceBlocked
    ? provenanceRiskForAction(action, state)
    : null;
  if (directProvenanceRisk) {
    const isolatedRead = action.tool === "read_file" && !assessment.sensitive && !assessment.systemMutation;
    findings.push(finding(
      "Context Provenance",
      "deterministic",
      isolatedRead ? "pass" : "block",
      isolatedRead
        ? "tool reads a risky workspace item for isolated analysis; downstream high-risk sinks remain restricted"
        : "tool call directly references a workspace item marked risky by provenance scan",
      isolatedRead ? 10 : 100,
      directProvenanceRisk,
    ));
    if (!isolatedRead) violations.push("tool call directly references risky workspace item");
  }

  const ifcExecutionFindings = config.policy.deterministic
    ? ifcExecutionBoundaryFindings(action, assessment, state, capabilityAuthorization, context.provenanceLinks || [])
    : [];
  for (const ifcFinding of ifcExecutionFindings) {
    findings.push(ifcFinding);
    if (ifcFinding.verdict === "block") violations.push(ifcFinding.reason);
  }

  const memoryIfcFindings = config.policy.deterministic ? persistentMemoryIFCFindings(action, assessment, state) : [];
  for (const memoryFinding of memoryIfcFindings) {
    findings.push(memoryFinding);
    if (memoryFinding.verdict === "block") violations.push(memoryFinding.reason);
  }

  const outsideTaskSpec = !implicitManifestRead
    && (taskSpec.forbidden_tools.includes(action.tool) || !taskSpec.allowed_tools.includes(action.tool));
  if (config.policy.deterministic && outsideTaskSpec && shouldHardBlockTaskMismatch(action, assessment, state)) {
    const reason = authorizationBoundaryReason(action, assessment, "deny");
    violations.push(reason);
    findings.push(finding("Tool Boundary", "deterministic", "block", reason, 100, { tool: action.tool, assessment, authorization_gap: "unauthorized_high_risk" }));
  } else if (riskScoringEnabled && outsideTaskSpec) {
    risk += assessment.highRisk ? 40 : 12;
    const implicit = allowsImplicitLowRiskRead(action, assessment, "missing_explicit_authorization");
    findings.push(finding(
      "Tool Boundary",
      "heuristic",
      implicit ? "pass" : assessment.highRisk ? "require_approval" : "pass",
      authorizationBoundaryReason(action, assessment, implicit ? "allow" : "ask"),
      implicit ? 0 : assessment.highRisk ? 35 : 8,
      { tool: action.tool, assessment, authorization_gap: implicit ? "implicit_low_risk_read" : "needs_clarification" },
    ));
  } else {
    reasons.push("tool is allowed by TaskSpec");
  }

  if (riskScoringEnabled) {
    const alignmentFindings = decisionAlignment(action, taskSpec);
    findings.push(...alignmentFindings);
  }

  const policyViolations = config.policy.deterministic
    ? deterministicViolations(action, taskSpec, state, config, context.workspaceDir || "")
    : [];
  for (const violation of policyViolations) {
    violations.push(violation);
    findings.push(finding("Tool Boundary", "deterministic", "block", violation, 100, { tool: action.tool }));
  }
  for (const reason of findings
    .filter((item) => item.finding_type === "deterministic" && item.verdict === "block")
    .map((item) => item.reason)) {
    violations.push(reason);
  }

  const agentFindings = config.multiAgentSecurity.enabled
    ? agentCommunicationFindings(action, config)
    : [];
  findings.push(...agentFindings);
  for (const finding of agentFindings) {
    if (finding.verdict === "block") violations.push(finding.reason);
  }

  if (riskScoringEnabled) {
    const trajectoryFindings = trajectoryFindingsFor(action, state, config);
    findings.push(...trajectoryFindings);

    const behaviorFindings = behaviorAnomalyFindingsFor(action, state, config);
    findings.push(...behaviorFindings);

    const runtimeFeedbackFindings = runtimeFeedbackFindingsFor(action, state, config);
    findings.push(...runtimeFeedbackFindings);

    const abacFindings = abacFindingsFor(action, state);
    findings.push(...abacFindings);

    const taskSpecFindings = taskSpecBoundaryFindings(action, state, config);
    findings.push(...taskSpecFindings);

    const manifestPurposeFindings = manifestPurposeBoundaryFindings(action, state);
    findings.push(...manifestPurposeFindings);

    const dynamicFindings = dynamicSecurityFindingsFor(action, assessment, state.dynamicSecurity, config);
    findings.push(...dynamicFindings);
  }

  const actionRisk = riskVectorFromFindings(findings);
  const combinedRisk = mergeRiskVectors(state.aggregateRisk, actionRisk);
  const blockedTaintForRisk = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (riskScoringEnabled && blockedTaintForRisk) {
    risk += Math.min(35, Math.max(15, Math.trunc(blockedTaintForRisk.confidence / 3)));
  }
  if (riskScoringEnabled && (assessment.highRisk || isTrustSensitiveSink(action, assessment))) {
    risk += Math.min(45, Math.trunc(riskMax(actionRisk) / 2));
  }
  const sentryScore = riskScoringEnabled ? heuristicScore(findings) : 0;
  if (riskScoringEnabled) {
    risk += sentryScore;
    risk += taintRisk(action, state, config);
  }
  const deterministicBlock = violations.length > 0 || findings.some((item) => item.finding_type === "deterministic" && item.verdict === "block");
  if (deterministicBlock) risk = Math.max(risk + 35, 100);
  const deterministicDecision = deterministicBlock
    ? "deny"
    : findings.some((item) => item.finding_type === "deterministic" && item.verdict === "require_approval")
      ? "ask"
      : "allow";
  const additionalDecision = riskScoringEnabled
    ? decisionFromRisk({
      hasBlock: findings.some((item) => item.verdict === "block"),
      hasApproval: findings.some((item) => item.verdict === "require_approval"),
      riskScore: risk,
      askThreshold: config.detection.askThreshold,
      denyThreshold: config.detection.denyThreshold,
    })
    : "allow";
  const rawDecision = mergeDecision(deterministicDecision, additionalDecision);
  const intervention = applyInterventionGate({
    mode: config.intervention.mode,
    rawDecision,
    findings,
    preserveSafetyBoundaries: config.intervention.preserveSafetyBoundaries,
  });
  const decision = intervention.decision;
  if (actionGraphNodeId) setSemanticActionDecision(state.semanticActionGraph, actionGraphNodeId, decision);

  return {
    decision,
    risk_score: Math.min(risk, 150),
    reasons,
    violations: unique(violations),
    deterministic_block: deterministicBlock,
    sentry_score: sentryScore,
    risk_vector: combinedRisk,
    trust_labels: state.trustLabels.slice(-8),
    action,
    task_spec: taskSpec,
    findings: dedupeFindings(findings),
    action_graph_node_id: actionGraphNodeId,
    deterministic_disposition: config.intervention.mode === "evidence-gated"
      ? decision === "deny"
        ? "deny"
        : decision === "ask"
          ? "ambiguous"
          : "allow"
      : deterministicBlock
        ? "deny"
        : findings.some((item) => item.verdict !== "pass") || decision !== "allow"
          ? "ambiguous"
          : "allow",
    intervention,
  };
}

function capabilityAuthorizationReason(reason: string, tool: string): string {
  if (reason === "unknown_tool_capability" && (resolveToolManifest(tool) || resolveToolManifest(normalizeToolName(tool)))) {
    return `已注册工具 ${tool} 的能力已完成基线登记，但当前任务没有覆盖它的目标或副作用范围，需要确认`;
  }
  const messages: Record<string, string> = {
    explicit_user_denial: `用户明确禁止 ${tool} 动作`,
    missing_explicit_authorization: `${tool} 缺少明确授权，属于授权不明确`,
    authorization_parse_failed: `${tool} 的任务意图解析失败，建议先确认输入属于说明、数据还是实际授权`,
    non_authoritative_context_cannot_grant_side_effects: "记忆或工具返回内容不能授予新的外部副作用权限",
    non_authoritative_context: "非用户上下文不能建立该工具权限",
    recipient_outside_authorization: "邮件收件人不在用户明确授权范围内",
    attachment_outside_authorization: "邮件附件不在用户明确授权文件范围内",
    path_outside_authorization: "文件路径不在用户明确授权路径范围内",
    target_outside_authorization: "网络目标不在用户明确授权目标范围内",
    host_outside_authorization: "网络主机不在用户明确授权主机范围内",
    method_outside_authorization: "HTTP 方法不在用户明确授权方法范围内",
    command_outside_authorization: "Shell 命令不在用户明确授权命令范围内",
    unknown_tool_capability: `${tool} 没有已注册的能力模型，需要确认`,
  };
  return messages[reason] || `${tool} 能力授权校验未通过：${reason}`;
}

function allowsImplicitLowRiskRead(action: AgentSentryAction, assessment: ActionAssessment, reason: string): boolean {
  if (reason !== "missing_explicit_authorization" && reason !== "unknown_tool_capability") return false;
  if (assessment.highRisk || assessment.sensitive || assessment.persistence || assessment.systemMutation || assessment.externalSink) return false;
  if (action.tool === "read_file" || action.tool === "memory_read") return true;
  if (action.tool !== "call_api") return false;
  const method = readFirstString(action.args, ["method", "httpMethod", "verb"]).toUpperCase() || "GET";
  return ["GET", "HEAD", "OPTIONS"].includes(method);
}

function authorizationBoundaryReason(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  disposition: "allow" | "ask" | "deny",
): string {
  if (disposition === "allow") {
    return `低风险只读动作 ${action.tool} 未命中显式授权，按最小权限记录审计后放行`;
  }
  if (disposition === "ask") {
    return `授权不明确：${action.tool} 未在当前任务授权范围内，执行前需要确认目标、数据范围和副作用`;
  }
  const detail = assessment.reasons.length ? `；风险原因：${assessment.reasons.join("；")}` : "";
  return `未授权高风险动作：${action.tool} 超出当前任务授权范围${detail}`;
}

function deterministicViolations(
  action: AgentSentryAction,
  taskSpec: TaskSpec,
  state: PolicyState,
  config: PluginConfig,
  workspaceDir: string,
): string[] {
  const violations: string[] = [];
  const assessment = assessAction(action, config);
  const argsAnalysis = analyzeTrustContent(action.args, {
    source: sourceFromTool(action.tool),
    sourceId: action.originalTool,
    toolName: action.originalTool,
    previewChars: config.capture.previewChars,
  });
  if (action.tool === "read_webpage") {
    const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
    if (!targetAllowed(url, taskSpec.allowed_targets)) {
      violations.push(`target ${url || "<empty>"} is outside allowed_targets`);
    }
  }

  const blockedTaint = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (blockedTaint) {
    violations.push(`ABAC blocked high-risk sink because taint profile disallows flow to ${blockedTaint.sink}`);
  }
  if (isTrustSensitiveSink(action, assessment) && argsAnalysis.label.confidentiality === "secret") {
    violations.push("tool arguments carry secret-tainted data");
  }
  if (argsAnalysis.findings.some((finding) => finding.verdict === "block" && finding.finding_type === "deterministic")) {
    violations.push("tool arguments match deterministic trust-risk policy");
  }

  if (action.tool === "send_email") {
    const recipients = readStringValues(action.args, ["recipient", "recipients", "to", "target", "email"]);
    const body = readFirstString(action.args, ["body", "content", "message", "text"]);
    const unauthorizedRecipient = recipients.find((recipient) => !config.policy.allowlistedRecipients.includes(recipient));
    if (config.policy.allowlistedRecipients.length && unauthorizedRecipient) {
      violations.push(`recipient ${unauthorizedRecipient} is not allowlisted`);
    }
    if (config.policy.sensitiveAssets.some((asset) => asset && body.toLowerCase().includes(asset.toLowerCase()))) {
      violations.push("body contains secret-tainted data");
    }
    if (!taskSpec.allowed_tools.includes("send_email") && config.policy.sensitiveAssets.some((asset) => asset && body.toLowerCase().includes(asset.toLowerCase()))) {
      violations.push("邮件正文包含敏感资产且当前任务没有邮件发送授权");
    }
  }

  if (action.tool === "write_file") {
    const requestedPath = readFirstString(action.args, ["path", "file", "filename", "target"]);
    const content = readFirstString(action.args, ["content", "body", "text", "patch", "input"]);
    let effectivePath = requestedPath;
    if (!requestedPath.trim()) violations.push("missing write path");
    if (config.policy.restrictWritesToAllowedRoots) {
      const needsWorkspace = !isAbsolute(requestedPath) || config.policy.allowedWriteRoots.some((root) => !isAbsolute(root));
      if (needsWorkspace && !workspaceDir.trim()) {
        violations.push("write path cannot be authorized without a workspace root");
      } else {
        const writeBaseDir = workspaceDir || process.cwd();
        const allowedRoots = config.policy.allowedWriteRoots.map((root) => isAbsolute(root) ? root : resolve(writeBaseDir, root));
        const boundary = matchAllowedWritePath(requestedPath, allowedRoots, writeBaseDir);
        if (!boundary.allowed) violations.push(boundary.reason || "write path is outside allowed roots");
        else effectivePath = boundary.target;
      }
    } else if (requestedPath.trim()) {
      if (!isAbsolute(requestedPath) && !workspaceDir.trim()) {
        violations.push("write path cannot be canonicalized without a workspace root");
      } else {
        try {
          effectivePath = canonicalizePath(isAbsolute(requestedPath) ? requestedPath : resolve(workspaceDir, requestedPath));
        } catch (error) {
          violations.push(`cannot canonicalize write path: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
    const path = effectivePath.replace(/\\/g, "/").toLowerCase();
    const effectiveAssessment = effectivePath === requestedPath
      ? assessment
      : assessAction({ ...action, args: { ...action.args, path: effectivePath } }, config);
    if (effectiveAssessment.systemMutation) violations.push("write path targets protected system path");
    if (isSensitivePath(path, config)) violations.push("write path references sensitive asset");
    if (config.policy.sensitiveAssets.some((asset) => asset && content.toLowerCase().includes(asset.toLowerCase()))) {
      violations.push("content contains secret-tainted data");
    }
    const skillSurface = /(^|\/)(?:skills)(?:\/|$)/i.test(path) || /(^|\/)skill\.md$/i.test(path);
    if (/(^|\/)(memory\.md|agents\.md|soul\.md|user\.md|openclaw\.json)$/i.test(path) || /(^|\/)(?:cron\.d|systemd|startup)(?:\/|$)/i.test(path)) {
      violations.push("write path targets memory, configuration, startup, or skill surface");
    }
    const writeContentAnalysis = analyzeTrustContent(content, { source: path.includes("skill") ? "skill" : "memory", path, previewChars: config.capture.previewChars });
    if (writeContentAnalysis.findings.some((finding) => finding.verdict === "block")) {
      violations.push("write content contains persistence or skill hijack instructions");
    }
    if (skillSurface && !taskSpec.allowed_tools.includes("write_file")) {
      violations.push("Skill 写入缺少用户明确授权");
    }
    if (!taskSpec.allowed_tools.includes("write_file") && effectiveAssessment.highRisk) {
      violations.push("task intent does not allow file write");
    }
  }

  if (action.tool === "read_file") {
    const requestedPath = readFirstString(action.args, ["path", "file", "filename", "target"]);
    const boundary = matchWorkspaceReadPath(requestedPath, workspaceDir);
    if (!boundary.allowed) violations.push(boundary.reason || "read path is outside workspace root");
    const effectivePath = boundary.allowed ? boundary.target : requestedPath;
    const path = effectivePath.replace(/\\/g, "/").toLowerCase();
    if (isSensitivePath(path, config)) {
      violations.push("read path references sensitive asset");
    }
  }

  if (action.tool === "call_api") {
    const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
    const host = hostFromUrl(url);
    let apiTargetAllowed = true;
    if (!targetAllowed(url, taskSpec.allowed_targets)) {
      violations.push(`target ${url || "<empty>"} is outside allowed_targets`);
      apiTargetAllowed = false;
    }
    if (host) {
      if (config.policy.allowlistedApiHosts.length && !config.policy.allowlistedApiHosts.includes(host)) {
        violations.push(`api host ${host} is not allowlisted`);
      }
      if (apiTargetAllowed && (!config.policy.allowlistedApiHosts.length || config.policy.allowlistedApiHosts.includes(host))) {
        state.apiCallCounts.set(host, (state.apiCallCounts.get(host) || 0) + 1);
      }
      if ((state.apiCallCounts.get(host) || 0) > 10) violations.push("api rate exceeds configured limit");
    }
    if (/[?&]gatewayURL\s*=\s*wss?:\/\//i.test(url) && !/[?&]gatewayURL\s*=\s*wss?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(url)) {
      violations.push("api call includes non-local Control UI gateway override");
    }
  }

  if (action.tool === "shell_exec") {
    const command = readFirstString(action.args, ["command", "cmd", "script", "input"]);
    if (command && assessment.highRisk) violations.push("shell command requires explicit review");
  }

  if (action.tool === "memory_write") {
    const content = readFirstString(action.args, ["content", "body", "text", "value"]);
    const analysis = analyzeTrustContent(content, { source: "memory", sourceId: "memory_write", previewChars: config.capture.previewChars });
    if (analysis.findings.some((finding) => finding.verdict === "block")) {
      violations.push("memory write contains privileged persistent instruction");
    }
    if (!taskSpec.allowed_tools.includes("memory_write") && analysis.findings.some((finding) => finding.verdict === "block")) {
      violations.push("高风险记忆写入缺少用户明确授权");
    }
  }

  return unique(violations);
}

function decisionAlignment(action: AgentSentryAction, taskSpec: TaskSpec): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const loweredTask = taskSpec.task.toLowerCase();
  const assessment = assessActionWithSensitiveAssets(action, taskSpec.sensitive_assets);
  if (action.tool === "send_email" && containsAny(loweredTask, EXPLICIT_NO_EMAIL)) {
    findings.push(finding("Intent Authorization", "heuristic", "require_approval", "email action conflicts with explicit user constraint", 35, { tool: action.tool }));
  }
  if ((assessment.highRisk || isTrustSensitiveSink(action, assessment)) && !taskSpec.allowed_tools.includes(action.tool)) {
    findings.push(finding("Intent Authorization", "heuristic", "require_approval", "high-risk action deviates from task intent", 30, { tool: action.tool }));
  }
  return findings;
}

function trajectoryFindingsFor(action: AgentSentryAction, state: PolicyState, config: PluginConfig): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const frequencyKey = toolFrequencyKey(action);
  const count = state.history.filter((item) => (item.frequencyKey || item.originalTool || item.tool) === frequencyKey).length;
  if (count >= 3) {
    const assessment = assessAction(action, config);
    const budget = workflowFrequencyBudget(action, state, assessment, count + 1);
    findings.push(finding(
      "Evidence Feedback",
      "heuristic",
      budget.requiresApproval ? "require_approval" : "pass",
      budget.reason,
      budget.requiresApproval ? 20 : 0,
      {
        tool: action.tool,
        original_tool: action.originalTool,
        frequency_key: frequencyKey,
        count: count + 1,
        workflow_budget: budget,
      },
    ));
  }
  const assessment = assessAction(action, config);
  findings.push(...sensitiveReadAggregationFindings(action, state));
  const blockedTaint = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (blockedTaint) {
    findings.push(finding("Evidence Feedback", "heuristic", "require_approval", "taint profile tightens this high-risk sink", 20, {
      tool: action.tool,
      sink: blockedTaint.sink,
      taint: blockedTaint,
    }));
  }
  const readOnlyTask = /summari[sz]e|总结|概括|查看|阅读|看看|分析/.test(state.currentTask.toLowerCase())
    && !/(发送|发邮件|email|mail|写入|保存|执行|运行|记住|memory|remember|shell|command)/i.test(state.currentTask);
  const lastRead = state.history.slice(-4).some((item) => item.tool === "read_webpage" || item.tool === "read_file" || item.tool === "call_api");
  if (readOnlyTask && lastRead && isTrustSensitiveSink(action, assessment)) {
    findings.push(finding("Intent Authorization", "deterministic", "block", "dynamic intent tracking detected drift from read-only task to high-risk action", 100, {
      task: state.currentTask,
      tool: action.tool,
      recent_tools: state.history.slice(-4).map((item) => item.tool),
    }));
  }
  return findings;
}

function sensitiveReadAggregationFindings(action: AgentSentryAction, state: PolicyState): DetectionFinding[] {
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!envelope || !isReadOnlyManifest(envelope.manifest)) return [];
  const currentClassification = envelope.manifest.dataClassification;
  if (currentClassification !== "user_private" && currentClassification !== "secret") return [];

  const prior = [...state.toolResultLabels.values()]
    .filter((label) => (label.tags || []).some((tag) => tag === "manifest:user_private" || tag === "manifest:secret"));
  const currentScopes = subjectScopesForAction(envelope.manifest, action);
  if (sameSubjectScope(currentScopes, prior)) return [];
  const sourceCount = new Set(prior.map((label) => label.source)).size;
  if (!sourceCount) return [];

  return [finding(
    "Data Aggregation",
    "deterministic",
    "require_approval",
    "连续读取已形成敏感数据聚合，需要确认当前读取是否仍符合最小必要范围",
    currentClassification === "secret" || sourceCount >= 2 ? 45 : 30,
    {
      basis: "cross_tool_sensitive_read_aggregation",
      current_classification: currentClassification,
      prior_sensitive_source_count: sourceCount,
      prior_classifications: unique(prior.flatMap((label) => (label.tags || [])
        .filter((tag) => tag.startsWith("manifest:"))
        .map((tag) => tag.slice("manifest:".length)))),
      current_subject_scope_count: currentScopes.length,
      prior_subject_scope_count: unique(prior.flatMap((label) => label.subject_scopes || [])).length,
    },
  )];
}

function sameSubjectScope(currentScopes: string[], prior: Label[]): boolean {
  if (!currentScopes.length || !prior.length) return false;
  const priorScopes = prior.map((label) => label.subject_scopes || []);
  if (priorScopes.some((scopes) => !scopes.length)) return false;
  return priorScopes.every((scopes) => scopes.some((scope) => currentScopes.includes(scope)));
}

function isReadOnlyManifest(manifest: ToolSecurityManifest): boolean {
  return manifest.sideEffects.length > 0
    && manifest.sideEffects.every((effect) => effect === "none" || effect === "file_read" || effect === "network_read")
    && !manifest.canExfiltrate;
}

function workflowFrequencyBudget(
  action: AgentSentryAction,
  state: PolicyState,
  assessment: ActionAssessment,
  count: number,
): { requiresApproval: boolean; reason: string; basis: string; count: number } {
  if (isLowImpactWorkflowRead(action, assessment)) {
    return {
      requiresApproval: false,
      reason: "同一只读业务工具调用次数偏多，已记录审计，不打断正常多步任务",
      basis: "read_only_workflow_budget",
      count,
    };
  }
  if (isExplicitWorkflowSideEffect(action, state, assessment)) {
    return {
      requiresApproval: false,
      reason: "显式授权的工作流副作用工具调用次数偏多，参数仍在业务边界内，已记录审计",
      basis: "explicit_side_effect_workflow_budget",
      count,
    };
  }
  return {
    requiresApproval: true,
    reason: "同一高影响工具调用次数偏多，需要确认是否仍属于当前任务",
    basis: "high_impact_frequency_review",
    count,
  };
}

function isLowImpactWorkflowRead(action: AgentSentryAction, assessment: ActionAssessment): boolean {
  if (assessment.highRisk || assessment.sensitive || assessment.persistence || assessment.systemMutation || assessment.dangerousCommand) return false;
  if (["external_api_read", "read_webpage", "read_file", "memory_read"].includes(action.tool)) return true;
  const manifest = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!manifest) return false;
  const sideEffects = manifest.manifest.sideEffects || [];
  return !manifest.manifest.requiresExplicitAuthorization
    && !manifest.manifest.canExfiltrate
    && !manifest.manifest.acceptsSensitiveData
    && sideEffects.every((effect) => effect === "none" || effect === "file_read" || effect === "network_read");
}

function isExplicitWorkflowSideEffect(action: AgentSentryAction, state: PolicyState, assessment: ActionAssessment): boolean {
  if (assessment.sensitive || assessment.persistence || assessment.systemMutation || assessment.dangerousCommand) return false;
  if (!isApiLikeWorkflowTool(action)) return false;
  if (!hasTaskToolOverlap(state.currentTask || state.taskSpec.task, action)) return false;
  if (!numericArgumentsInsideWorkflowBudget(action.args)) return false;
  return true;
}

function isApiLikeWorkflowTool(action: AgentSentryAction): boolean {
  if (["call_api", "registered_effect_api", "registered_sensitive_read_api", "registered_privileged_api", "registered_persistent_api", "external_api_read"].includes(action.tool)) return true;
  const manifest = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  return Boolean(manifest?.manifest.sideEffects.some((effect) => effect === "network_read" || effect === "network_write"));
}

function hasTaskToolOverlap(task: string, action: AgentSentryAction): boolean {
  const taskTokens = new Set(semanticWorkflowTokens(task));
  if (!taskTokens.size) return false;
  const toolTokens = semanticWorkflowTokens(action.originalTool || action.tool);
  let overlap = 0;
  for (const token of toolTokens) {
    if (taskTokens.has(token)) overlap += 1;
    if (overlap >= 1 && token.length >= 5) return true;
    if (overlap >= 2) return true;
  }
  return false;
}

function semanticWorkflowTokens(value: string): string[] {
  const normalized = String(value || "")
    .normalize("NFKC")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase();
  const stop = new Set(["get", "set", "list", "search", "find", "check", "verify", "current", "conditions", "api", "tool", "data", "info", "the", "and", "for", "with", "from", "that", "this", "please"]);
  return normalized
    .split(/[^a-z0-9\u4e00-\u9fa5]+/u)
    .map((token) => token.trim())
    .filter((token) => token.length >= 3 && !stop.has(token))
    .slice(0, 48);
}

function numericArgumentsInsideWorkflowBudget(args: Record<string, unknown>): boolean {
  for (const [key, value] of Object.entries(args)) {
    const lowered = key.toLowerCase();
    const amountLike = /(amount|price|cost|charge|payment|usd|total|quantity|count|emissions)/i.test(lowered);
    if (!amountLike) continue;
    const numeric = typeof value === "number" ? value : typeof value === "string" ? Number(value.replace(/,/g, "")) : Number.NaN;
    if (!Number.isFinite(numeric)) continue;
    if (/(amount|price|cost|charge|payment|usd|total)/i.test(lowered) && numeric > 1000) return false;
    if (/(quantity|count)/i.test(lowered) && numeric > 100) return false;
    if (numeric < 0) return false;
  }
  return true;
}

function runtimeFeedbackFindingsFor(action: AgentSentryAction, state: PolicyState, config: PluginConfig): DetectionFinding[] {
  if (!config.runtimeIsolation.auditAfterExecution) return [];
  const profile = state.runtimeProfiles.get(action.tool) || state.runtimeProfiles.get(normalizeToolName(action.originalTool || action.tool));
  if (!profile || profile.runtime_alerts <= 0) return [];

  const assessment = assessAction(action, config);
  const sensitiveSink = assessment.highRisk || isTrustSensitiveSink(action, assessment);
  if (!sensitiveSink) return [];

  const critical = criticalRuntimeFeedback(profile);
  const score = Math.min(70, Math.max(25, critical ? profile.risk_score : Math.trunc(profile.risk_score / 2)));
  const verdict: "block" | "require_approval" = critical || profile.runtime_alerts >= 2 ? "block" : "require_approval";
  return [finding(
    "Evidence Feedback",
    "learned",
    verdict,
    critical
      ? "runtime feedback observed a critical kernel anomaly and blocks recurring high-risk tool use"
      : profile.runtime_alerts >= 2
        ? "runtime feedback observed repeated kernel anomalies and blocks recurring high-risk tool use"
        : "runtime feedback downgraded repeated high-risk tool use after a previous eBPF anomaly",
    score,
    {
      tool: action.tool,
      runtime_feedback: {
        alerts: profile.runtime_alerts,
        last_seen: profile.last_seen,
        reasons: profile.reasons.slice(-4),
        events: profile.events.slice(-4),
      },
    },
  )];
}

function criticalRuntimeFeedback(profile: RuntimeFeedbackProfile): boolean {
  const text = `${profile.reasons.join("\n")}\n${profile.events.join("\n")}`.toLowerCase();
  return /execution was observed after agentsentry blocked|unexpected process execution|unexpected sensitive file access/.test(text)
    && profile.risk_score >= 70;
}

function abacFindingsFor(action: AgentSentryAction, state: PolicyState): DetectionFinding[] {
  const assessment = assessActionWithSensitiveAssets(action, []);
  const decision = evaluateAbacDecision(action, assessment, state);
  if (decision.blockedFlow) rememberTaintFlow(state, decision.blockedFlow);
  return decision.findings;
}

function taskSpecBoundaryFindings(action: AgentSentryAction, state: PolicyState, config: PluginConfig): DetectionFinding[] {
  const taskSpec = state.taskSpec;
  const assessment = assessAction(action, config);
  if (!isTrustSensitiveSink(action, assessment)) return [];

  const family = taskSpec.task_family || "unknown";
  const mode = taskSpec.task_mode || "unknown";
  const confidence = Number.isFinite(taskSpec.task_confidence) ? (taskSpec.task_confidence || 0) : 0;
  const reasons: string[] = [];

  if (mode === "data_only" || mode === "chatter") {
    reasons.push(`task mode ${mode} does not grant side-effect authority`);
  }
  if ((family === "analysis" || family === "read_only") && confidence < 0.7) {
    reasons.push(`task family ${family} is not a stable side-effect boundary`);
  }
  if (family === "mixed" && confidence < 0.5) {
    reasons.push("mixed task spec has low confidence for side-effect approval");
  }
  if (taskSpec.capabilities.length > 4 && confidence < 0.8) {
    reasons.push("task spec contains several capability clauses and benefits from semantic review");
  }
  if (taskSpec.allowed_tools.some((tool) => ["send_email", "write_file", "call_api", "memory_write", "shell_exec"].includes(tool)) && confidence < 0.75) {
    reasons.push("task spec includes side-effect tools with uncertain scope");
  }
  if (!reasons.length) return [];

  const verdict: "block" | "require_approval" = mode === "data_only" || mode === "chatter" ? "require_approval" : "require_approval";
  return [finding(
    "Intent Authorization",
    "heuristic",
    verdict,
    reasons.join("；"),
    mode === "data_only" || mode === "chatter" ? 35 : 22,
    {
      tool: action.tool,
      task_mode: mode,
      task_family: family,
      task_confidence: confidence,
      task_spec: {
        allowed_tools: taskSpec.allowed_tools.slice(0, 8),
        denied_tools: taskSpec.denied_tools.slice(0, 8),
        forbidden_tools: taskSpec.forbidden_tools.slice(0, 8),
      },
    },
  )];
}

/**
 * Enforces the part of a signed tool contract that cannot be inferred from a
 * prompt: a private lookup about another person must name a subject and be
 * attached to an active user task. It deliberately produces approval rather
 * than denial. A legitimate investigation can continue after its scope is
 * made explicit; an unscoped dossier-building workflow cannot silently grow.
 */
function manifestPurposeBoundaryFindings(action: AgentSentryAction, state: PolicyState): DetectionFinding[] {
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!envelope) return [];
  const manifest = envelope.manifest;
  const privateData = manifest.dataClassification === "user_private" || manifest.dataClassification === "secret";
  const thirdPartyData = manifest.dataSubjects?.some((subject) => subject === "named_subject" || subject === "third_party");
  if (!privateData || !thirdPartyData || manifest.purposeBinding !== "task_bound") return [];

  const mode = state.taskSpec.task_mode || "unknown";
  if (!state.taskSpec.task.trim() || mode === "chatter" || mode === "data_only") {
    return [finding(
      "Intent Authorization",
      "deterministic",
      "require_approval",
      "私密第三方数据查询缺少可执行的用户任务范围，需要说明业务目的和数据主体",
      40,
      {
        tool: action.tool,
        tool_id: manifest.toolId,
        data_classification: manifest.dataClassification,
        data_subjects: manifest.dataSubjects,
        purpose_binding: manifest.purposeBinding,
        task_mode: mode,
      },
    )];
  }

  const targetFields = manifest.targetFields || [];
  if (!targetFields.length) {
    return [finding(
      "Tool Manifest",
      "deterministic",
      "require_approval",
      "私密第三方数据工具缺少主体绑定字段声明，无法验证本次查询对象是否属于当前任务",
      35,
      {
        tool: action.tool,
        tool_id: manifest.toolId,
        data_classification: manifest.dataClassification,
        data_subjects: manifest.dataSubjects,
        missing_contract_field: "targetFields",
      },
    )];
  }

  const subjectValues = targetFields.flatMap((field) => readValuesAtField(action.args[field]));
  if (subjectValues.length) return [];
  return [finding(
    "Intent Authorization",
    "deterministic",
    "require_approval",
    "私密第三方数据查询未提供工具契约声明的主体标识，需要确认查询对象",
    35,
    {
      tool: action.tool,
      tool_id: manifest.toolId,
      target_fields: targetFields,
      data_classification: manifest.dataClassification,
      data_subjects: manifest.dataSubjects,
    },
  )];
}

function ifcExecutionBoundaryFindings(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  state: PolicyState,
  authorization: CapabilityAuthorization,
  provenanceLinks: SemanticProvenanceLink[],
): DetectionFinding[] {
  const sink = sinkForAction(action, assessment);
  if (!sink || !isTrustSensitiveSink(action, assessment) || !provenanceLinks.length) return [];

  const consumedIds = provenanceLinks.map((link) => link.provenanceId).filter(Boolean);
  const consumedLineage = provenanceClosure(consumedIds, state.dataProvenance);
  if (!consumedLineage.size) return [];

  const branches = state.ifcBranches
    .filter((branch) => branch.status === "isolated")
    .filter((branch) => branch.provenanceIds.some((id) => consumedLineage.has(id)));
  if (!branches.length) return [];

  const strongest = [...branches].sort((left, right) =>
    confidentialityRank(right.confidentiality) - confidentialityRank(left.confidentiality)
    || right.risk - left.risk
    || right.confidence - left.confidence
  )[0];
  const severe = branches.some((branch) =>
    branch.confidentiality === "tenant-secret"
    || branch.risk >= 80
    || branch.integrity === "untrusted-external" && branch.risk >= 65
  );
  const strongAuthorization = hasStrongUserAuthorization(authorization);
  const verdict: "block" | "require_approval" = severe || !strongAuthorization ? "block" : "require_approval";
  const reason = verdict === "block"
    ? "IFC 执行边界阻断：高风险工具正在消费未清洗的低信任数据分支"
    : "IFC 执行边界要求审批：高风险工具消费了隔离分支数据，需要确认清洗结果和用途";

  return [finding(
    "IFC Execution Boundary",
    "deterministic",
    verdict,
    reason,
    verdict === "block" ? 100 : 70,
    {
      tool: action.tool,
      sink,
      authorization_reason: authorization.reason,
      authorized: authorization.authorized,
      consumed_provenance_ids: consumedIds.slice(0, 12),
      consumed_lineage_ids: Array.from(consumedLineage).slice(0, 16),
      strongest_branch: {
        id: strongest.id,
        source: strongest.source,
        integrity: strongest.integrity,
        confidentiality: strongest.confidentiality,
        purpose: strongest.purpose,
        risk: strongest.risk,
        confidence: strongest.confidence,
      },
      branches: branches.slice(0, 6).map((branch) => ({
        id: branch.id,
        source: branch.source,
        integrity: branch.integrity,
        confidentiality: branch.confidentiality,
        risk: branch.risk,
        confidence: branch.confidence,
      })),
    },
  )];
}

function hasStrongUserAuthorization(authorization: CapabilityAuthorization): boolean {
  const capability = authorization.capability;
  return Boolean(authorization.authorized
    && capability
    && capability.evidence.source === "user"
    && capability.evidence.explicitAuthorization
    && !capability.evidence.insideQuotation
    && !capability.evidence.negated
    && capability.evidence.targetIsConcrete
    && capability.evidence.confidence >= 0.82);
}

function provenanceClosure(ids: string[], provenance: DataProvenance[]): Set<string> {
  const byId = new Map(provenance.map((item) => [item.id, item]));
  const closure = new Set<string>();
  const pending = ids.filter(Boolean);
  while (pending.length && closure.size < 512) {
    const id = pending.pop()!;
    if (!id || closure.has(id)) continue;
    closure.add(id);
    const node = byId.get(id);
    if (node) pending.push(...node.parentIds);
  }
  return closure;
}

function persistentMemoryIFCFindings(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  state: PolicyState,
): DetectionFinding[] {
  if (!state.persistentMemoryLabels.length) return [];
  const key = memoryKeyForAction(action);
  if (!key) return [];
  const labels = state.persistentMemoryLabels.filter((label) => memoryKeysOverlap(label.key, key)).slice(-12);
  if (!labels.length) return [];
  const lowTrust = labels.filter((label) =>
    label.integrity === "untrusted-external"
    || label.confidentiality === "tenant-secret"
    || riskMax(label.risk_vector) >= 50
  );
  if (!lowTrust.length) return [];
  if (action.tool === "memory_read" || action.tool === "read_file") {
    return [finding(
      "Memory IFC",
      "deterministic",
      "require_approval",
      "跨会话记忆标签提示：读取的长期记忆包含低信任或高风险来源，读取后只能进入隔离分析分支",
      55,
      {
        key,
        labels: lowTrust.map(publicPersistentMemoryLabel),
      },
    )];
  }
  if (!isTrustSensitiveSink(action, assessment)) return [];
  return [finding(
    "Memory IFC",
    "deterministic",
    "block",
    "跨会话记忆标签阻断：低信任长期记忆不能直接授权高风险工具动作",
    100,
    {
      key,
      tool: action.tool,
      labels: lowTrust.map(publicPersistentMemoryLabel),
    },
  )];
}

function memoryKeyForAction(action: AgentSentryAction): string {
  if (action.tool !== "memory_read" && action.tool !== "memory_write" && action.tool !== "read_file" && action.tool !== "write_file") return "";
  const path = readFirstString(action.args, ["key", "name", "path", "file", "filename", "target"]);
  return path ? normalizeMemoryKey(path) : action.tool.startsWith("memory_") ? "memory" : "";
}

function memoryKeysOverlap(left: string, right: string): boolean {
  const a = normalizeMemoryKey(left).toLowerCase();
  const b = normalizeMemoryKey(right).toLowerCase();
  if (a === b) return true;
  const abase = a.split("/").pop();
  const bbase = b.split("/").pop();
  return Boolean(abase && bbase && abase === bbase);
}

function taintRisk(action: AgentSentryAction, state: PolicyState, config: PluginConfig): number {
  let risk = 0;
  const assessment = assessPolicyAction(action, config);
  const argsText = safeStringify(action.args).toLowerCase();
  const blockedTaint = config.policy.taintFeedback ? taintFlowForAction(action, assessment, state) : null;
  if (!isManifestBoundReadRequestForAction(action) && action.tool !== "memory_write" && config.policy.sensitiveAssets.some((asset) => asset && argsText.includes(asset.toLowerCase()))) risk += 45;
  if (blockedTaint) risk += Math.min(45, Math.max(20, Math.trunc(blockedTaint.confidence / 2)));
  return Math.min(risk, 80);
}

function isManifestBoundReadRequestForAction(action: AgentSentryAction): boolean {
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  return Boolean(envelope && isManifestBoundReadRequest(action, envelope.manifest));
}

function provenanceRiskForAction(action: AgentSentryAction, state: PolicyState): Record<string, unknown> | null {
  if (!state.provenanceFindings.length) return null;
  const argsText = normalizeExposureText(safeStringify(action.args));
  if (!argsText) return null;
  const matched = state.provenanceFindings.filter((item) => {
    const evidence = (item.evidence || {}) as Record<string, unknown>;
    const rawPath = String(evidence.path || evidence.file || "").replace(/\\/g, "/").toLowerCase();
    if (!rawPath || item.verdict !== "block") return false;
    const base = rawPath.split("/").filter(Boolean).pop() || rawPath;
    return (rawPath.length >= 6 && argsText.includes(rawPath))
      || (base.length >= 6 && argsText.includes(base));
  });
  if (!matched.length) return null;
  return {
    matched_paths: matched.map((item) => String(((item.evidence || {}) as Record<string, unknown>).path || ((item.evidence || {}) as Record<string, unknown>).file || "")).slice(0, 5),
    blocked_findings: matched.map((item) => item.reason).slice(0, 5),
  };
}

function taintFlowForAction(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  state: PolicyState,
): PolicyState["taintFlows"][number] | null {
  const flow = evaluateAbacDecision(action, assessment, state).blockedFlow;
  if (!flow) return null;
  rememberTaintFlow(state, flow);
  return flow;
}

function evaluateAbacDecision(
  action: AgentSentryAction,
  assessment: ActionAssessment,
  state: PolicyState,
) {
  return evaluateAbacDataFlow({
    action,
    assessment,
    sink: sinkForAction(action, assessment),
    labels: trustLabelsForAction(action, state),
    isolatedBranches: state.ifcBranches,
    taskSpec: state.taskSpec,
    aggregateRisk: state.aggregateRisk,
    taintedSources: state.taintedSources,
  });
}

function trustLabelsForAction(action: AgentSentryAction, state: PolicyState): TrustLabel[] {
  const labels: TrustLabel[] = [];
  collectActionTrustLabels(action.args, labels);
  const argsText = flattenText(action.args);
  const matched = matchExposure(argsText, state.exposures);
  if (matched?.exposure.label.trust_label) {
    const evidence = provenanceEvidenceForMatch(matched.mode);
    if (evidence.basis !== "conservative" && evidence.confidence >= 0.95) {
      labels.push(matched.exposure.label.trust_label);
    }
  }
  return labels;
}

function collectActionTrustLabels(value: unknown, labels: TrustLabel[], visited = new WeakSet<object>(), depth = 0): void {
  if (depth > 64) return;
  if (value && typeof value === "object") {
    if (visited.has(value)) return;
    visited.add(value);
  }
  if (isLabeledValue(value)) {
    if (value.label.trust_label) labels.push(value.label.trust_label);
    collectActionTrustLabels(value.value, labels, visited, depth + 1);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => collectActionTrustLabels(item, labels, visited, depth + 1));
    return;
  }
  if (!value || typeof value !== "object") return;
  try {
    Object.values(value as Record<string, unknown>).forEach((item) => collectActionTrustLabels(item, labels, visited, depth + 1));
  } catch {
    // Malformed action values are rejected by normalizePolicyAction before this traversal.
  }
}

function rememberTaintFlow(state: PolicyState, flow: PolicyState["taintFlows"][number]): void {
  const key = `${flow.label_id}:${flow.sink}:${flow.blocked}`;
  if (!state.taintFlows.some((item) => `${item.label_id}:${item.sink}:${item.blocked}` === key)) {
    state.taintFlows.push(flow);
  }
  if (state.taintFlows.length > 80) state.taintFlows = state.taintFlows.slice(-80);
}

function manifestAllowsImplicitRead(action: AgentSentryAction, taskSpec: TaskSpec): boolean {
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!envelope) return false;
  const manifest = envelope.manifest;
  const readOnly = manifest.sideEffects.every((effect) => effect === "none" || effect === "file_read" || effect === "network_read");
  if (!readOnly || manifest.canExfiltrate) return false;
  const targetInScope = manifestTargetIsInsideTaskScope(action, manifest, taskSpec);
  const publicReadWithoutConcreteTarget = manifest.dataClassification === "public"
    && manifest.accessScope === "explicit_target"
    && manifest.sensitiveInputHandling === "none"
    && Boolean(taskSpec.task?.trim())
    && !taskSpec.denied_tools.includes(action.tool);
  // A user request such as "verify this article" can authorize a public
  // lookup without naming the provider's exact endpoint. The response is
  // still an untrusted ingress and cannot authorize a later sink.
  if (!targetInScope && !publicReadWithoutConcreteTarget) return false;
  if (targetInScope) return true;
  if (!manifest.requiresExplicitAuthorization) return true;

  // An onboarded non-secret read produces data for the current task and has
  // no execution, persistence or egress capability. Its result remains
  // labeled and is checked again before any later sink. This prevents a
  // missing natural-language tool name from turning ordinary research or
  // account inspection into repeated approval prompts.
  if (manifest.dataClassification === "public"
    && manifest.sensitiveInputHandling !== "business_payload"
    && ["caller_bound", "explicit_target", "unscoped"].includes(manifest.accessScope || "unknown")) {
    return true;
  }

  // A caller-bound query can use an authentication credential to retrieve the
  // current caller's own data. It cannot name another subject, carry a
  // business payload, write state, or send data away. The contract is signed
  // at onboarding and therefore does not rely on the tool name.
  return manifest.accessScope === "caller_bound"
    && manifest.sensitiveInputHandling === "authentication_only"
    && !manifest.canExfiltrate
    && readOnly
    && isManifestBoundReadRequest(action, manifest);
}

function manifestTargetIsInsideTaskScope(action: AgentSentryAction, manifest: ToolSecurityManifest, taskSpec: TaskSpec): boolean {
  const targetFields = manifest.targetFields || [];
  if (!targetFields.length) return true;
  const values = targetFields.flatMap((field) => readValuesAtField(action.args[field]));
  const networkTargets = values.filter((value) => /^https?:\/\//i.test(value));
  if (!networkTargets.length) return true;
  return networkTargets.every((target) => targetAllowed(target, taskSpec.allowed_targets));
}

function assessPolicyAction(action: AgentSentryAction, config: PluginConfig): ActionAssessment {
  const assessment = assessAction(action, config);
  const envelope = resolveToolManifest(action.originalTool) || resolveToolManifest(action.tool);
  if (!envelope || !isManifestBoundReadRequest(action, envelope.manifest)) return assessment;

  // Authentication material passed only to the verified provider must not be
  // treated as an attempted exfiltration. Payload, write, execution and
  // cross-subject fields fail isManifestBoundReadRequest and retain the
  // regular high-risk assessment.
  return {
    ...assessment,
    highRisk: assessment.persistence || assessment.systemMutation || assessment.dangerousCommand,
    sensitive: false,
    reasons: assessment.reasons.filter((reason) => reason !== "arguments reference sensitive asset"),
  };
}

function isManifestBoundReadRequest(action: AgentSentryAction, manifest: ToolSecurityManifest): boolean {
  if (manifest.accessScope !== "caller_bound" || manifest.sensitiveInputHandling !== "authentication_only") return false;
  if (manifest.canExfiltrate || manifest.sideEffects.some((effect) => !["none", "file_read", "network_read"].includes(effect))) return false;
  const credentials = new Set((manifest.credentialFields || []).map((field) => field.toLowerCase()));
  const targets = new Set((manifest.targetFields || []).map((field) => field.toLowerCase()));
  if (!credentials.size) return false;
  const keys = Object.keys(action.args).filter((key) => !key.startsWith("__"));
  if (!keys.length || !keys.some((key) => credentials.has(key.toLowerCase()))) return false;
  return keys.every((key) => credentials.has(key.toLowerCase()) || targets.has(key.toLowerCase()));
}

function readStringValues(args: Record<string, unknown>, keys: string[]): string[] {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) return [value.trim()];
    if (Array.isArray(value)) {
      const values = value.map((item) => flattenValueText(item).trim()).filter(Boolean);
      if (values.length) return values;
    }
    if (isLabeledValue(value)) {
      const text = flattenValueText(value.value).trim();
      if (text) return [text];
    }
  }
  return [];
}

function heuristicScore(findings: DetectionFinding[]): number {
  return Math.min(
    findings
      .filter((finding) => finding.finding_type !== "deterministic" && finding.verdict !== "pass")
      .reduce((total, finding) => total + finding.score, 0),
    100,
  );
}

function baseToolRisk(tool: string): number {
  return {
    read_file: 18,
    write_file: 22,
    send_email: 25,
    call_api: 20,
    memory_write: 25,
    memory_read: 10,
    read_webpage: 10,
    shell_exec: 25,
  }[tool] ?? 20;
}

function compactEvidenceList(values: string[], limit: number): string[] {
  if (values.length <= limit) return [...values];
  const head = Math.ceil(limit / 2);
  const tail = Math.floor(limit / 2);
  return [...values.slice(0, head), ...values.slice(-tail)];
}

function dedupeFindings(findings: DetectionFinding[]): DetectionFinding[] {
  const seen = new Set<string>();
  const out: DetectionFinding[] = [];
  for (const item of findings) {
    const key = `${item.layer}:${item.finding_type}:${item.verdict}:${item.reason}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}
