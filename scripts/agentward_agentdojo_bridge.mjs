#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import path from "node:path";

const BRIDGE_VERSION = "1.0.0";
const MAX_SESSIONS = 64;
const MAX_LINE_CHARS = 4 * 1024 * 1024;
const DETECTOR_FIELDS = ["session_history", "tool_args", "tool_name", "tool_result", "user_message"];
const agentWardRoot = path.resolve(process.env.AGENTWARD_ROOT || "/root/.openclaw/extensions/agent-ward");
const agentWardSourceRoot = path.resolve(process.env.AGENTWARD_SOURCE_ROOT || "/root/AgentWard");

const packagePath = path.join(agentWardRoot, "package.json");
const packageDocument = JSON.parse(readFileSync(packagePath, "utf8"));
const modulePaths = {
  inputSanitization: path.join(agentWardRoot, "dist/layers/input-sanitization.js"),
  execControl: path.join(agentWardRoot, "dist/layers/exec-control.js"),
  cognitionProtection: path.join(agentWardRoot, "dist/layers/cognition-protection.js"),
  decisionAlignment: path.join(agentWardRoot, "dist/layers/decision-alignment.js"),
  workerManager: path.join(agentWardRoot, "dist/worker/model-worker-manager.js"),
  logger: path.join(agentWardRoot, "dist/util/logger.js"),
};
const [
  { inputDetect },
  { toolCallDetect },
  { detectCognitionProtectionAnomaly },
  { decisionAlignmentDetect },
  { PersistentWorker, getWorker, setWorker },
  { initLogger },
] =
  await Promise.all([
    import(pathToFileURL(modulePaths.inputSanitization)),
    import(pathToFileURL(modulePaths.execControl)),
    import(pathToFileURL(modulePaths.cognitionProtection)),
    import(pathToFileURL(modulePaths.decisionAlignment)),
    import(pathToFileURL(modulePaths.workerManager)),
    import(pathToFileURL(modulePaths.logger)),
  ]);

// AgentWard detectors log on a match. Keep stdout reserved for the JSONL protocol.
initLogger({ logger: { info() {}, warn() {}, error() {} } });

const sessions = new Map();
const reader = createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });

for await (const line of reader) {
  if (!line.trim()) continue;
  let id = null;
  try {
    if (line.length > MAX_LINE_CHARS) throw new Error("bridge request exceeds maximum line size");
    const request = JSON.parse(line);
    id = request && typeof request === "object" ? request.id ?? null : null;
    const result = await handleRequest(request);
    writeResponse({ id, ok: true, result });
  } catch (error) {
    writeResponse({
      id,
      ok: false,
      error: {
        code: "bridge_request_failed",
        message: error instanceof Error ? error.message.slice(0, 500) : "unknown bridge failure",
      },
    });
  }
}

async function handleRequest(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) throw new Error("request must be an object");
  const op = requiredText(request.op, "op");
  if (op === "ping") return bridgeMetadata();

  const sessionId = requiredText(request.session_id, "session_id");
  if (!/^trial_[a-f0-9]{24,64}$/i.test(sessionId)) throw new Error("session_id must be an opaque trial id");
  if (op === "end") {
    const ended = sessions.delete(sessionId);
    if (sessions.size === 0) shutdownWorker();
    return { ended };
  }

  const payload = validateDetectorPayload(request.payload);
  if (op === "start") {
    if (sessions.has(sessionId)) throw new Error("session already exists");
    const judge = semanticJudgeConfig();
    if (judge.enabled) await ensureWorkerReady(judge.timeoutMs);
    sessions.set(sessionId, {
      userMessage: payload.user_message,
      pending: new Map(),
      queuedInputWarnings: [],
      decisionWarning: null,
      lastSemanticResult: null,
      judgeState: createJudgeState(payload.user_message),
    });
    trimSessions();
    return { started: true, ...bridgeMetadata() };
  }

  const session = sessions.get(sessionId);
  if (!session) throw new Error("unknown session");
  if (payload.user_message !== session.userMessage) throw new Error("user_message cannot change within a trial");
  const callId = requiredText(request.call_id, "call_id");
  if (op === "assistant_tool_use") return assistantToolUse(session, callId, payload);
  if (op === "before_tool") return beforeTool(session, callId, payload);
  if (op === "after_tool") return afterTool(session, callId, payload);
  throw new Error(`unsupported operation: ${op}`);
}

function beforeTool(session, callId, payload) {
  if (payload.tool_result !== null) throw new Error("before_tool requires a null tool_result");
  if (session.pending.has(callId)) throw new Error("duplicate call_id");

  if (session.decisionWarning) {
    return decision("deny", "decision_alignment", [session.decisionWarning], {
      summary: "AgentWard Decision Alignment blocked this assistant tool-use turn.",
      ...semanticFields(session),
    });
  }

  // AgentWard consumes queued tool-result warnings at the next before_tool_call hook.
  if (session.queuedInputWarnings.length > 0) {
    const warnings = session.queuedInputWarnings.splice(0);
    return decision("deny", "input_sanitization", warnings, {
      summary: "AgentWard blocked the next tool call after detecting prompt injection in a tool result.",
    });
  }

  const execResult = toolCallDetect(payload.tool_name, payload.tool_args);
  if (execResult?.warning) {
    const verdict = execResult.verdict === "requireApproval" ? "ask" : execResult.verdict === "block" ? "deny" : "allow";
    if (verdict !== "allow") {
      return decision(verdict, "exec_control", [warningObject(execResult.warning)], semanticFields(session));
    }
  }

  const cognitionWarning = detectCognitionProtectionAnomaly(payload.tool_name, payload.tool_args);
  if (cognitionWarning) {
    return decision("deny", "cognition_protection", [warningObject(cognitionWarning)], semanticFields(session));
  }

  session.pending.set(callId, payload.tool_name);
  return decision("allow", "none", [], {
    summary: "No covered AgentWard detector blocked this tool call.",
    ...semanticFields(session),
  });
}

function afterTool(session, callId, payload) {
  const expectedTool = session.pending.get(callId);
  if (!expectedTool) throw new Error("after_tool has no matching allowed call");
  if (payload.tool_name !== expectedTool) throw new Error("after_tool tool_name differs from before_tool");
  session.pending.delete(callId);

  const warning = inputDetect(payload.tool_result);
  const findings = warning ? [warningObject(warning)] : [];
  if (warning) session.queuedInputWarnings.push(...findings);
  session.judgeState.currentMessages.push({
    role: "toolResult",
    toolCallId: callId,
    toolName: payload.tool_name,
    isError: false,
    content: [{ type: "text", text: stableText(payload.tool_result) }],
  });
  return {
    findings,
    input_sanitization_detected: Boolean(warning),
    queued_intervention_count: session.queuedInputWarnings.length,
  };
}

function assistantToolUse(session, callId, payload) {
  if (payload.tool_result !== null) throw new Error("assistant_tool_use requires a null tool_result");
  const assistantMessage = extractAssistantMessage(payload.session_history);
  const toolCalls = Array.isArray(assistantMessage.content)
    ? assistantMessage.content.filter((item) => item && typeof item === "object" && item.type === "toolCall")
    : [];
  if (toolCalls.length === 0) throw new Error("assistant_tool_use requires at least one toolCall content block");

  // OpenClaw clears the previous temporary decision block when the next
  // assistant message is persisted, then evaluates the new tool-use turn.
  session.decisionWarning = null;
  const judge = semanticJudgeConfig();
  const beforeInfo = session.judgeState.decisionAlignmentInfo.length;
  let warning = null;
  let attempts = 0;
  if (judge.enabled) {
    ensureWorker(judge.timeoutMs);
    do {
      attempts += 1;
      warning = decisionAlignmentDetect(session.judgeState, assistantMessage);
    } while (!warning && session.judgeState.decisionAlignmentInfo.length === beforeInfo && attempts <= judge.maxRetries);
  }
  const called = session.judgeState.decisionAlignmentInfo.length > beforeInfo;
  if (warning) session.decisionWarning = warningObject(warning);
  session.lastSemanticResult = {
    requested: judge.enabled,
    called,
    verdict: warning ? "blocked" : called ? "ok" : "unavailable",
  };
  session.judgeState.currentMessages.push(assistantMessage);

  return {
    decision: warning ? "deny" : "allow",
    policy_decision: warning ? "deny" : "allow",
    enforcement_mode: "approval",
    layer: "decision_alignment",
    warnings: warning ? [warningObject(warning)] : [],
    semantic_judge_requested: judge.enabled,
    semantic_judge_called: called,
    semantic_judge_verdict: warning ? "blocked" : called ? "ok" : "unavailable",
    semantic_judge_attempts: attempts,
    assistant_call_id: callId,
    tool_call_count: toolCalls.length,
    summary: warning
      ? "AgentWard Decision Alignment found clear user-intent misalignment."
      : called
        ? "AgentWard Decision Alignment allowed the assistant tool-use turn."
        : "AgentWard Decision Alignment was unavailable; upstream behavior is fail-open.",
  };
}

function semanticFields(session) {
  const result = session.lastSemanticResult;
  return result
    ? {
        semantic_judge_requested: result.requested,
        semantic_judge_called: result.called,
        semantic_judge_verdict: result.verdict,
        semantic_judge_observation_only: true,
      }
    : {};
}

function decision(value, layer, warnings, extra = {}) {
  return {
    decision: value,
    policy_decision: value,
    enforcement_mode: "approval",
    layer,
    warnings,
    semantic_judge_requested: false,
    semantic_judge_called: false,
    ...extra,
  };
}

function warningObject(warning) {
  return {
    type: String(warning?.type || "AgentWard warning"),
    description: String(warning?.description || ""),
    details: String(warning?.details || ""),
  };
}

function validateDetectorPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("payload must be an object");
  const fields = Object.keys(payload).sort();
  if (fields.length !== DETECTOR_FIELDS.length || fields.some((field, index) => field !== DETECTOR_FIELDS[index])) {
    throw new Error(`detector payload must contain exactly: ${DETECTOR_FIELDS.join(", ")}`);
  }
  if (typeof payload.user_message !== "string") throw new Error("user_message must be a string");
  if (typeof payload.tool_name !== "string") throw new Error("tool_name must be a string");
  if (!payload.tool_args || typeof payload.tool_args !== "object" || Array.isArray(payload.tool_args)) {
    throw new Error("tool_args must be an object");
  }
  if (!Array.isArray(payload.session_history) || payload.session_history.some((item) => !item || typeof item !== "object" || Array.isArray(item))) {
    throw new Error("session_history must be an array of objects");
  }
  return payload;
}

function bridgeMetadata() {
  const judge = semanticJudgeConfig();
  return {
    bridge_version: BRIDGE_VERSION,
    plugin_id: "agent-ward",
    plugin_version: String(packageDocument.version || "unknown"),
    profile: "agentward-default",
    enforcement_mode: "approval",
    detector_input_fields: DETECTOR_FIELDS,
    upstream_commit: gitCommit(agentWardSourceRoot),
    plugin_dist_sha256: moduleTreeSha256(modulePaths),
    semantic_judge: {
      enabled: judge.enabled,
      provider: judge.provider,
      model: judge.model,
      api: judge.api,
      base_url: judge.baseUrl,
      timeout_ms: judge.timeoutMs,
      max_tokens: judge.maxTokens,
      max_retries: judge.maxRetries,
    },
    hook_coverage: {
      input_sanitization_tool_results: "enforced",
      execution_control_before_tool: "enforced",
      cognition_protection_before_tool: "enforced",
      decision_alignment_assistant_message: judge.enabled ? "enforced" : "disabled_missing_judge_configuration",
      foundation_scan_openclaw_workspace: "not_applicable_to_agentdojo_suite",
    },
  };
}

function createJudgeState(userMessage) {
  const judge = semanticJudgeConfig();
  return {
    historyMessages: [{ role: "user", content: [{ type: "text", text: userMessage }] }],
    currentMessages: [],
    decisionAlignmentInfo: [],
    llmContext: judge.enabled
      ? {
          model: {
            id: judge.model,
            name: judge.model,
            provider: judge.provider,
            api: judge.api,
            baseUrl: judge.baseUrl,
            reasoning: false,
            input: ["text"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 128000,
            maxTokens: 4096,
            compat: {
              supportsStore: false,
              supportsDeveloperRole: false,
              supportsReasoningEffort: false,
              supportsUsageInStreaming: true,
              maxTokensField: "max_tokens",
            },
          },
          options: { apiKey: judge.apiKey, maxTokens: judge.maxTokens },
          apiKey: judge.apiKey,
          modelRef: `${judge.provider}/${judge.model}`,
        }
      : undefined,
  };
}

function semanticJudgeConfig() {
  const provider = String(process.env.AGENTWARD_JUDGE_PROVIDER || "agentward-compatible").trim();
  const model = String(process.env.AGENTWARD_JUDGE_MODEL || "").trim();
  const api = String(process.env.AGENTWARD_JUDGE_API || "openai-completions").trim();
  const baseUrl = String(process.env.AGENTWARD_JUDGE_BASE_URL || "").trim().replace(/\/+$/, "");
  const apiKey = String(process.env.AGENT_WARD_API_KEY || "").trim();
  const timeoutMs = Number(process.env.AGENTWARD_JUDGE_TIMEOUT_MS || 120000);
  const maxTokens = Number(process.env.AGENTWARD_JUDGE_MAX_TOKENS || 2048);
  const maxRetries = Number(process.env.AGENTWARD_JUDGE_MAX_RETRIES || 2);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 600000) {
    throw new Error("AGENTWARD_JUDGE_TIMEOUT_MS must be an integer from 500 to 600000");
  }
  if (!Number.isInteger(maxTokens) || maxTokens < 256 || maxTokens > 8192) {
    throw new Error("AGENTWARD_JUDGE_MAX_TOKENS must be an integer from 256 to 8192");
  }
  if (!Number.isInteger(maxRetries) || maxRetries < 0 || maxRetries > 4) {
    throw new Error("AGENTWARD_JUDGE_MAX_RETRIES must be an integer from 0 to 4");
  }
  return {
    enabled: Boolean(provider && model && api && baseUrl && apiKey),
    provider,
    model,
    api,
    baseUrl,
    apiKey,
    timeoutMs,
    maxTokens,
    maxRetries,
  };
}

function ensureWorker(timeoutMs) {
  const existing = getWorker();
  if (existing?.isRunning()) return existing;
  const worker = new PersistentWorker({
    tmpDir: tmpdir(),
    config: { timeout: timeoutMs, debug: false, logLevel: "error" },
  });
  setWorker(worker);
  return worker;
}

async function ensureWorkerReady(timeoutMs) {
  const existing = getWorker();
  if (existing?.isRunning()) return;
  const worker = ensureWorker(timeoutMs);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("AgentWard worker did not become ready within 5s")), 5000);
    const onMessage = (message) => {
      if (message?.type === "log" && message.message === "[Worker] Started") finish();
    };
    const onError = (error) => finish(error);
    const onExit = (code) => finish(new Error(`AgentWard worker exited during startup (${code})`));
    const finish = (error) => {
      clearTimeout(timer);
      worker.worker.off("message", onMessage);
      worker.worker.off("error", onError);
      worker.worker.off("exit", onExit);
      error ? reject(error) : resolve();
    };
    worker.worker.on("message", onMessage);
    worker.worker.once("error", onError);
    worker.worker.once("exit", onExit);
  });
}

function shutdownWorker() {
  const worker = getWorker();
  if (!worker) return;
  try { worker.shutdown(); } catch {}
  setWorker(null);
}

function extractAssistantMessage(history) {
  if (!Array.isArray(history) || history.length === 0) throw new Error("assistant event is missing from session_history");
  const last = history.at(-1);
  const message = last?.message;
  if (!message || typeof message !== "object" || message.role !== "assistant") {
    throw new Error("last session_history item must contain an assistant message");
  }
  return message;
}

function stableText(value) {
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function moduleTreeSha256(paths) {
  const hash = createHash("sha256");
  for (const [name, filePath] of Object.entries(paths).sort(([a], [b]) => a.localeCompare(b))) {
    hash.update(name);
    hash.update("\0");
    hash.update(readFileSync(filePath));
    hash.update("\0");
  }
  return hash.digest("hex");
}

function gitCommit(root) {
  try {
    return execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8", timeout: 3000 }).trim();
  } catch {
    return null;
  }
}

function requiredText(value, field) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${field} must be a non-empty string`);
  return value;
}

function trimSessions() {
  while (sessions.size > MAX_SESSIONS) sessions.delete(sessions.keys().next().value);
}

function writeResponse(response) {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}
