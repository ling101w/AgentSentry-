#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createInterface } from "node:readline";

import { PluginConfig, applySecurityProfile, isSecurityProfileName } from "../dist/config.js";
import { detectToolCall } from "../dist/core/detect.js";
import {
  createPolicyState,
  policyTrustSnapshot,
  resultFindings,
  updateAfterDecision,
  updateAfterMessage,
  updateTaskSpec,
} from "../dist/core/policy.js";
import { semanticJudgeAmbiguousAction } from "../dist/core/semantic.js";
import { clearCustomToolManifests, registerToolManifest } from "../dist/core/tool-manifest.js";

const BRIDGE_VERSION = "1.1.0-static-trajectory";
const MAX_SESSIONS = 64;
const MAX_LINE_CHARS = 4 * 1024 * 1024;
const DETECTOR_FIELDS = ["session_history", "tool_args", "tool_name", "tool_result", "user_message"];

const profile = process.env.AGENTSENTRY_NATIVE_PROFILE || "competition";
if (!isSecurityProfileName(profile)) throw new Error(`unsupported AgentSentry native profile: ${profile}`);

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
  if (op === "end") return { ended: sessions.delete(sessionId) };

  const payload = validateDetectorPayload(request.payload);
  if (op === "start") {
    if (sessions.has(sessionId)) throw new Error("session already exists");
    clearCustomToolManifests();
    const catalogDigest = registerCatalog(request.tool_catalog);
    const config = applySecurityProfile(new PluginConfig(), profile);
    if (process.env.AGENTSENTRY_NATIVE_DISABLE_JUDGE === "1") config.semantic.enabled = false;
    const state = createPolicyState();
    updateTaskSpec(state, [{ role: "user", content: payload.user_message }], config);
    sessions.set(sessionId, { config, state, userMessage: payload.user_message, pending: new Map(), catalogDigest, mode: request.mode || "enforce_sim" });
    trimSessions();
    return { started: true, catalog_sha256: catalogDigest, task_spec_version: state.taskSpec.version, ...bridgeMetadata() };
  }

  const session = sessions.get(sessionId);
  if (!session) throw new Error("unknown session");

  if (op === "observe_user") {
    session.userMessage = payload.user_message;
    updateTaskSpec(session.state, [{ role: "user", content: payload.user_message }], session.config);
    return { observed: true, trust: policyTrustSnapshot(session.state) };
  }

  const callId = requiredText(request.call_id, "call_id");
  if (op === "before_tool") return beforeTool(session, callId, payload);
  if (op === "after_tool") return afterTool(session, callId, payload);
  throw new Error(`unsupported operation: ${op}`);
}

async function beforeTool(session, callId, payload) {
  if (payload.tool_result !== null) throw new Error("before_tool requires a null tool_result");
  if (session.pending.has(callId)) throw new Error("duplicate call_id");

  const toolArgs = bridgeToolArgs(payload.tool_name, payload.tool_args);
  const preliminary = detectToolCall(payload.tool_name, toolArgs, session.config, session.state);
  const semanticFindings = await semanticJudgeAmbiguousAction({
    action: preliminary.policy.action,
    taskSpec: preliminary.policy.task_spec,
    policyState: session.state,
    preliminary: preliminary.policy,
  }, session.config);
  const detection = semanticFindings.length
    ? detectToolCall(payload.tool_name, toolArgs, session.config, session.state, semanticFindings)
    : preliminary;
  const semanticJudgeCalled = preliminary.policy.deterministic_disposition === "ambiguous" && semanticFindings.length > 0;
  updateAfterDecision(session.state, detection.policy);
  if (detection.decision === "allow" || session.mode === "shadow") {
    session.pending.set(callId, { tool: payload.tool_name, args: toolArgs });
  }

  return {
    decision: detection.decision,
    risk_score: detection.risk_score,
    deterministic_block: detection.policy.deterministic_block,
    normalized_tool: detection.policy.action.tool,
    summary: detection.summary,
    findings: detection.findings,
    semantic_judge_requested: preliminary.policy.deterministic_disposition === "ambiguous",
    semantic_judge_called: semanticJudgeCalled,
    semantic_gate: { disposition: preliminary.policy.deterministic_disposition },
    contaminated: session.state.contaminated,
    trust: policyTrustSnapshot(session.state),
  };
}

function afterTool(session, callId, payload) {
  const pending = session.pending.get(callId);
  if (!pending) throw new Error("after_tool has no matching allowed call");
  if (payload.tool_name !== pending.tool) throw new Error("after_tool tool_name differs from before_tool");
  session.pending.delete(callId);
  const findings = resultFindings(callId, payload.tool_result, session.state, session.config, payload.tool_name);
  updateAfterMessage(session.state, findings);
  return {
    findings,
    contaminated: session.state.contaminated,
    trust: policyTrustSnapshot(session.state),
  };
}

function registerCatalog(catalog) {
  const rows = Array.isArray(catalog) ? catalog : [];
  for (const [index, raw] of rows.entries()) {
    if (!raw || typeof raw !== "object" || typeof raw.name !== "string" || !raw.name.trim()) continue;
    const manifest = inferManifest(raw.name.trim(), typeof raw.description === "string" ? raw.description : "");
    registerToolManifest(manifest, {
      schema: raw.parameters || {},
      version: "atbench-static",
      endpoint: `atbench://tool/${index}`,
    });
  }
  return canonicalSha256(rows);
}

function inferManifest(name, description) {
  const text = `${name}\n${description}`.toLowerCase();
  const writes = /(send|post|publish|create|update|delete|trip|disable|trigger|transfer|message|email|comment|rank|score|submit|execute|run)/i.test(text);
  const reads = /(get|search|lookup|fetch|read|list|find|query|retrieve|check|verify|analy[sz]e)/i.test(text);
  const sensitive = /(auth|token|secret|password|credential|login|phone|email|ssn|medical|private|location|ip|risk|identity)/i.test(text);
  return {
    toolId: name,
    aliases: [],
    dataOrigins: ["third_party_api"],
    sideEffects: writes ? ["network_write"] : reads ? ["network_read"] : ["none"],
    acceptsSensitiveData: sensitive,
    canExfiltrate: writes || sensitive,
    requiresExplicitAuthorization: writes || sensitive,
    defaultTrust: "external",
  };
}

function bridgeToolArgs(toolName, args) {
  const output = { ...(args || {}) };
  if (!("url" in output) && !("endpoint" in output)) output.endpoint = `atbench://tool/${toolName}`;
  return output;
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
  return {
    bridge_version: BRIDGE_VERSION,
    profile,
    detector_input_fields: DETECTOR_FIELDS,
  };
}

function requiredText(value, name) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} must be a non-empty string`);
  return value.trim();
}

function trimSessions() {
  while (sessions.size > MAX_SESSIONS) {
    const oldest = sessions.keys().next().value;
    if (!oldest) break;
    sessions.delete(oldest);
  }
}

function canonicalSha256(value) {
  return createHash("sha256").update(stableStringify(value), "utf8").digest("hex");
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

function writeResponse(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}
