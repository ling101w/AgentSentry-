import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { AgentIdentityConfig, AgentIdentityLevel, PluginConfig } from "../config.ts";
import { loadOrCreateStateSecret } from "./state-secret.ts";
import type { DetectionFinding } from "./detect.ts";
import type { AgentSentryAction } from "./policy.ts";
import { analyzeTrustContent, finding, riskMax } from "./trust.ts";

export type AgentIdentity = AgentIdentityConfig & {
  score: number;
};

export type AgentMessageEnvelope = {
  version: 1;
  issuer: string;
  from: string;
  to: string;
  tenant: string;
  sourceNamespace: string;
  targetNamespace: string;
  contentSha256: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
};

const LEVEL_SCORE: Record<AgentIdentityLevel, number> = {
  owner: 100,
  trusted_agent: 80,
  delegated_agent: 55,
  external_agent: 20,
};

let signingSecret: Buffer<ArrayBufferLike> = Buffer.from(process.env.AGENTSENTRY_AGENT_MESSAGE_SECRET || "agentsentry-agent-message-development-key", "utf8");

export function configureAgentTrust(config: PluginConfig): void {
  signingSecret = loadOrCreateStateSecret(config, "agent-message");
}

export function agentTrustCatalog(config?: PluginConfig): AgentIdentity[] {
  const identities = config?.multiAgentSecurity.agents || [];
  return identities.map(toIdentity).sort((left, right) => left.id.localeCompare(right.id));
}

export function classifyAgentIdentity(raw: unknown, config?: PluginConfig): AgentIdentity {
  const id = typeof raw === "string" ? raw.trim() : "";
  const candidate = agentTrustCatalog(config).find((item) => item.id === id);
  if (candidate) return candidate;
  return {
    id: id || "agent:external",
    label: id ? "未登记 Agent" : "缺失 Agent 身份",
    level: "external_agent",
    tenant: "external",
    namespace: "untrusted",
    score: LEVEL_SCORE.external_agent,
    mayDelegate: false,
    mayAuthorizeSensitiveTools: false,
    mayReceiveUntrustedData: true,
  };
}

/**
 * Seals an outbound multi-Agent message immediately before the OpenClaw tool
 * call. The envelope binds sender, recipient, tenant, namespaces, expiry and
 * content. A recipient cannot reuse a message under another identity or alter
 * its content without invalidating the signature.
 */
export function sealAgentMessageParameters(params: Record<string, unknown>, config: PluginConfig, now = Date.now()): Record<string, unknown> {
  if (!config.multiAgentSecurity.enabled) return params;
  const from = firstString(params, ["from", "source", "sender", "agent"]) || "agent:main";
  const to = firstString(params, ["to", "target", "recipient", "sessionKey", "session_id"]);
  if (!to) return params;
  const source = classifyAgentIdentity(from, config);
  const target = classifyAgentIdentity(to, config);
  const content = messageContent(params);
  const ttlMs = config.multiAgentSecurity.maxEnvelopeTtlMs;
  const envelope = signEnvelope({
    version: 1,
    issuer: "xuanjian-agent-transport",
    from: source.id,
    to: target.id,
    tenant: source.tenant,
    sourceNamespace: source.namespace,
    targetNamespace: target.namespace,
    contentSha256: contentHash(content),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttlMs).toISOString(),
  });
  return { ...params, from: source.id, to: target.id, __agentSentryEnvelope: envelope };
}

export function createAgentMessageEnvelope(
  input: { from: string; to: string; content: unknown },
  config: PluginConfig,
  now = Date.now(),
): AgentMessageEnvelope {
  const params = sealAgentMessageParameters({ from: input.from, to: input.to, content: input.content }, config, now);
  return params.__agentSentryEnvelope as AgentMessageEnvelope;
}

export function verifyAgentMessageEnvelope(
  value: unknown,
  input: { from: AgentIdentity; to: AgentIdentity; content: string },
  config: PluginConfig,
  now = Date.now(),
): { valid: boolean; reason: string } {
  const envelope = parseEnvelope(value);
  if (!envelope) return { valid: false, reason: "agent message envelope is missing or malformed" };
  if (envelope.version !== 1 || envelope.issuer !== "xuanjian-agent-transport") return { valid: false, reason: "agent message envelope has an unsupported issuer or version" };
  if (!constantTimeEqual(envelope.signature, envelopeSignature(envelope))) return { valid: false, reason: "agent message envelope signature is invalid" };
  if (!Number.isFinite(Date.parse(envelope.issuedAt)) || !Number.isFinite(Date.parse(envelope.expiresAt))) return { valid: false, reason: "agent message envelope timestamps are invalid" };
  const maxExpiry = Date.parse(envelope.issuedAt) + config.multiAgentSecurity.maxEnvelopeTtlMs;
  if (Date.parse(envelope.expiresAt) < now || Date.parse(envelope.expiresAt) > maxExpiry) return { valid: false, reason: "agent message envelope is expired or exceeds the configured lifetime" };
  if (envelope.from !== input.from.id || envelope.to !== input.to.id) return { valid: false, reason: "agent message envelope identity binding does not match the tool call" };
  if (envelope.tenant !== input.from.tenant || envelope.sourceNamespace !== input.from.namespace || envelope.targetNamespace !== input.to.namespace) {
    return { valid: false, reason: "agent message envelope namespace binding does not match the registered identity" };
  }
  if (!constantTimeEqual(envelope.contentSha256, contentHash(input.content))) return { valid: false, reason: "agent message content differs from the signed envelope" };
  return { valid: true, reason: "" };
}

export function agentCommunicationFindings(action: AgentSentryAction, config: PluginConfig): DetectionFinding[] {
  if (!config.multiAgentSecurity.enabled || action.tool !== "sessions_send") return [];
  const fromRaw = firstString(action.args, ["from", "source", "sender", "agent"]);
  const toRaw = firstString(action.args, ["to", "target", "recipient", "sessionKey", "session_id"]);
  const from = classifyAgentIdentity(fromRaw, config);
  const to = classifyAgentIdentity(toRaw, config);
  const content = messageContent(action.args);
  const findings: DetectionFinding[] = [];
  const analysis = analyzeTrustContent(content, {
    source: from.level === "external_agent" ? "unknown" : "tool_result",
    sourceId: from.id,
    toolName: action.tool,
    previewChars: config.capture.previewChars,
  });
  const risk = riskMax(analysis.risk_vector);

  if (config.multiAgentSecurity.requireIdentity && (!fromRaw || !toRaw || from.level === "external_agent" || to.level === "external_agent")) {
    findings.push(finding("Agent Communication", "deterministic", "require_approval", "跨 Agent 消息包含未登记或缺失的身份，不能获得可信执行权限", 55, {
      from: publicIdentity(from),
      to: publicIdentity(to),
    }));
  }
  if (from.tenant !== to.tenant) {
    findings.push(finding("Agent Communication", "deterministic", "block", "跨租户 Agent 消息被隔离，禁止将上下文和能力跨租户传递", 100, {
      from: publicIdentity(from),
      to: publicIdentity(to),
    }));
  }
  if (config.multiAgentSecurity.requireSignedEnvelope) {
    const envelope = verifyAgentMessageEnvelope(action.args.__agentSentryEnvelope, { from, to, content }, config);
    if (!envelope.valid) {
      findings.push(finding("Agent Communication", "deterministic", "require_approval", `跨 Agent 消息未通过传输完整性校验：${envelope.reason}`, 60, {
        from: publicIdentity(from),
        to: publicIdentity(to),
      }));
    }
  }

  const crossesTrustBoundary = from.score < to.score;
  const tainted = risk >= 45 || analysis.label.integrity === "external" || analysis.label.integrity === "tainted" || analysis.tags.length > 0;
  if (tainted && !to.mayReceiveUntrustedData) {
    findings.push(finding("Agent Communication", "deterministic", "block", "低信任或受污染消息不能进入不接收不可信数据的 Agent 命名空间", 100, {
      from: publicIdentity(from),
      to: publicIdentity(to),
      risk_vector: analysis.risk_vector,
      tags: analysis.tags,
    }));
  } else if (tainted && crossesTrustBoundary) {
    findings.push(finding("Agent Communication", "deterministic", risk >= 70 ? "block" : "require_approval", "低信任 Agent 消息不能提升为高信任 Agent 的工具授权", risk >= 70 ? 100 : 55, {
      from: publicIdentity(from),
      to: publicIdentity(to),
      risk_vector: analysis.risk_vector,
      tags: analysis.tags,
    }));
  }
  if (!from.mayDelegate && to.id !== from.id) {
    findings.push(finding("Agent Communication", "deterministic", "require_approval", "当前 Agent 身份未声明委派权限，需要确认本次跨 Agent 任务分发", 45, {
      from: publicIdentity(from),
      to: publicIdentity(to),
    }));
  }
  return findings;
}

function toIdentity(config: AgentIdentityConfig): AgentIdentity {
  return { ...config, score: LEVEL_SCORE[config.level] };
}

function signEnvelope(envelope: Omit<AgentMessageEnvelope, "signature">): AgentMessageEnvelope {
  return { ...envelope, signature: envelopeSignature(envelope) };
}

function envelopeSignature(envelope: Omit<AgentMessageEnvelope, "signature"> | AgentMessageEnvelope): string {
  return createHmac("sha256", signingSecret).update(canonicalEnvelope(envelope), "utf8").digest("base64url");
}

function canonicalEnvelope(envelope: Omit<AgentMessageEnvelope, "signature"> | AgentMessageEnvelope): string {
  return JSON.stringify({
    version: envelope.version,
    issuer: envelope.issuer,
    from: envelope.from,
    to: envelope.to,
    tenant: envelope.tenant,
    sourceNamespace: envelope.sourceNamespace,
    targetNamespace: envelope.targetNamespace,
    contentSha256: envelope.contentSha256,
    issuedAt: envelope.issuedAt,
    expiresAt: envelope.expiresAt,
  });
}

function parseEnvelope(value: unknown): AgentMessageEnvelope | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  const required = ["issuer", "from", "to", "tenant", "sourceNamespace", "targetNamespace", "contentSha256", "issuedAt", "expiresAt", "signature"];
  if (item.version !== 1 || required.some((key) => typeof item[key] !== "string" || !(item[key] as string).trim())) return null;
  return {
    version: 1,
    issuer: item.issuer as string,
    from: item.from as string,
    to: item.to as string,
    tenant: item.tenant as string,
    sourceNamespace: item.sourceNamespace as string,
    targetNamespace: item.targetNamespace as string,
    contentSha256: item.contentSha256 as string,
    issuedAt: item.issuedAt as string,
    expiresAt: item.expiresAt as string,
    signature: item.signature as string,
  };
}

function messageContent(args: Record<string, unknown>): string {
  const value = args.content ?? args.body ?? args.message ?? args.text ?? "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value || "");
  }
}

function contentHash(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

function firstString(args: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function publicIdentity(identity: AgentIdentity): Record<string, unknown> {
  return {
    id: identity.id,
    level: identity.level,
    tenant: identity.tenant,
    namespace: identity.namespace,
  };
}
