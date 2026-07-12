import { createHash, createHmac } from "node:crypto";
import type { PluginConfig } from "../config.ts";
import type { DetectionFinding } from "./detect.ts";
import { clampText, safeStringify } from "./redact.ts";
import {
  analyzeTrustContent,
  finding,
  riskMax,
  type RiskVector,
  type TrustAnalysis,
  type TrustLabel,
  type TrustLevel,
  type TrustSource,
} from "./trust.ts";

export type MemorySourceClass =
  | "user_directive"
  | "agent_inference"
  | "external_web"
  | "tool_result"
  | "webhook"
  | "unknown";

export type MemoryGuardAction = "allow" | "redact" | "quarantine" | "block";

export type MemoryPassport = {
  id: string;
  key: string;
  source_class: MemorySourceClass;
  trust_level: TrustLevel;
  created_at: string;
  updated_at: string;
  context_hash: string;
  content_sha256: string;
  size_bytes: number;
  tags: string[];
  risk_vector: RiskVector;
  trust_label: TrustLabel;
  protected_key: boolean;
  signature: string;
};

export type MemoryEnvelope = {
  updated_at: string;
  value: string;
  passport: MemoryPassport;
};

export type MemoryGuardWriteResult = {
  action: MemoryGuardAction;
  sanitizedContent: string;
  passport: MemoryPassport;
  findings: DetectionFinding[];
  analysis: TrustAnalysis;
};

export type MemoryGuardReadResult = {
  key: string;
  envelope: MemoryEnvelope;
  findings: DetectionFinding[];
  integrity_ok: boolean;
};

const MAX_MEMORY_BYTES = 16 * 1024;
const WARN_MEMORY_BYTES = 8 * 1024;

const PROTECTED_KEY_PATTERNS = [
  /(^|[/._-])system[_ -]?prompt($|[/._-])/i,
  /(^|[/._-])developer[_ -]?prompt($|[/._-])/i,
  /(^|[/._-])security[_ -]?policy($|[/._-])/i,
  /(^|[/._-])api[_ -]?endpoints?($|[/._-])/i,
  /(^|[/._-])gateway($|[/._-])/i,
  /(^|[/._-])openclaw(?:\.json)?($|[/._-])/i,
  /(^|[/._-])memory\.md$/i,
  /(^|[/._-])agents\.md$/i,
];

const AUTHORITATIVE_MEMORY_PATTERNS = [
  /\b(?:must|always|never|from now on|future sessions?|default policy|priority rule)\b/i,
  /\b(?:approval|confirmation|review|security|guard|policy)\b.{0,80}\b(?:already handled|skip|suppress|quiet|silent|auto|no interruption)\b/i,
  /(以后|未来|下次|永久|默认|优先).{0,80}(必须|总是|永远|策略|审批|确认|安全|监督|静默|无需|跳过)/i,
];

const MEMORY_SECRET_PATTERNS = [
  /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
  /\bgh[pousr]_[a-zA-Z0-9_]{20,}\b/,
  /\bsk-[a-zA-Z0-9_-]{16,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bxox[baprs]-[a-zA-Z0-9-]{16,}\b/,
  /\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*["']?[a-zA-Z0-9._/-]{12,}/i,
];

export function memoryGuardScanWrite(input: {
  key: string;
  content: unknown;
  context: string;
  sourceClass?: MemorySourceClass;
  sourceId?: string;
  existing?: MemoryEnvelope | null;
  config: PluginConfig;
}): MemoryGuardWriteResult {
  const key = normalizeMemoryKey(input.key);
  const content = stringifyMemory(input.content);
  const sourceClass = input.sourceClass || inferMemorySourceClass(input.context, input.sourceId);
  const analysis = analyzeTrustContent(content, {
    source: trustSourceForMemory(sourceClass),
    sourceId: input.sourceId || key,
    path: key,
    toolName: "memory_write",
    previewChars: input.config.capture.previewChars,
  });
  const passport = createMemoryPassport({
    key,
    content,
    context: input.context,
    sourceClass,
    analysis,
    existing: input.existing || null,
  });
  const findings = [...analysis.findings, ...memoryStructuralFindings(key, content, passport, input.existing || null, input.config)];
  const action = chooseMemoryAction(findings, passport);
  const sanitizedContent = action === "redact" ? redactMemorySecrets(content) : content;
  return { action, sanitizedContent, passport, findings: dedupeFindings(findings), analysis };
}

export function memoryGuardScanRead(input: {
  key: string;
  envelope: MemoryEnvelope;
  context: string;
  config: PluginConfig;
}): MemoryGuardReadResult {
  const key = normalizeMemoryKey(input.key);
  const envelope = normalizeEnvelope(key, input.envelope, input.context, input.config);
  const content = stringifyMemory(envelope.value);
  const contentHash = sha256(content);
  const integrityOk = envelope.passport.content_sha256 === contentHash && verifyPassport(envelope.passport);
  const findings: DetectionFinding[] = [];
  const analysis = analyzeTrustContent(content, {
    source: "memory",
    sourceId: key,
    path: key,
    toolName: "memory_read",
    previewChars: input.config.capture.previewChars,
  });
  findings.push(...analysis.findings);
  if (!integrityOk) {
    findings.push(finding("State Integrity", "deterministic", "block", "memory passport integrity check failed", 100, {
      key,
      expected_sha256: envelope.passport.content_sha256,
      actual_sha256: contentHash,
      passport_id: envelope.passport.id,
    }));
  }
  if (isLowTrustMemory(envelope.passport) && riskMax(analysis.risk_vector) >= 45) {
    findings.push(finding("State Integrity", "heuristic", "require_approval", "low-trust memory requires review before it can influence decisions", 60, {
      key,
      passport: publicPassport(envelope.passport),
      risk_vector: analysis.risk_vector,
    }));
  }
  if (isAuthoritativeMemory(content) && isLowTrustMemory(envelope.passport)) {
    findings.push(finding("State Integrity", "deterministic", "block", "low-trust memory tries to assert authoritative future behavior", 95, {
      key,
      passport: publicPassport(envelope.passport),
      preview: clampText(content, input.config.capture.previewChars),
    }));
  }
  return { key, envelope, findings: dedupeFindings(findings), integrity_ok: integrityOk };
}

export function memoryConsensusFindings(input: {
  memories: Array<{ key: string; envelope: MemoryEnvelope }>;
  context: string;
  config: PluginConfig;
}): DetectionFinding[] {
  if (input.memories.length < 2) return [];
  const risky = input.memories.filter(({ envelope }) => {
    const text = stringifyMemory(envelope.value);
    return isLowTrustMemory(envelope.passport) && (isAuthoritativeMemory(text) || riskMax(envelope.passport.risk_vector) >= 50);
  });
  if (!risky.length) return [];
  const benign = input.memories.length - risky.length;
  if (benign <= 0) return [];
  return [finding("State Integrity", "heuristic", "require_approval", "memory consensus check found low-trust outlier records", 70, {
    query_context: clampText(input.context, input.config.capture.previewChars),
    total_memories: input.memories.length,
    outliers: risky.slice(0, 8).map(({ key, envelope }) => ({
      key,
      passport: publicPassport(envelope.passport),
      preview: clampText(stringifyMemory(envelope.value), 240),
    })),
  })];
}

export function normalizeEnvelope(key: string, value: unknown, context: string, config: PluginConfig): MemoryEnvelope {
  if (isMemoryEnvelope(value)) return value;
  const content = legacyMemoryValue(value);
  const analysis = analyzeTrustContent(content, {
    source: "memory",
    sourceId: key,
    path: key,
    toolName: "memory_read",
    previewChars: config.capture.previewChars,
  });
  const passport = createMemoryPassport({
    key,
    content,
    context,
    sourceClass: "unknown",
    analysis,
    existing: null,
  });
  return {
    updated_at: typeof (value as { updated_at?: unknown })?.updated_at === "string" ? String((value as { updated_at: string }).updated_at) : new Date().toISOString(),
    value: content,
    passport,
  };
}

export function publicPassport(passport: MemoryPassport): Record<string, unknown> {
  return {
    id: passport.id,
    key: passport.key,
    source_class: passport.source_class,
    trust_level: passport.trust_level,
    created_at: passport.created_at,
    updated_at: passport.updated_at,
    content_sha256: passport.content_sha256,
    size_bytes: passport.size_bytes,
    tags: passport.tags,
    risk_vector: passport.risk_vector,
    protected_key: passport.protected_key,
  };
}

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function createMemoryPassport(input: {
  key: string;
  content: string;
  context: string;
  sourceClass: MemorySourceClass;
  analysis: TrustAnalysis;
  existing: MemoryEnvelope | null;
}): MemoryPassport {
  const now = new Date().toISOString();
  const previous = input.existing?.passport;
  const protectedKey = isProtectedMemoryKey(input.key);
  const trustLevel = memoryTrustLevel(input.sourceClass, input.analysis.label.integrity, protectedKey);
  const passport: Omit<MemoryPassport, "signature"> = {
    id: previous?.id || `mem_${sha256(`${input.key}:${now}:${Math.random()}`).slice(0, 18)}`,
    key: input.key,
    source_class: input.sourceClass,
    trust_level: trustLevel,
    created_at: previous?.created_at || now,
    updated_at: now,
    context_hash: sha256(input.context || ""),
    content_sha256: sha256(input.content),
    size_bytes: Buffer.byteLength(input.content, "utf8"),
    tags: Array.from(new Set([...input.analysis.tags, protectedKey ? "protected_key" : ""])).filter(Boolean),
    risk_vector: input.analysis.risk_vector,
    trust_label: input.analysis.label,
    protected_key: protectedKey,
  };
  return { ...passport, signature: signPassport(passport) };
}

function memoryStructuralFindings(
  key: string,
  content: string,
  passport: MemoryPassport,
  existing: MemoryEnvelope | null,
  config: PluginConfig,
): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  if (passport.protected_key) {
    findings.push(finding("State Integrity", "deterministic", "block", "memory write targets a protected key", 100, {
      key,
      passport: publicPassport(passport),
    }));
  }
  if (passport.size_bytes > MAX_MEMORY_BYTES) {
    findings.push(finding("State Integrity", "deterministic", "block", "memory payload exceeds maximum allowed size", 95, {
      key,
      size_bytes: passport.size_bytes,
      max_bytes: MAX_MEMORY_BYTES,
    }));
  } else if (passport.size_bytes > WARN_MEMORY_BYTES) {
    findings.push(finding("State Integrity", "heuristic", "require_approval", "memory payload is unusually large", 45, {
      key,
      size_bytes: passport.size_bytes,
      warn_bytes: WARN_MEMORY_BYTES,
    }));
  }
  if (MEMORY_SECRET_PATTERNS.some((pattern) => pattern.test(content))) {
    findings.push(finding("State Integrity", "deterministic", "block", "memory write attempts to persist secrets or credentials", 100, {
      key,
      preview: clampText(redactMemorySecrets(content), config.capture.previewChars),
    }));
  }
  if (isAuthoritativeMemory(content) && trustRankForPassport(passport) <= 2) {
    findings.push(finding("State Integrity", "deterministic", "block", "low-trust source cannot write authoritative future-behavior memory", 95, {
      key,
      source_class: passport.source_class,
      trust_level: passport.trust_level,
      preview: clampText(content, config.capture.previewChars),
    }));
  }
  if (existing && existing.passport.content_sha256 !== sha256(legacyMemoryValue(existing))) {
    findings.push(finding("State Integrity", "deterministic", "block", "existing memory record failed integrity check before update", 100, {
      key,
      passport: publicPassport(existing.passport),
    }));
  }
  return findings;
}

function chooseMemoryAction(findings: DetectionFinding[], passport: MemoryPassport): MemoryGuardAction {
  if (findings.some((item) => item.verdict === "block")) return "block";
  if (passport.trust_level === "tainted") return "quarantine";
  if (findings.some((item) => item.verdict === "require_approval")) return "quarantine";
  if (findings.some((item) => item.reason.includes("secret"))) return "redact";
  return "allow";
}

function isProtectedMemoryKey(key: string): boolean {
  return PROTECTED_KEY_PATTERNS.some((pattern) => pattern.test(key));
}

function inferMemorySourceClass(context: string, sourceId = ""): MemorySourceClass {
  const text = `${context}\n${sourceId}`.toLowerCase();
  if (/hook|webhook|\/hooks\/wake/.test(text)) return "webhook";
  if (/网页|web|url|http|外部|pdf|image|图片|邮件|email|mail/.test(text)) return "external_web";
  if (/tool|工具|result|结果/.test(text)) return "tool_result";
  if (/remember|记住|偏好|preference|用户/.test(text)) return "user_directive";
  return "agent_inference";
}

function trustSourceForMemory(sourceClass: MemorySourceClass): TrustSource {
  if (sourceClass === "external_web") return "external_web";
  if (sourceClass === "tool_result") return "tool_result";
  if (sourceClass === "webhook") return "webhook";
  if (sourceClass === "user_directive") return "user_input";
  return "memory";
}

function memoryTrustLevel(sourceClass: MemorySourceClass, analysisTrust: TrustLevel, protectedKey: boolean): TrustLevel {
  if (analysisTrust === "tainted" || protectedKey) return "tainted";
  if (sourceClass === "user_directive") return "user";
  if (sourceClass === "agent_inference") return "workspace";
  if (sourceClass === "tool_result") return "workspace";
  return "external";
}

function isLowTrustMemory(passport: MemoryPassport): boolean {
  return trustRankForPassport(passport) <= 1 || passport.trust_level === "tainted";
}

function trustRankForPassport(passport: MemoryPassport): number {
  const rank: Record<TrustLevel, number> = {
    tainted: 0,
    external: 1,
    workspace: 2,
    user: 3,
    trusted: 4,
  };
  return rank[passport.trust_level] ?? 0;
}

function isAuthoritativeMemory(content: string): boolean {
  if (isNegatedSafetyBoundaryMemory(content)) return false;
  return AUTHORITATIVE_MEMORY_PATTERNS.some((pattern) => pattern.test(content));
}

function isNegatedSafetyBoundaryMemory(content: string): boolean {
  return [
    /(不改变|不会改变|不涉及|不得改变|不能改变|不覆盖|不绕过|不跳过|不禁用|不关闭).{0,80}(安全策略|策略|权限边界|审批|确认|工具审批|授权|监督)/i,
    /(不改变|不会改变|不涉及|不得改变|不能改变|不覆盖|不绕过|不跳过|不禁用|不关闭).{0,80}(security|policy|permission|authorization|approval|guard|audit)/i,
    /\b(?:does\s+not|do\s+not|without|never)\b.{0,80}\b(?:change|override|bypass|skip|disable|suppress)\b.{0,80}\b(?:security|policy|permission|authorization|approval|guard|audit)\b/i,
  ].some((pattern) => pattern.test(content));
}

function redactMemorySecrets(content: string): string {
  return content
    .replace(/-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/g, "[redacted-private-key]")
    .replace(/\bgh[pousr]_[a-zA-Z0-9_]{20,}\b/g, "[redacted-github-token]")
    .replace(/\bsk-[a-zA-Z0-9_-]{16,}\b/g, "[redacted-api-key]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[redacted-aws-key]")
    .replace(/\bxox[baprs]-[a-zA-Z0-9-]{16,}\b/g, "[redacted-slack-token]")
    .replace(/\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*["']?[a-zA-Z0-9._/-]{12,}/gi, (match) => `${match.split(/[:=]/)[0]}=[redacted]`);
}

function stringifyMemory(value: unknown): string {
  if (typeof value === "string") return value;
  return safeStringify(value);
}

function legacyMemoryValue(value: unknown): string {
  if (isMemoryEnvelope(value)) return value.value;
  if (value && typeof value === "object" && typeof (value as { value?: unknown }).value !== "undefined") {
    return stringifyMemory((value as { value?: unknown }).value);
  }
  return stringifyMemory(value);
}

function normalizeMemoryKey(key: string): string {
  return String(key || "memory").trim().replace(/[^\w./:-]+/g, "_").slice(0, 160) || "memory";
}

function isMemoryEnvelope(value: unknown): value is MemoryEnvelope {
  if (!value || typeof value !== "object") return false;
  const obj = value as Partial<MemoryEnvelope>;
  return typeof obj.value === "string"
    && typeof obj.updated_at === "string"
    && Boolean(obj.passport && typeof obj.passport === "object" && typeof obj.passport.content_sha256 === "string");
}

function signPassport(passport: Omit<MemoryPassport, "signature">): string {
  return createHmac("sha256", passportSecret()).update(stableStringify(passport)).digest("hex");
}

function verifyPassport(passport: MemoryPassport): boolean {
  const { signature: _signature, ...unsigned } = passport;
  return signPassport(unsigned) === passport.signature;
}

function passportSecret(): string {
  return process.env.AGENTSENTRY_TRUST_SECRET || process.env.AGENTSENTRY_API_KEY || "agentsentry-local-memory-guard";
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function dedupeFindings(findings: DetectionFinding[]): DetectionFinding[] {
  const seen = new Set<string>();
  const out: DetectionFinding[] = [];
  for (const item of findings) {
    const key = `${item.layer}:${item.verdict}:${item.reason}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}
