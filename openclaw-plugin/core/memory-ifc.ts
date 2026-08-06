import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { PluginConfig } from "../config.ts";
import { analyzeTrustContent, type RiskVector, type TrustLabel, type TrustSource } from "./trust.ts";

export type PersistentMemoryLabel = {
  id: string;
  key: string;
  content_sha256: string;
  source_class: "user_directive" | "agent_inference" | "external_web" | "tool_result" | "webhook" | "unknown";
  integrity: "system-trusted" | "user-trusted" | "untrusted-external";
  confidentiality: "public" | "internal" | "user-private" | "tenant-secret";
  purpose: string;
  lifetime: "turn" | "session" | "memory" | "expired";
  tenant: string;
  session_id: string;
  created_at: string;
  updated_at: string;
  tags: string[];
  risk_vector: RiskVector;
  trust_label: TrustLabel;
};

export function loadPersistentMemoryLabels(config: PluginConfig): PersistentMemoryLabel[] {
  try {
    const parsed = JSON.parse(readFileSync(memoryLabelLedgerPath(config), "utf8")) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isPersistentMemoryLabel).slice(-400);
  } catch {
    return [];
  }
}

export function upsertPersistentMemoryLabel(config: PluginConfig, label: PersistentMemoryLabel): void {
  const labels = loadPersistentMemoryLabels(config);
  const key = `${label.key}:${label.content_sha256}`;
  const next = [
    ...labels.filter((item) => `${item.key}:${item.content_sha256}` !== key),
    label,
  ].slice(-400);
  const target = memoryLabelLedgerPath(config);
  mkdirSync(dirname(target), { recursive: true });
  const tmp = `${target}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, JSON.stringify(next, null, 2), "utf8");
  renameSync(tmp, target);
}

export function buildPersistentMemoryLabel(input: {
  key: string;
  content: unknown;
  context: string;
  sourceClass?: PersistentMemoryLabel["source_class"];
  sessionId?: string;
  tenant?: string;
  config: PluginConfig;
}): PersistentMemoryLabel {
  const content = stringifyMemory(input.content);
  const sourceClass = input.sourceClass || inferMemorySourceClass(input.context);
  const analysis = analyzeTrustContent(content, {
    source: trustSourceForMemory(sourceClass),
    sourceId: input.key,
    path: input.key,
    toolName: "memory_write",
    previewChars: input.config.capture.previewChars,
  });
  const now = new Date().toISOString();
  const contentHash = sha256(content);
  return {
    id: `mem_ifc_${sha256(`${input.key}:${contentHash}`).slice(0, 20)}`,
    key: normalizeMemoryKey(input.key),
    content_sha256: contentHash,
    source_class: sourceClass,
    integrity: memoryIntegrity(sourceClass, analysis.label.tainted),
    confidentiality: memoryConfidentiality(analysis.label.confidentiality),
    purpose: normalizePurpose(input.context),
    lifetime: "memory",
    tenant: input.tenant || "default",
    session_id: input.sessionId || "",
    created_at: now,
    updated_at: now,
    tags: Array.from(new Set([...analysis.tags, ...lifecycleTags(sourceClass)])),
    risk_vector: analysis.risk_vector,
    trust_label: analysis.label,
  };
}

export function normalizeMemoryKey(value: string): string {
  const normalized = String(value || "memory").trim().replace(/\\/g, "/");
  const memoryFile = normalized.match(/(?:^|\/)memory\/([^/]+\.md)$/i);
  if (memoryFile?.[1]) return `memory/${memoryFile[1]}`;
  const namedMemory = normalized.match(/(?:^|\/)(user\.md|soul\.md|memory\.md|agents\.md)$/i);
  if (namedMemory?.[1]) return namedMemory[1].toLowerCase();
  return normalized.replace(/[^\w./:-]+/g, "_").slice(0, 160) || "memory";
}

export function memoryContentHash(value: unknown): string {
  return sha256(stringifyMemory(value));
}

function memoryLabelLedgerPath(config: PluginConfig): string {
  const stateDir = config.storage.stateDir || process.env.OPENCLAW_STATE_DIR?.trim() || join(homedir(), ".openclaw");
  return join(stateDir, "agentsentry", "memory-labels.json");
}

function stringifyMemory(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function inferMemorySourceClass(context: string): PersistentMemoryLabel["source_class"] {
  const text = String(context || "").toLowerCase();
  if (/hook|webhook|\/hooks\/wake/.test(text)) return "webhook";
  if (/网页|web|url|http|外部|pdf|image|图片|邮件|email|mail/.test(text)) return "external_web";
  if (/tool|工具|result|结果/.test(text)) return "tool_result";
  if (/remember|记住|偏好|preference|用户|身份/.test(text)) return "user_directive";
  return "agent_inference";
}

function trustSourceForMemory(sourceClass: PersistentMemoryLabel["source_class"]): TrustSource {
  if (sourceClass === "external_web") return "external_web";
  if (sourceClass === "tool_result") return "tool_result";
  if (sourceClass === "webhook") return "webhook";
  if (sourceClass === "user_directive") return "user_input";
  return "memory";
}

function memoryIntegrity(
  sourceClass: PersistentMemoryLabel["source_class"],
  tainted: boolean,
): PersistentMemoryLabel["integrity"] {
  if (tainted || sourceClass === "external_web" || sourceClass === "webhook" || sourceClass === "unknown") return "untrusted-external";
  if (sourceClass === "user_directive") return "user-trusted";
  return "system-trusted";
}

function memoryConfidentiality(value: TrustLabel["confidentiality"]): PersistentMemoryLabel["confidentiality"] {
  if (value === "secret") return "tenant-secret";
  if (value === "internal") return "internal";
  return "public";
}

function normalizePurpose(context: string): string {
  const text = String(context || "").normalize("NFKC").trim();
  if (!text) return "unspecified";
  if (/(巡检|health|status|检查|诊断)/i.test(text)) return "system_health";
  if (/(报告|文档|总结|summary|report)/i.test(text)) return "reporting";
  if (/(代码|开发|修复|编程|code|edit)/i.test(text)) return "code_work";
  if (/(邮件|email|mail|发送)/i.test(text)) return "delivery";
  if (/(记住|偏好|身份|remember|preference)/i.test(text)) return "user_preference";
  return "general";
}

function lifecycleTags(sourceClass: PersistentMemoryLabel["source_class"]): string[] {
  return sourceClass === "external_web" || sourceClass === "webhook"
    ? ["persistent_memory", "low_trust_source"]
    : ["persistent_memory"];
}

function isPersistentMemoryLabel(value: unknown): value is PersistentMemoryLabel {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Partial<PersistentMemoryLabel>;
  return typeof item.id === "string"
    && typeof item.key === "string"
    && typeof item.content_sha256 === "string"
    && typeof item.source_class === "string"
    && typeof item.integrity === "string"
    && typeof item.confidentiality === "string"
    && typeof item.purpose === "string"
    && typeof item.lifetime === "string"
    && typeof item.created_at === "string"
    && typeof item.updated_at === "string"
    && Array.isArray(item.tags)
    && Boolean(item.trust_label && typeof item.trust_label === "object");
}
