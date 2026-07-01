import { createHmac } from "node:crypto";
import type { DetectionFinding } from "./detect.ts";
import { clampText, safeStringify } from "./redact.ts";

export type TrustLevel = "trusted" | "user" | "workspace" | "external" | "tainted";

export type TrustSource =
  | "user_input"
  | "external_web"
  | "email_html"
  | "pdf_text"
  | "image_metadata"
  | "tool_result"
  | "memory"
  | "config"
  | "skill"
  | "webhook"
  | "workspace"
  | "unknown";

export type RiskVector = {
  prompt_injection: number;
  hidden_content: number;
  sensitive_data: number;
  exfiltration: number;
  persistence: number;
  tool_hijack: number;
  privilege: number;
  intent_drift: number;
  supply_chain: number;
};

export type TrustLabel = {
  id: string;
  source: TrustSource;
  integrity: TrustLevel;
  confidentiality: "public" | "internal" | "secret";
  tainted: boolean;
  signed_at: string;
  signature: string;
  evidence: Record<string, unknown>;
};

export type TrustAnalysis = {
  label: TrustLabel;
  risk_vector: RiskVector;
  findings: DetectionFinding[];
  tags: string[];
};

export const EMPTY_RISK_VECTOR: RiskVector = {
  prompt_injection: 0,
  hidden_content: 0,
  sensitive_data: 0,
  exfiltration: 0,
  persistence: 0,
  tool_hijack: 0,
  privilege: 0,
  intent_drift: 0,
  supply_chain: 0,
};

const TRUST_RANK: Record<TrustLevel, number> = {
  tainted: 0,
  external: 1,
  workspace: 2,
  user: 3,
  trusted: 4,
};

const HIDDEN_HTML_PATTERNS = [
  /style\s*=\s*["'][^"']*(?:color\s*:\s*(?:#fff\b|#ffffff\b|white\b|rgb\s*\(\s*255\s*,\s*255\s*,\s*255\s*\)))/i,
  /style\s*=\s*["'][^"']*(?:font-size\s*:\s*(?:0|1px|0\.1px))/i,
  /style\s*=\s*["'][^"']*(?:opacity\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden)/i,
  /style\s*=\s*["'][^"']*(?:width\s*:\s*0|height\s*:\s*0|overflow\s*:\s*hidden)/i,
  /<(?:span|div|p|a)\b[^>]*(?:hidden|aria-hidden\s*=\s*["']true["'])[^>]*>/i,
  /<!--[\s\S]{0,240}(?:ignore|system|developer|token|secret|id_rsa|ssh|exfiltrate|忽略|系统|密钥)[\s\S]{0,240}-->/i,
];

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above|security|safety)\s+(instructions?|rules?|commands?|policies?)/i,
  /\b(system|developer|internal)\b.{0,56}\b(prompt|configuration|policy|instruction|message)\b/i,
  /(act\s+as|pretend\s+to\s+be).{0,32}(developer|system|jailbroken|unfiltered)/i,
  /(bypass|disable|override|circumvent|evade).{0,40}(policy|guardrail|safety|approval|monitor|audit)/i,
  /(send|show|list|provide|copy|exfiltrate|upload|post).{0,96}(api[_ -]?key|token|secret|password|credential|private\s*key|id_rsa|openclaw\.json)/i,
  /(忽略|绕过|禁用|关闭).{0,40}(安全策略|策略|规则|限制|审批|审计|监督|系统提示)/i,
  /(读取|发送|上传|泄露|外发).{0,96}(ssh|私钥|密钥|token|api[_ -]?key|openclaw\.json|系统提示|配置)/i,
];

const PDF_STEGO_PATTERNS = [
  /\/(?:CA|ca)\s+0(?:\.0+)?\b/,
  /\/Tr\s+3\b/,
  /\/OC\b|Optional\s+Content|\/OCProperties|\/Layer\b/i,
  /transparent\s+text|invisible\s+text|white\s+text/i,
];

const IMAGE_METADATA_PATTERNS = [
  /\b(?:exif|xmp|itxt|tEXt|zTXt|comment|metadata|ocr|alt\s*text)\b.{0,120}(?:ignore|system|developer|token|secret|id_rsa|exfiltrate|忽略|系统|密钥)/i,
  /<\?xpacket[\s\S]{0,600}(?:ignore|system|developer|token|secret|id_rsa|exfiltrate|忽略|系统|密钥)/i,
];

const URL_FRAGMENT_PATTERNS = [
  /https?:\/\/[^\s"'<>#]+#[^\s"'<>]*(?:ignore|system|developer|token|secret|id_rsa|exfiltrate|忽略|系统|密钥)/i,
  /#[^\s"'<>]*(?:ignore|system|developer|token|secret|id_rsa|exfiltrate|忽略|系统|密钥)/i,
];

const MEMORY_POISON_PATTERNS = [
  /\[(?:system|developer)\]/i,
  /\brole\s*[:=]\s*["']?(?:system|developer)["']?/i,
  /(always|future|next\s+time|from\s+now\s+on|persist|remember).{0,80}(ignore|bypass|disable|override|priority|execute)/i,
  /(以后|未来|下次|永久|记住).{0,80}(忽略|绕过|禁用|优先执行|直接执行|无需确认|关闭安全)/i,
  /\b(?:cron|crontab|systemd|startup|autorun|hooks\/wake|\/hooks\/wake)\b/i,
];

const GATEWAY_HIJACK_PATTERNS = [
  /[?&]gatewayURL\s*=\s*wss?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))/i,
  /\bgatewayURL\b.{0,80}\bwss?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))/i,
  /\bgateway(?:Auth)?(?:Token|URL)\b.{0,80}(?:evil|attacker|collect|exfil|外发|窃取)/i,
];

const SKILL_EXFIL_PATTERNS = [
  /openclaw\.json|gateway.{0,24}(?:auth|token)|auth.{0,24}token/i,
  /\b(?:fetch|axios|curl|wget|https?\.request|XMLHttpRequest)\b[\s\S]{0,180}(?:token|secret|openclaw\.json|gateway|credential|password)/i,
  /\b(?:readFileSync|readFile|fs\.)\b[\s\S]{0,180}(?:openclaw\.json|\.env|id_rsa|secret|token|password)/i,
];

const SENSITIVE_PATTERNS: Array<[string, RegExp]> = [
  ["private_key", /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/],
  ["ssh_private_key_path", /(?:~\/\.ssh\/id_rsa|\.ssh[/\\]id_rsa|id_ed25519)/i],
  ["api_key", /\bsk-[a-zA-Z0-9_-]{16,}\b/],
  ["github_token", /\bgh[pousr]_[a-zA-Z0-9_]{20,}\b/],
  ["slack_token", /\bxox[baprs]-[a-zA-Z0-9-]{16,}\b/],
  ["aws_access_key", /\bAKIA[0-9A-Z]{16}\b/],
  ["bearer_token", /\bbearer\s+[a-zA-Z0-9._-]{16,}\b/i],
  ["named_secret", /\b(api[_-]?key|token|secret|password|credential|authorization)\b/i],
  ["openclaw_config", /\bopenclaw\.json\b/i],
];

const SOURCE_DEFAULT_TRUST: Record<TrustSource, TrustLevel> = {
  user_input: "user",
  external_web: "external",
  email_html: "external",
  pdf_text: "external",
  image_metadata: "external",
  tool_result: "workspace",
  memory: "workspace",
  config: "workspace",
  skill: "workspace",
  webhook: "external",
  workspace: "workspace",
  unknown: "external",
};

export function analyzeTrustContent(
  value: unknown,
  options: {
    source?: TrustSource;
    sourceId?: string;
    path?: string;
    toolName?: string;
    previewChars?: number;
  } = {},
): TrustAnalysis {
  const previewChars = options.previewChars ?? 1200;
  const source = options.source || inferSource(value, options);
  const text = flattenContent(value);
  const lowerPath = (options.path || "").replace(/\\/g, "/").toLowerCase();
  const matched = {
    hiddenHtml: matchPatterns(text, HIDDEN_HTML_PATTERNS),
    promptInjection: matchPatterns(text, PROMPT_INJECTION_PATTERNS),
    pdfStego: matchPatterns(text, PDF_STEGO_PATTERNS),
    imageMetadata: matchPatterns(text, IMAGE_METADATA_PATTERNS),
    urlFragment: matchPatterns(text, URL_FRAGMENT_PATTERNS),
    memoryPoison: matchPatterns(text, MEMORY_POISON_PATTERNS),
    gatewayHijack: matchPatterns(text, GATEWAY_HIJACK_PATTERNS),
    skillExfil: matchPatterns(text, SKILL_EXFIL_PATTERNS),
    sensitive: matchSensitive(text),
  };
  matched.promptInjection = matched.promptInjection.filter((item) => !isNegatedSafetyBoundary(item));

  if (/(^|\/)(memory\.md|agents\.md|soul\.md|user\.md)$/i.test(lowerPath)) {
    matched.memoryPoison.push(lowerPath);
  }
  if (/(^|\/)(skill\.md|package\.json|index\.[cm]?[jt]s)$/i.test(lowerPath) && matched.skillExfil.length) {
    matched.memoryPoison.push("skill package can persist unsafe capability");
  }
  if (/\.(pdf)$/i.test(lowerPath) && matched.promptInjection.length) {
    matched.pdfStego.push("pdf content carries agent instructions");
  }
  if (/\.(png|jpe?g|webp|gif|tiff?)$/i.test(lowerPath) && matched.promptInjection.length) {
    matched.imageMetadata.push("image asset carries agent instructions");
  }

  const risk = createRiskVector({
    prompt_injection: score(Boolean(matched.promptInjection.length), 75),
    hidden_content: score(Boolean(matched.hiddenHtml.length || matched.pdfStego.length || matched.imageMetadata.length || matched.urlFragment.length), 80),
    sensitive_data: score(Boolean(matched.sensitive.length), 80),
    exfiltration: score(hasExfilSignal(text), 70),
    persistence: score(Boolean(matched.memoryPoison.length), 85),
    tool_hijack: score(Boolean(matched.gatewayHijack.length || matched.skillExfil.length), 90),
    privilege: score(hasPrivilegeSignal(text), 65),
    intent_drift: score(hasIntentDriftSignal(text), 55),
    supply_chain: score(Boolean(matched.skillExfil.length), 80),
  });

  const tags = [
    matched.hiddenHtml.length ? "hidden_html" : "",
    matched.urlFragment.length ? "url_fragment_instruction" : "",
    matched.pdfStego.length ? "pdf_hidden_text" : "",
    matched.imageMetadata.length ? "image_metadata_instruction" : "",
    matched.memoryPoison.length ? "persistence_instruction" : "",
    matched.gatewayHijack.length ? "gateway_hijack" : "",
    matched.skillExfil.length ? "skill_secret_exfiltration" : "",
    matched.sensitive.length ? "sensitive_data" : "",
    matched.promptInjection.length ? "prompt_injection" : "",
  ].filter(Boolean);

  const tainted = riskMax(risk) >= 50 || source === "external_web" || source === "email_html" || source === "pdf_text" || source === "image_metadata" || source === "webhook";
  const confidentiality = matched.sensitive.length ? "secret" : source === "config" || source === "memory" ? "internal" : "public";
  const integrity: TrustLevel = riskMax(risk) >= 80 ? "tainted" : SOURCE_DEFAULT_TRUST[source];
  const label = createTrustLabel({
    source,
    sourceId: options.sourceId || options.toolName || options.path || "content",
    integrity,
    confidentiality,
    tainted,
    evidence: {
      path: options.path || "",
      toolName: options.toolName || "",
      tags,
      risk_vector: risk,
      sensitive_kinds: matched.sensitive,
    },
  });

  const findings: DetectionFinding[] = [];
  if (matched.hiddenHtml.length || matched.urlFragment.length) {
    findings.push(finding("Input Sanitization", "deterministic", "block", "external content contains hidden prompt-injection instructions", 95, {
      source,
      tags,
      matched: [...matched.hiddenHtml, ...matched.urlFragment].slice(0, 5),
      trust_label: label,
      risk_vector: risk,
      preview: clampText(text, previewChars),
    }));
  }
  if (matched.pdfStego.length) {
    findings.push(finding("Input Sanitization", "deterministic", "block", "PDF content contains hidden or low-visibility agent instructions", 95, {
      source,
      path: options.path || "",
      matched: matched.pdfStego.slice(0, 5),
      trust_label: label,
      risk_vector: risk,
    }));
  }
  if (matched.imageMetadata.length) {
    findings.push(finding("Input Sanitization", "deterministic", "block", "image metadata or OCR text contains agent instructions", 90, {
      source,
      path: options.path || "",
      matched: matched.imageMetadata.slice(0, 5),
      trust_label: label,
      risk_vector: risk,
    }));
  }
  if (matched.promptInjection.length && !findings.some((item) => item.layer === "Input Sanitization")) {
    findings.push(finding("Input Sanitization", "heuristic", "require_approval", "content contains prompt-injection or exfiltration indicators", 45, {
      source,
      matched: matched.promptInjection.slice(0, 5),
      trust_label: label,
      risk_vector: risk,
      preview: clampText(text, previewChars),
    }));
  }
  if (matched.memoryPoison.length) {
    findings.push(finding("Cognition Protection", "deterministic", "block", "content attempts to persist privileged instructions into memory or startup flow", 100, {
      source,
      path: options.path || "",
      matched: matched.memoryPoison.slice(0, 5),
      trust_label: label,
      risk_vector: risk,
    }));
  }
  if (matched.gatewayHijack.length) {
    findings.push(finding("Execution Control", "deterministic", "block", "gateway URL override or token-hijack pattern detected", 100, {
      source,
      matched: matched.gatewayHijack.slice(0, 5),
      trust_label: label,
      risk_vector: risk,
    }));
  }
  if (matched.skillExfil.length) {
    findings.push(finding("Foundation", "deterministic", "block", "skill or code path can read OpenClaw secrets and exfiltrate them", 100, {
      source,
      path: options.path || "",
      matched: matched.skillExfil.slice(0, 5).map((item) => sanitizeEvidence(item)),
      trust_label: label,
      risk_vector: risk,
    }));
  }
  if (matched.sensitive.length) {
    findings.push(finding("Execution Control", "heuristic", "require_approval", "content references sensitive credentials or private assets", 55, {
      source,
      sensitive_kinds: matched.sensitive,
      trust_label: label,
      risk_vector: risk,
    }));
  }

  return { label, risk_vector: risk, findings: dedupeFindings(findings), tags };
}

export function mergeRiskVectors(...vectors: Array<RiskVector | undefined | null>): RiskVector {
  const out = createRiskVector();
  for (const vector of vectors) {
    if (!vector) continue;
    for (const key of Object.keys(out) as Array<keyof RiskVector>) {
      out[key] = Math.max(out[key], clampScore(vector[key]));
    }
  }
  return out;
}

export function addRisk(a: RiskVector, b: RiskVector): RiskVector {
  const out = createRiskVector(a);
  for (const key of Object.keys(out) as Array<keyof RiskVector>) {
    out[key] = Math.min(100, out[key] + clampScore(b[key]));
  }
  return out;
}

export function riskMax(vector: RiskVector): number {
  return Math.max(...Object.values(vector).map(clampScore));
}

export function trustRank(level: TrustLevel): number {
  return TRUST_RANK[level] ?? 0;
}

export function minimumTrustLabel(labels: TrustLabel[]): TrustLabel | null {
  if (!labels.length) return null;
  return labels.reduce((lowest, label) => trustRank(label.integrity) < trustRank(lowest.integrity) ? label : lowest, labels[0]);
}

export function createRiskVector(partial: Partial<RiskVector> = {}): RiskVector {
  return {
    ...EMPTY_RISK_VECTOR,
    ...Object.fromEntries(
      Object.entries(partial).map(([key, value]) => [key, clampScore(value)]),
    ),
  } as RiskVector;
}

export function sourceFromTool(toolName: string): TrustSource {
  const lower = toolName.toLowerCase();
  if (/web|browser|url|fetch|http|api|request|curl|wget/.test(lower)) return "external_web";
  if (/mail|email/.test(lower)) return "email_html";
  if (/pdf/.test(lower)) return "pdf_text";
  if (/image|ocr|vision|photo|png|jpg|jpeg|webp/.test(lower)) return "image_metadata";
  if (/memory|remember/.test(lower)) return "memory";
  if (/config|setting/.test(lower)) return "config";
  if (/skill|plugin|package/.test(lower)) return "skill";
  return "tool_result";
}

export function finding(
  layer: string,
  findingType: "deterministic" | "heuristic" | "learned",
  verdict: "pass" | "require_approval" | "block",
  reason: string,
  score: number,
  evidence: Record<string, unknown>,
): DetectionFinding {
  return { layer, finding_type: findingType, verdict, reason, score, evidence };
}

function createTrustLabel(input: {
  source: TrustSource;
  sourceId: string;
  integrity: TrustLevel;
  confidentiality: "public" | "internal" | "secret";
  tainted: boolean;
  evidence: Record<string, unknown>;
}): TrustLabel {
  const signedAt = new Date().toISOString();
  const id = `trust_${hmac(`${input.source}:${input.sourceId}:${signedAt}`).slice(0, 18)}`;
  const base = {
    id,
    source: input.source,
    sourceId: input.sourceId,
    integrity: input.integrity,
    confidentiality: input.confidentiality,
    tainted: input.tainted,
    evidence: input.evidence,
  };
  return {
    id,
    source: input.source,
    integrity: input.integrity,
    confidentiality: input.confidentiality,
    tainted: input.tainted,
    signed_at: signedAt,
    signature: hmac(stableStringify(base)),
    evidence: input.evidence,
  };
}

function inferSource(value: unknown, options: { path?: string; toolName?: string }): TrustSource {
  if (options.toolName) return sourceFromTool(options.toolName);
  const path = (options.path || "").toLowerCase();
  if (path.endsWith(".pdf")) return "pdf_text";
  if (/\.(png|jpe?g|webp|gif|tiff?)$/.test(path)) return "image_metadata";
  if (/(^|\/)(memory\.md|agents\.md|soul\.md|user\.md)$/.test(path)) return "memory";
  if (path.endsWith("skill.md") || path.includes("/skills/")) return "skill";
  if (path.endsWith("openclaw.json") || path.includes("/config")) return "config";
  const text = flattenContent(value);
  if (/<html|<body|<span|<div|style\s*=|https?:\/\//i.test(text)) return "external_web";
  if (/content-type:\s*text\/html|from:\s*.+@.+|subject:/i.test(text)) return "email_html";
  return "unknown";
}

function flattenContent(value: unknown): string {
  if (typeof value === "string") return value;
  if (Buffer.isBuffer(value)) return extractStrings(value);
  if (Array.isArray(value)) return value.map(flattenContent).join("\n");
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (typeof obj.preview === "string") return obj.preview;
    if (typeof obj.content === "string") return obj.content;
    if (typeof obj.text === "string") return obj.text;
  }
  return safeStringify(value);
}

function extractStrings(buffer: Buffer): string {
  return buffer
    .toString("latin1")
    .replace(/[^\x09\x0a\x0d\x20-\x7e]+/g, " ")
    .replace(/\s{3,}/g, " ");
}

function matchPatterns(text: string, patterns: RegExp[]): string[] {
  const out: string[] = [];
  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match) out.push(sanitizeEvidence(match[0]));
  }
  return Array.from(new Set(out));
}

function matchSensitive(text: string): string[] {
  const kinds: string[] = [];
  for (const [kind, pattern] of SENSITIVE_PATTERNS) {
    if (pattern.test(text)) kinds.push(kind);
  }
  return Array.from(new Set(kinds));
}

function isNegatedSafetyBoundary(value: string): boolean {
  return /(?:do\s+not|don't|without|never|no\s+need\s+to|不要|不需要|无需|禁止|不得|避免|不能|不应).{0,80}(?:read|send|upload|include|access|exfiltrate|token|secret|password|credential|private\s*key|读取|访问|发送|上传|外发|泄露|包含|凭据|密钥|私钥|配置)/i.test(value)
    || /(?:read|send|upload|include|access|exfiltrate|读取|访问|发送|上传|外发|泄露|包含).{0,40}(?:do\s+not|don't|without|never|不要|不需要|无需|禁止|不得|避免|不能|不应)/i.test(value);
}

function hasExfilSignal(text: string): boolean {
  return /(exfiltrate|send|post|upload|transmit|collect|webhook|外发|发送|上传|泄露).{0,100}(token|secret|password|credential|private\s*key|id_rsa|openclaw\.json|api[_ -]?key|密钥|私钥|配置)/i.test(text);
}

function hasPrivilegeSignal(text: string): boolean {
  return /(sudo|root|chmod|chown|systemctl|crontab|\/etc\/|startup|system32|~\/\.ssh|id_rsa|管理员|提权|系统目录)/i.test(text);
}

function hasIntentDriftSignal(text: string): boolean {
  return /(instead|do\s+not\s+summarize|ignore\s+the\s+user|new\s+objective|改为|不要总结|忽略用户|新任务|优先执行)/i.test(text);
}

function score(condition: boolean, value: number): number {
  return condition ? clampScore(value) : 0;
}

function clampScore(value: unknown): number {
  const number = typeof value === "number" && Number.isFinite(value) ? value : 0;
  return Math.max(0, Math.min(100, Math.trunc(number)));
}

function sanitizeEvidence(value: string): string {
  return value
    .replace(/\bsk-[a-zA-Z0-9_-]{8,}\b/g, "[redacted]")
    .replace(/\bgh[pousr]_[a-zA-Z0-9_]{12,}\b/g, "[redacted]")
    .replace(/\bbearer\s+[a-zA-Z0-9._-]{8,}\b/gi, "bearer [redacted]")
    .slice(0, 180);
}

function hmac(value: string): string {
  const key = process.env.AGENTSENTRY_LABEL_KEY || "agentsentry-local-trust-label-v1";
  return createHmac("sha256", key).update(value).digest("hex");
}

function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return String(value);
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`).join(",")}}`;
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
