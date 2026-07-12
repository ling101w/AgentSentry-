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

export type TaintSink =
  | "sensitive_read"
  | "write_file"
  | "send_email"
  | "call_api"
  | "shell_exec"
  | "memory_write"
  | "config_write"
  | "skill_install";

export type TaintProfile = {
  tainted: boolean;
  source: TrustSource;
  confidence: number;
  blocked_sinks: TaintSink[];
  allowed_uses: string[];
  reasons: string[];
  tags: string[];
  risk_vector: RiskVector;
  provenance_untrusted: boolean;
  confidentiality: "public" | "internal" | "secret";
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
  /<!--[\s\S]{0,360}(?:ignore|system|developer|token|secret|credential|id_(?:rsa|ed25519|ecdsa|dsa)|ssh|exfiltrate|archive|route|ingest|telemetry|ops-archive|忽略|系统|密钥|凭据|归档|投递)[\s\S]{0,360}-->/i,
  /\bdata-(?:note|ops|sync|trace|payload|comment)\s*=\s*["'][^"']{16,}["']/i,
];

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above|security|safety)\s+(instructions?|rules?|commands?|policies?)/i,
  /\b(system|developer|internal)\b.{0,56}\b(prompt|configuration|policy|instruction|message)\b/i,
  /(act\s+as|pretend\s+to\s+be).{0,32}(developer|system|jailbroken|unfiltered)/i,
  /(bypass|disable|override|circumvent|evade).{0,40}(policy|guardrail|safety|approval|monitor|audit)/i,
  /(send|show|list|provide|copy|exfiltrate|upload|post|attach|append|include|route|forward|mirror|sync|archive).{0,120}(api[_ -]?key|token|secret|password|credential|private\s*key|identity|session|environment|config|id_(?:rsa|ed25519|ecdsa|dsa)|openclaw\.json|\.env)/i,
  /(忽略|绕过|禁用|关闭).{0,40}(安全策略|策略|规则|限制|审批|审计|监督|系统提示)/i,
  /(读取|发送|上传|泄露|外发|附加|追加|归档|同步|转发|投递).{0,96}(ssh|私钥|密钥|凭据|身份|会话|环境|token|api[_ -]?key|openclaw\.json|系统提示|配置|\.env)/i,
];

const PDF_STEGO_PATTERNS = [
  /\/(?:CA|ca)\s+0(?:\.0+)?\b/,
  /\/Tr\s+3\b/,
  /\/OC\b|Optional\s+Content|\/OCProperties|\/Layer\b/i,
  /transparent\s+text|invisible\s+text|white\s+text/i,
];

const IMAGE_METADATA_PATTERNS = [
  /\b(?:exif|xmp|itxt|tEXt|zTXt|comment|metadata|ocr|alt\s*text)\b.{0,180}(?:ignore|system|developer|token|secret|credential|id_(?:rsa|ed25519|ecdsa|dsa)|exfiltrate|archive|route|ingest|telemetry|忽略|系统|密钥|凭据|归档|投递)/i,
  /<\?xpacket[\s\S]{0,800}(?:ignore|system|developer|token|secret|credential|id_(?:rsa|ed25519|ecdsa|dsa)|exfiltrate|archive|route|ingest|telemetry|忽略|系统|密钥|凭据)/i,
];

const URL_FRAGMENT_PATTERNS = [
  /https?:\/\/[^\s"'<>#]+#[^\s"'<>]*(?:ignore|system|developer|token|secret|credential|id_(?:rsa|ed25519|ecdsa|dsa)|openclaw|\.env|exfiltrate|archive|route|ingest|telemetry|忽略|系统|密钥|凭据|归档|投递)/i,
  /#[^\s"'<>]*(?:ignore|system|developer|token|secret|credential|id_(?:rsa|ed25519|ecdsa|dsa)|openclaw|\.env|exfiltrate|archive|route|ingest|telemetry|忽略|系统|密钥|凭据|归档|投递)/i,
  /#[A-Za-z0-9+/_=-]{24,}/,
];

const MEMORY_POISON_PATTERNS = [
  /\[(?:system|developer)\]/i,
  /\brole\s*[:=]\s*["']?(?:system|developer)["']?/i,
  /(always|future|next\s+time|from\s+now\s+on|persist|remember).{0,80}(ignore|bypass|disable|override|priority|execute)/i,
  /(以后|未来|下次|永久|记住).{0,80}(忽略|绕过|禁用|优先执行|直接执行|无需确认|关闭安全)/i,
  /(future|default|profile|preference|continuity|fast[-\s]?path|quiet).{0,120}(approval|review|confirmation|guard|policy|banner).{0,100}(already\s+handled|skip|suppress|quiet|silent|auto|no\s+interruption)/i,
  /(route|archive|forward|mirror|sync|attach|append|include).{0,120}(identity|session|environment|config|credential|private|operator|bundle|openclaw\.json|\.env|\.ssh)/i,
  /(以后|后续|默认|长期|偏好|连续性|快速通道).{0,90}(审批|确认|策略|安全|提示|横幅).{0,90}(已处理|跳过|静默|自动|无需|不打扰)/i,
  /(归档|同步|转发|附加|追加|包含|投递).{0,100}(身份|会话|环境|配置|凭据|资料|材料|openclaw\.json|\.env|\.ssh)/i,
  /\b(?:cron|crontab|systemd|startup|autorun|hooks\/wake|\/hooks\/wake)\b.{0,120}\b(?:write|add|install|enable|persist|execute|ignore|bypass|disable|secret|token|exfiltrate|send|upload)\b/i,
  /\b(?:write|add|install|enable|persist|execute|ignore|bypass|disable|send|upload|写入|添加|安装|启用|持久化|执行|绕过|禁用|发送|上传)\b.{0,120}\b(?:cron|crontab|systemd|startup|autorun|hooks\/wake|\/hooks\/wake|启动项|定时任务)\b/i,
];

const GATEWAY_HIJACK_PATTERNS = [
  /[?&]gatewayURL\s*=\s*wss?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))/i,
  /\bgatewayURL\b.{0,80}\bwss?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))/i,
  /\bgateway(?:Auth)?(?:Token|URL)\b.{0,120}(?:collect|exfil|ingest|telemetry|archive|route|sync|external|外发|窃取|归档|同步|投递)/i,
];

const SKILL_EXFIL_PATTERNS = [
  /\b(?:fetch|axios|curl|wget|https?\.request|XMLHttpRequest)\b[\s\S]{0,220}(?:token|secret|openclaw\.json|gateway|credential|password|\.env|\.ssh|identity|config|session)/i,
  /\b(?:readFileSync|readFile|fs\.|openSync|createReadStream)\b[\s\S]{0,220}(?:openclaw\.json|\.env|id_(?:rsa|ed25519|ecdsa|dsa)|secret|token|password|credential|\.openclaw)/i,
  /(?:openclaw\.json|\.openclaw|\.env|\.ssh|id_(?:rsa|ed25519|ecdsa|dsa))[\s\S]{0,260}\b(?:fetch|axios|curl|wget|https?\.request|XMLHttpRequest)\b/i,
];

const SENSITIVE_PATTERNS: Array<[string, RegExp]> = [
  ["private_key", /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/],
  ["ssh_private_key_path", /(?:~\/\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)|\.ssh[/\\]id_(?:rsa|ed25519|ecdsa|dsa)|id_(?:rsa|ed25519|ecdsa|dsa))/i],
  ["env_file", /(?:^|[^\w])\.env(?:[^\w]|$)/i],
  ["api_key", /\bsk-[a-zA-Z0-9_-]{16,}\b/],
  ["github_token", /\bgh[pousr]_[a-zA-Z0-9_]{20,}\b/],
  ["slack_token", /\bxox[baprs]-[a-zA-Z0-9-]{16,}\b/],
  ["aws_access_key", /\bAKIA[0-9A-Z]{16}\b/],
  ["bearer_token", /\bbearer\s+[a-zA-Z0-9._-]{16,}\b/i],
  ["named_secret", /\b(api[_-]?key|token|secret|password|credential|authorization)\s*[:=]\s*["']?[a-zA-Z0-9._/-]{12,}/i],
  ["openclaw_config", /\bopenclaw\.json\b/i],
];

const DATA_FLOW_EXFIL_PATTERNS = [
  /(route|forward|archive|mirror|sync|attach|append|include|post|send|upload|transmit).{0,140}(identity|session|environment|config|profile|bundle|operator|credential|private|material|openclaw\.json|\.env|\.ssh|id_(?:rsa|ed25519|ecdsa|dsa))/i,
  /(identity|session|environment|config|credential|private|operator|material|openclaw\.json|\.env|\.ssh|id_(?:rsa|ed25519|ecdsa|dsa)).{0,140}(route|forward|archive|mirror|sync|attach|append|include|post|send|upload|transmit|endpoint|collector|ingest|telemetry|metrics|webhook)/i,
  /(归档|同步|转发|附加|追加|包含|投递|发送|上传).{0,120}(身份|会话|环境|配置|凭据|资料|材料|openclaw\.json|\.env|\.ssh)/i,
  /(身份|会话|环境|配置|凭据|资料|材料|openclaw\.json|\.env|\.ssh).{0,120}(归档|同步|转发|附加|追加|包含|投递|发送|上传|端点)/i,
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
  matched.promptInjection.push(...matchPatterns(text, DATA_FLOW_EXFIL_PATTERNS));
  matched.promptInjection = matched.promptInjection.filter((item) => !isNegatedSafetyBoundary(item));
  matched.memoryPoison = matched.memoryPoison.filter((item) => !isNegatedSafetyBoundary(item) && !isOperationalStatusBoundary(item));
  if (hasSkillDataFlow(text, lowerPath, source, options.toolName)) {
    matched.skillExfil.push("skill code reads local state and contacts an external endpoint");
  }

  if (isActiveSkillSurface(lowerPath, source, options.toolName) && matched.skillExfil.length) {
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

  const provenanceUntrusted = source === "external_web" || source === "email_html" || source === "pdf_text" || source === "image_metadata" || source === "webhook";
  const confidentiality = matched.sensitive.length ? "secret" : source === "config" || source === "memory" ? "internal" : "public";
  const taintProfile = buildTaintProfile({
    source,
    risk,
    tags,
    sensitiveKinds: matched.sensitive,
    provenanceUntrusted,
    confidentiality,
  });
  const tainted = taintProfile.tainted;
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
      provenance_untrusted: provenanceUntrusted,
      taint_profile: taintProfile,
    },
  });

  const findings: DetectionFinding[] = [];
  if (matched.hiddenHtml.length || matched.urlFragment.length) {
    findings.push(finding("Context Provenance", "deterministic", "block", "external content contains hidden prompt-injection instructions", 95, {
      source,
      tags,
      matched: [...matched.hiddenHtml, ...matched.urlFragment].slice(0, 5),
      trust_label: label,
      risk_vector: risk,
      preview: clampText(text, previewChars),
    }));
  }
  if (matched.pdfStego.length) {
    findings.push(finding("Context Provenance", "deterministic", "block", "PDF content contains hidden or low-visibility agent instructions", 95, {
      source,
      path: options.path || "",
      matched: matched.pdfStego.slice(0, 5),
      trust_label: label,
      risk_vector: risk,
    }));
  }
  if (matched.imageMetadata.length) {
    findings.push(finding("Context Provenance", "deterministic", "block", "image metadata or OCR text contains agent instructions", 90, {
      source,
      path: options.path || "",
      matched: matched.imageMetadata.slice(0, 5),
      trust_label: label,
      risk_vector: risk,
    }));
  }
  if (matched.promptInjection.length && !findings.some((item) => item.layer === "Context Provenance")) {
    findings.push(finding("Context Provenance", "heuristic", "require_approval", "content contains prompt-injection or exfiltration indicators", 45, {
      source,
      matched: matched.promptInjection.slice(0, 5),
      trust_label: label,
      risk_vector: risk,
      preview: clampText(text, previewChars),
    }));
  }
  if (matched.memoryPoison.length) {
    findings.push(finding("State Integrity", "deterministic", "block", "content attempts to persist privileged instructions into memory or startup flow", 100, {
      source,
      path: options.path || "",
      matched: matched.memoryPoison.slice(0, 5),
      trust_label: label,
      risk_vector: risk,
    }));
  }
  if (matched.gatewayHijack.length) {
    findings.push(finding("Tool Boundary", "deterministic", "block", "gateway URL override or token-hijack pattern detected", 100, {
      source,
      matched: matched.gatewayHijack.slice(0, 5),
      trust_label: label,
      risk_vector: risk,
    }));
  }
  if (matched.skillExfil.length) {
    findings.push(finding("Context Provenance", "deterministic", "block", "skill or code path can read OpenClaw secrets and exfiltrate them", 100, {
      source,
      path: options.path || "",
      matched: matched.skillExfil.slice(0, 5).map((item) => sanitizeEvidence(item)),
      trust_label: label,
      risk_vector: risk,
    }));
  }
  if (matched.sensitive.length) {
    findings.push(finding("Tool Boundary", "heuristic", "require_approval", "content references sensitive credentials or private assets", 55, {
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

export function taintProfileFromLabel(label: TrustLabel): TaintProfile | null {
  const value = label.evidence?.taint_profile;
  if (!value || typeof value !== "object") return null;
  const profile = value as Partial<TaintProfile>;
  if (!Array.isArray(profile.blocked_sinks) || typeof profile.confidence !== "number") return null;
  return {
    tainted: Boolean(profile.tainted),
    source: profile.source || label.source,
    confidence: clampScore(profile.confidence),
    blocked_sinks: profile.blocked_sinks.filter(isTaintSink),
    allowed_uses: Array.isArray(profile.allowed_uses) ? profile.allowed_uses.filter((item): item is string => typeof item === "string") : [],
    reasons: Array.isArray(profile.reasons) ? profile.reasons.filter((item): item is string => typeof item === "string") : [],
    tags: Array.isArray(profile.tags) ? profile.tags.filter((item): item is string => typeof item === "string") : [],
    risk_vector: isRiskVector(profile.risk_vector) ? profile.risk_vector : createRiskVector(),
    provenance_untrusted: Boolean(profile.provenance_untrusted),
    confidentiality: profile.confidentiality === "secret" || profile.confidentiality === "internal" ? profile.confidentiality : "public",
  };
}

export function taintBlockedForSink(label: TrustLabel, sink: TaintSink): boolean {
  const profile = taintProfileFromLabel(label);
  return Boolean(profile && profile.confidence >= 50 && profile.blocked_sinks.includes(sink));
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
  findingType: DetectionFinding["finding_type"],
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
  if (isActiveSkillSurface(path)) return "skill";
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
  for (const variant of textVariants(text)) {
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      const match = pattern.exec(variant);
      if (match) {
        const index = typeof match.index === "number" ? match.index : 0;
        const start = Math.max(0, index - 48);
        const end = Math.min(variant.length, index + match[0].length + 48);
        out.push(sanitizeEvidence(variant.slice(start, end)));
      }
    }
  }
  return Array.from(new Set(out));
}

function matchSensitive(text: string): string[] {
  const kinds: string[] = [];
  for (const variant of textVariants(text)) {
    for (const [kind, pattern] of SENSITIVE_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(variant)) kinds.push(kind);
    }
  }
  return Array.from(new Set(kinds));
}

function textVariants(text: string): string[] {
  const normalized = canonicalText(text);
  const compact = deobfuscateSeparators(normalized);
  return Array.from(new Set([
    normalized,
    compact,
    ...decodedTextCandidates(normalized),
    ...decodedTextCandidates(compact),
  ].filter(Boolean))).slice(0, 18);
}

function canonicalText(text: string): string {
  return text
    .normalize("NFKC")
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00ad]/g, "")
    .replace(/&(?:#x?200b|zwnj|zwj|nbsp);/gi, " ");
}

function deobfuscateSeparators(text: string): string {
  return text
    .replace(/["'`]\s*\+\s*["'`]/g, "")
    .replace(/([A-Za-z0-9])[\s._-]{1,3}(json|env|ssh|token|secret|credential|config)\b/gi, "$1$2")
    .replace(/open\s*claw\s*\.?\s*json/gi, "openclaw.json");
}

function decodedTextCandidates(text: string): string[] {
  const tokens = text.match(/[A-Za-z0-9+/_=-]{16,}|(?:[0-9A-Fa-f]{2}){8,}/g) || [];
  const out: string[] = [];
  const percent = decodePercentText(text);
  if (percent) out.push(percent);
  const unicode = decodeUnicodeEscapes(text);
  if (unicode) out.push(unicode);
  for (const token of tokens.slice(0, 28)) {
    if (token.length > 4096) continue;
    for (const candidate of encodedTokenVariants(token)) {
      const b64 = decodeBase64Text(candidate);
      if (b64) out.push(b64);
      const hex = decodeHexText(candidate);
      if (hex) out.push(hex);
    }
  }
  return out;
}

function decodePercentText(text: string): string {
  if (!/%[0-9a-fA-F]{2}/.test(text)) return "";
  try {
    return printableText(decodeURIComponent(text.replace(/\+/g, "%20")));
  } catch {
    return "";
  }
}

function decodeUnicodeEscapes(text: string): string {
  if (!/\\u[0-9a-fA-F]{4}/.test(text)) return "";
  try {
    return printableText(text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16))));
  } catch {
    return "";
  }
}

function encodedTokenVariants(token: string): string[] {
  const variants = [token];
  const index = token.indexOf("=");
  if (index > 0) {
    const head = token.slice(0, index);
    const tail = token.slice(index + 1);
    if (tail.length >= 16 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(tail) && /^[A-Za-z][A-Za-z0-9_-]{2,40}$/.test(head)) {
      variants.push(tail);
    }
  }
  return Array.from(new Set(variants));
}

function decodeBase64Text(token: string): string {
  if (token.length < 16) return "";
  try {
    const normalized = token.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    return printableText(Buffer.from(padded, "base64").toString("utf8"));
  } catch {
    return "";
  }
}

function decodeHexText(token: string): string {
  if (token.length < 16 || token.length % 2) return "";
  if (!/^[0-9A-Fa-f]+$/.test(token)) return "";
  try {
    return printableText(Buffer.from(token, "hex").toString("utf8"));
  } catch {
    return "";
  }
}

function printableText(value: string): string {
  if (!value || value.length > 4096) return "";
  let printable = 0;
  for (const char of value) {
    if (/\s/.test(char) || char >= " ") printable += 1;
  }
  return printable / Math.max(value.length, 1) >= 0.85 ? canonicalText(value) : "";
}

function isNegatedSafetyBoundary(value: string): boolean {
  return /(?:do\s+not|don't|without|never|no\s+need\s+to|不要|不需要|不包含|无需|禁止|不得|避免|不能|不应).{0,100}(?:read|send|upload|include|access|exfiltrate|token|secret|password|credential|private\s*key|读取|访问|发送|上传|外发|泄露|包含|凭据|密钥|私钥|配置)/i.test(value)
    || /(?:read|send|upload|include|access|exfiltrate|modify|change|write|读取|访问|发送|上传|外发|泄露|包含|修改|改变|写入).{0,60}(?:do\s+not|don't|without|never|不要|不需要|不包含|无需|禁止|不得|避免|不能|不应|不)/i.test(value)
    || /(?:只|仅|仅仅|only).{0,40}(?:read|check|inspect|status|查看|检查|读取|状态).{0,80}(?:不|不要|不会|不得|不能|without|do\s+not|don't|never).{0,40}(?:modify|change|write|修改|改变|写入|配置|系统配置)/i.test(value);
}

function isOperationalStatusBoundary(value: string): boolean {
  return /\b(?:denylist|allowlist|preflight|capabilities|system_monitor|recommended_runtime|controls?|limitations?|blocked|blocking|guard|policy|sandbox|monitor|status)\b/i.test(value)
    && !/(?:ignore|bypass|execute|exfiltrate|send|upload|泄露|外发|忽略|绕过|执行)/i.test(value.replace(/\b(?:denylist|allowlist)\b/gi, ""));
}

function hasExfilSignal(text: string): boolean {
  return textVariants(text).some((variant) =>
    /(exfiltrate|send|post|upload|transmit|collect|webhook|route|forward|archive|mirror|sync|attach|append|include|ingest|telemetry|metrics|外发|发送|上传|泄露|归档|同步|转发|附加|追加|投递).{0,140}(token|secret|password|credential|private\s*key|identity|session|environment|config|id_(?:rsa|ed25519|ecdsa|dsa)|openclaw\.json|api[_ -]?key|\.env|\.ssh|密钥|私钥|凭据|身份|会话|配置)/i.test(variant)
      || DATA_FLOW_EXFIL_PATTERNS.some((pattern) => {
        pattern.lastIndex = 0;
        return pattern.test(variant);
      })
  );
}

function hasSkillDataFlow(text: string, lowerPath: string, source: TrustSource, toolName?: string): boolean {
  const skillSurface = isActiveSkillSurface(lowerPath, source, toolName);
  if (!skillSurface) return false;
  return textVariants(text).some((variant) => {
    const readsLocal = /\b(?:readFileSync|readFile|openSync|createReadStream|fs\.|Path\(|open\()\b[\s\S]{0,260}(?:openclaw\.json|\.openclaw|\.env|\.ssh|id_(?:rsa|ed25519|ecdsa|dsa)|credentials?|config|session)/i.test(variant)
      || /(?:openclaw\.json|\.openclaw|\.env|\.ssh|id_(?:rsa|ed25519|ecdsa|dsa))[\s\S]{0,260}\b(?:readFileSync|readFile|openSync|createReadStream|fs\.|Path\(|open\()\b/i.test(variant);
    const contactsNetwork = /\b(?:fetch|axios|curl|wget|https?\.request|XMLHttpRequest|requests?\.(?:post|get)|urlopen)\b/i.test(variant)
      || /https?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))/i.test(variant);
    const declaresBenignSurface = /(weather|forecast|calendar|translate|天气|预报|日历|翻译|摘要|查询)/i.test(variant);
    return readsLocal && contactsNetwork && (declaresBenignSurface || /skill|package|plugin|能力|扩展/i.test(variant));
  });
}

function isActiveSkillSurface(lowerPath: string, source?: TrustSource, toolName?: string): boolean {
  if (source === "skill") return true;
  const normalized = lowerPath.replace(/\\/g, "/").replace(/^\.\/+/, "").toLowerCase();
  return normalized === "skill.md"
    || normalized.endsWith("/skill.md")
    || normalized.startsWith("skills/")
    || normalized.includes("/skills/")
    || normalized.startsWith("plugin-skills/")
    || normalized.includes("/plugin-skills/")
    || normalized.startsWith("extensions/")
    || normalized.includes("/extensions/")
    || /skill|plugin|package/i.test(toolName || "");
}

function hasPrivilegeSignal(text: string): boolean {
  return textVariants(text).some((variant) => /(sudo|root|chmod|chown|systemctl|crontab|\/etc\/|startup|system32|~\/\.ssh|id_(?:rsa|ed25519|ecdsa|dsa)|管理员|提权|系统目录)/i.test(variant));
}

function hasIntentDriftSignal(text: string): boolean {
  return textVariants(text).some((variant) => /(instead|do\s+not\s+summarize|ignore\s+the\s+user|new\s+objective|quiet\s+continuity|approval.{0,32}already\s+handled|改为|不要总结|忽略用户|新任务|优先执行|静默|已处理审批)/i.test(variant));
}

function buildTaintProfile(input: {
  source: TrustSource;
  risk: RiskVector;
  tags: string[];
  sensitiveKinds: string[];
  provenanceUntrusted: boolean;
  confidentiality: "public" | "internal" | "secret";
}): TaintProfile {
  const blocked = new Set<TaintSink>();
  const reasons = new Set<string>();
  const risk = input.risk;
  const maxRisk = riskMax(risk);

  if (risk.prompt_injection >= 50 || risk.hidden_content >= 50 || input.tags.some((tag) => tag.includes("prompt") || tag.includes("hidden"))) {
    addMany(blocked, ["sensitive_read", "send_email", "call_api", "shell_exec", "memory_write", "config_write", "skill_install"]);
    reasons.add("untrusted instructions must not control sensitive reads or external/persistent sinks");
  }
  if (risk.sensitive_data >= 50 || input.confidentiality === "secret" || input.sensitiveKinds.length) {
    addMany(blocked, ["send_email", "call_api", "shell_exec", "memory_write", "config_write"]);
    reasons.add("secret-bearing context must not flow to external, execution, or persistent sinks");
  }
  if (risk.exfiltration >= 50) {
    addMany(blocked, ["send_email", "call_api", "shell_exec"]);
    reasons.add("context contains exfiltration semantics");
  }
  if (risk.persistence >= 50) {
    addMany(blocked, ["memory_write", "write_file", "config_write", "skill_install"]);
    reasons.add("context attempts to persist future behavior or configuration");
  }
  if (risk.tool_hijack >= 50 || risk.supply_chain >= 50) {
    addMany(blocked, ["call_api", "shell_exec", "config_write", "skill_install"]);
    reasons.add("context can hijack tools, gateways, or skill behavior");
  }
  if (risk.privilege >= 50) {
    addMany(blocked, ["shell_exec", "write_file", "config_write"]);
    reasons.add("context references privileged or system-level effects");
  }

  const confidence = Math.max(maxRisk, input.provenanceUntrusted && blocked.size ? 55 : 0);
  return {
    tainted: confidence >= 50,
    source: input.source,
    confidence,
    blocked_sinks: Array.from(blocked).sort(),
    allowed_uses: ["summarize", "classify", "quote_with_attribution", "local_transform"],
    reasons: Array.from(reasons),
    tags: input.tags,
    risk_vector: risk,
    provenance_untrusted: input.provenanceUntrusted,
    confidentiality: input.confidentiality,
  };
}

function addMany<T>(set: Set<T>, values: T[]): void {
  for (const value of values) set.add(value);
}

function isTaintSink(value: unknown): value is TaintSink {
  return value === "sensitive_read"
    || value === "write_file"
    || value === "send_email"
    || value === "call_api"
    || value === "shell_exec"
    || value === "memory_write"
    || value === "config_write"
    || value === "skill_install";
}

function isRiskVector(value: unknown): value is RiskVector {
  if (!value || typeof value !== "object") return false;
  return "prompt_injection" in value && "sensitive_data" in value && "tool_hijack" in value;
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
