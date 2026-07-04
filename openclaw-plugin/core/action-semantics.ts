import type { PluginConfig } from "../config.ts";
import type { DetectionFinding } from "./detect.ts";
import { clampText, safeStringify } from "./redact.ts";

type SemanticFact = {
  path: string;
  value: string;
  variants: string[];
};

type SemanticGraph = {
  operations: string[];
  sensitiveSources: string[];
  externalSinks: string[];
  persistenceTargets: string[];
  privilegedEffects: string[];
  encodings: string[];
  benignClaims: string[];
  localReads: string[];
  networkWrites: string[];
};

const SENSITIVE_SOURCE_PATTERNS = [
  /(?:^|[^\w])\.env(?:[^\w]|$)/i,
  /\bopenclaw\.json\b/i,
  /(?:~\/|\/)?\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)\b/i,
  /\bid_(?:rsa|ed25519|ecdsa|dsa)\b/i,
  /\/etc\/(?:shadow|gshadow|sudoers)\b/i,
  /\/\.aws\/credentials\b/i,
  /\/\.kube\/config\b/i,
  /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/i,
  /\b(?:api[_-]?key|token|secret|password|credential)\s*[:=]\s*["']?[a-zA-Z0-9._/-]{12,}/i,
  /\b(?:sk-[a-zA-Z0-9_-]{16,}|gh[pousr]_[a-zA-Z0-9_]{20,}|AKIA[0-9A-Z]{16})\b/i,
];

const EXTERNAL_SINK_PATTERNS = [
  /\bhttps?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))[^\s"'<>)]{3,}/i,
  /\bwss?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))[^\s"'<>)]{3,}/i,
  /\b[A-Z0-9._%+-]+@(?!example\.com\b|localhost\b)[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
];

const NETWORK_WRITE_PATTERNS = [
  /\b(?:fetch|axios|XMLHttpRequest|https?\.request|requests?\.(?:post|put|get)|urlopen)\b/i,
  /\b(?:curl|wget|scp|rsync|nc|ncat|socat)\b/i,
  /\b(?:post|upload|send|forward|route|archive|sync|mirror|ingest|telemetry|webhook|callback)\b/i,
  /(发送|上传|外发|转发|同步|归档|投递|回调|遥测)/i,
];

const LOCAL_READ_PATTERNS = [
  /\b(?:readFileSync|readFile|openSync|createReadStream|fs\.|Path\(|open\()\b/i,
  /\b(?:cat|type|Get-Content)\s+["']?(?:~\/|\/|\.)/i,
  /(读取|打开|加载).{0,40}(文件|配置|凭据|密钥|私钥)/i,
];

const PERSISTENCE_PATTERNS = [
  /\b(?:crontab|cron\.d|systemd|startup|LaunchAgents|LaunchDaemons|autorun|hooks\/wake|\/hooks\/wake)\b/i,
  /\b(?:MEMORY\.md|AGENTS\.md|SHELL\.md|openclaw\.json|skill\.md)\b/i,
  /(长期记忆|启动项|定时任务|持久化|开机启动|自动运行)/i,
];

const PRIVILEGE_PATTERNS = [
  /\b(?:sudo|su\s+-|chmod|chown|iptables|ufw|systemctl\s+(?:start|restart|stop|reload|enable|disable|edit|daemon-reload|mask|unmask)|service\s+(?:start|restart|stop|reload|enable|disable)|mount|umount|setcap)\b/i,
  /\b(?:rm\s+-rf|dd\s+.*\bof=\/dev\/|mkfs\.|shutdown|reboot)\b/i,
  /(提权|管理员|系统目录|禁用防火墙|修改权限|删除系统)/i,
];

const OPERATION_PATTERNS: Array<[string, RegExp]> = [
  ["read", /\b(?:read|open|load|cat|type|Get-Content|读取|打开|加载)\b/i],
  ["write", /\b(?:write|save|append|patch|create|tee|写入|保存|追加|创建|修改)\b/i],
  ["send", /\b(?:send|email|mail|post|upload|forward|route|archive|sync|mirror|发送|邮件|上传|外发|转发|归档|同步)\b/i],
  ["execute", /\b(?:exec|shell|command|terminal|run|bash|sh|powershell|执行|运行|命令)\b/i],
  ["persist", /\b(?:remember|memory|persist|cron|startup|systemd|记住|记忆|持久|启动项|定时)\b/i],
];

const BENIGN_CLAIM_PATTERNS = [
  /\b(?:weather|forecast|calendar|translate|calculator|summarizer|notes?|formatter|search|reader)\b/i,
  /(天气|预报|日历|翻译|计算器|摘要|格式化|搜索|阅读器|查询)/i,
];

export function semanticActionFindings(
  toolName: string,
  params: Record<string, unknown>,
  config: PluginConfig,
): { findings: DetectionFinding[]; risk: number; graph: SemanticGraph } {
  const facts = collectFacts(params);
  const graph = buildGraph(toolName, facts);
  const findings: DetectionFinding[] = [];

  const hasSensitiveSource = graph.sensitiveSources.length > 0;
  const hasExternalSink = graph.externalSinks.length > 0 || toolNameLooksLikeExternalSink(toolName);
  const hasNetworkWrite = graph.networkWrites.length > 0 || toolNameLooksLikeExternalSink(toolName);
  const hasLocalRead = graph.localReads.length > 0 || /\bread[_-]?file\b|filesystem.*read/i.test(toolName);
  const hasPrivilegedEffect = graph.privilegedEffects.length > 0;
  const isMemoryTool = /memory|remember|webhook|wake/i.test(toolName);
  const readOnlySkillDocLookup = isReadOnlyInstalledSkillDocLookup(toolName, params);
  const hasExplicitPersistence = graph.persistenceTargets.length > 0 && !readOnlySkillDocLookup;
  const hasPersistence = hasExplicitPersistence || isMemoryTool;
  const declaredBenign = graph.benignClaims.length > 0;
  let risk = 0;

  if (hasSensitiveSource && hasExternalSink && hasNetworkWrite) {
    risk += 95;
    findings.push(finding("Semantic Action Graph", "deterministic", "block", "semantic action graph shows sensitive source can flow to an external sink", 100, {
      toolName,
      sources: graph.sensitiveSources.slice(0, 6),
      sinks: graph.externalSinks.slice(0, 6),
      operations: graph.operations,
      encodings: graph.encodings,
    }, config));
  }

  if (declaredBenign && hasLocalRead && hasNetworkWrite && (hasSensitiveSource || graph.externalSinks.length > 0)) {
    risk += 90;
    findings.push(finding("Context Provenance", "deterministic", "block", "declared benign tool capability conflicts with local read plus network egress behavior", 100, {
      toolName,
      benignClaims: graph.benignClaims.slice(0, 5),
      localReads: graph.localReads.slice(0, 5),
      networkWrites: graph.networkWrites.slice(0, 5),
      sensitiveSources: graph.sensitiveSources.slice(0, 5),
    }, config));
  }

  if ((hasExplicitPersistence || (isMemoryTool && hasSensitiveSource && hasExternalSink)) && (hasPrivilegedEffect || hasSensitiveSource || hasExternalSink)) {
    risk += 60;
    findings.push(finding("State Integrity", "deterministic", "block", "semantic action graph combines persistence with privileged, sensitive, or external side effects", 90, {
      toolName,
      persistenceTargets: graph.persistenceTargets.slice(0, 6),
      privilegedEffects: graph.privilegedEffects.slice(0, 6),
      sensitiveSources: graph.sensitiveSources.slice(0, 6),
      externalSinks: graph.externalSinks.slice(0, 6),
    }, config));
  } else if (hasExplicitPersistence || hasPrivilegedEffect) {
    risk += 35;
    findings.push(finding("Tool Boundary", "heuristic", "require_approval", "semantic action graph contains persistence or privileged side effects", 45, {
      toolName,
      persistenceTargets: graph.persistenceTargets.slice(0, 6),
      privilegedEffects: graph.privilegedEffects.slice(0, 6),
      operations: graph.operations,
    }, config));
  }

  if (graph.encodings.length && (hasSensitiveSource || hasExternalSink || hasPersistence || hasPrivilegedEffect)) {
    risk += 40;
    findings.push(finding("Context Provenance", "heuristic", "require_approval", "encoded parameter content expands to security-sensitive behavior", 45, {
      toolName,
      encodings: graph.encodings.slice(0, 8),
      sources: graph.sensitiveSources.slice(0, 5),
      sinks: graph.externalSinks.slice(0, 5),
      persistenceTargets: graph.persistenceTargets.slice(0, 5),
      privilegedEffects: graph.privilegedEffects.slice(0, 5),
    }, config));
  }

  return { findings: dedupeFindings(findings), risk: Math.min(risk, 150), graph };
}

function isReadOnlyInstalledSkillDocLookup(toolName: string, params: Record<string, unknown>): boolean {
  const tool = toolName.toLowerCase();
  if (/write|delete|remove|move|chmod|chown|exec|shell|command|terminal|powershell|cmd/.test(tool)) return false;
  const text = safeStringify(params).replace(/\\/g, "/").toLowerCase();
  return /(?:^|[~/"'\s])\.openclaw\/(?:plugin-skills\/[^/]+|tools\/node-[^/]+\/lib\/node_modules\/openclaw\/skills\/[^/]+)\/skill\.md(?:["'\s]|$)/i.test(text);
}

function collectFacts(value: unknown, path = ""): SemanticFact[] {
  const facts: SemanticFact[] = [];
  if (typeof value === "string") {
    facts.push({ path, value, variants: textVariants(value) });
    return facts;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => facts.push(...collectFacts(item, `${path}[${index}]`)));
    return facts;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      const nextPath = path ? `${path}.${key}` : key;
      if (typeof item === "string") {
        facts.push({ path: nextPath, value: item, variants: textVariants(`${key}: ${item}`) });
      } else {
        facts.push(...collectFacts(item, nextPath));
      }
    }
    return facts;
  }
  if (value !== undefined && value !== null) {
    const text = String(value);
    facts.push({ path, value: text, variants: textVariants(text) });
  }
  return facts;
}

function buildGraph(toolName: string, facts: SemanticFact[]): SemanticGraph {
  const graph: SemanticGraph = {
    operations: [],
    sensitiveSources: [],
    externalSinks: [],
    persistenceTargets: [],
    privilegedEffects: [],
    encodings: [],
    benignClaims: [],
    localReads: [],
    networkWrites: [],
  };
  const toolText = textVariants(toolName).join("\n");
  collectOperations(toolText, graph);
  for (const fact of facts) {
    for (const variant of fact.variants) {
      collectOperations(variant, graph);
      collectMatches(variant, fact.path, graph.sensitiveSources, SENSITIVE_SOURCE_PATTERNS);
      collectMatches(variant, fact.path, graph.externalSinks, EXTERNAL_SINK_PATTERNS);
      collectMatches(variant, fact.path, graph.persistenceTargets, PERSISTENCE_PATTERNS);
      collectMatches(variant, fact.path, graph.privilegedEffects, PRIVILEGE_PATTERNS);
      collectMatches(variant, fact.path, graph.localReads, LOCAL_READ_PATTERNS);
      collectMatches(variant, fact.path, graph.networkWrites, NETWORK_WRITE_PATTERNS);
      collectMatches(variant, fact.path, graph.benignClaims, BENIGN_CLAIM_PATTERNS);
    }
    if (fact.variants.length > 1) {
      const original = canonicalText(fact.value);
      const decoded = fact.variants.slice(1).filter((variant) => variant !== original);
      if (decoded.some(decodedVariantHasSecuritySignal)) graph.encodings.push(`${fact.path || "<root>"}:decoded`);
    }
  }
  return {
    operations: unique(graph.operations),
    sensitiveSources: unique(graph.sensitiveSources),
    externalSinks: unique(graph.externalSinks),
    persistenceTargets: unique(graph.persistenceTargets),
    privilegedEffects: unique(graph.privilegedEffects),
    encodings: unique(graph.encodings),
    benignClaims: unique(graph.benignClaims),
    localReads: unique(graph.localReads),
    networkWrites: unique(graph.networkWrites),
  };
}

function decodedVariantHasSecuritySignal(text: string): boolean {
  return SENSITIVE_SOURCE_PATTERNS.some((pattern) => {
    pattern.lastIndex = 0;
    return pattern.test(text);
  })
    || PERSISTENCE_PATTERNS.some((pattern) => {
      pattern.lastIndex = 0;
      return pattern.test(text);
    })
    || PRIVILEGE_PATTERNS.some((pattern) => {
      pattern.lastIndex = 0;
      return pattern.test(text);
    })
    || LOCAL_READ_PATTERNS.some((pattern) => {
      pattern.lastIndex = 0;
      return pattern.test(text);
    });
}

function collectOperations(text: string, graph: SemanticGraph): void {
  for (const [name, pattern] of OPERATION_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) graph.operations.push(name);
  }
}

function collectMatches(text: string, path: string, out: string[], patterns: RegExp[]): void {
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    const match = pattern.exec(text);
    if (match) out.push(`${path || "<root>"}:${match[0].slice(0, 160)}`);
  }
}

function toolNameLooksLikeExternalSink(toolName: string): boolean {
  return /send.*mail|email|mail|api|http|fetch|request|curl|wget|webhook|browser/i.test(toolName);
}

function textVariants(text: string): string[] {
  const normalized = canonicalText(text);
  const compact = deobfuscateSeparators(normalized);
  return unique([
    normalized,
    compact,
    ...decodedTextCandidates(normalized),
    ...decodedTextCandidates(compact),
  ].filter(Boolean)).slice(0, 20);
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
  const out: string[] = [];
  const percent = decodePercentText(text);
  if (percent) out.push(percent);
  const unicode = decodeUnicodeEscapes(text);
  if (unicode) out.push(unicode);
  const tokens = text.match(/[A-Za-z0-9+/_=-]{16,}|(?:[0-9A-Fa-f]{2}){8,}/g) || [];
  for (const token of tokens.slice(0, 28)) {
    if (token.length > 4096) continue;
    for (const candidate of encodedTokenVariants(token)) {
      const b64 = decodeBase64Text(candidate);
      if (b64) out.push(b64);
      const hex = decodeHexText(candidate);
      if (hex) out.push(hex);
    }
  }
  return unique(out);
}

function encodedTokenVariants(token: string): string[] {
  const variants = [token];
  const index = token.indexOf("=");
  if (index > 0) {
    const tail = token.slice(index + 1);
    if (tail.length >= 16 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(tail)) variants.push(tail);
  }
  return unique(variants);
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

function finding(
  layer: string,
  findingType: "deterministic" | "heuristic" | "learned",
  verdict: "pass" | "require_approval" | "block",
  reason: string,
  score: number,
  evidence: Record<string, unknown>,
  config: PluginConfig,
): DetectionFinding {
  return {
    layer,
    finding_type: findingType,
    verdict,
    reason,
    score,
    evidence: clampEvidence(evidence, config),
  };
}

function clampEvidence(evidence: Record<string, unknown>, config: PluginConfig): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(evidence)) {
    if (typeof value === "string") out[key] = clampText(value, config.capture.previewChars);
    else if (Array.isArray(value)) out[key] = value.slice(0, 12).map((item) => typeof item === "string" ? clampText(item, 240) : item);
    else out[key] = value;
  }
  return out;
}

function dedupeFindings(findings: DetectionFinding[]): DetectionFinding[] {
  const seen = new Set<string>();
  const out: DetectionFinding[] = [];
  for (const item of findings) {
    const key = `${item.layer}:${item.reason}:${safeStringify(item.evidence).slice(0, 240)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}
