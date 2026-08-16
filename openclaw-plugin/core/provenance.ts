import { watch, type FSWatcher } from "node:fs";
import { opendir, readFile, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, extname, join, relative } from "node:path";
import type { PluginConfig } from "../config.ts";
import type { DetectionFinding } from "./detect.ts";
import { interventionEvidence } from "./policy/intervention-gate.ts";
import { clampText } from "./redact.ts";
import { analyzeTrustContent } from "./trust.ts";

export type ProvenanceScanResult = {
  workspaceDir: string;
  scannedFiles: number;
  skippedFiles: number;
  findings: DetectionFinding[];
  blocked: boolean;
  cached: boolean;
  changedFiles: number;
};

type CachedFile = {
  size: string;
  mtimeNs: string;
  hash: string;
  findings: DetectionFinding[];
};

type CachedWorkspace = {
  scannedAt: number;
  configSignature: string;
  files: Map<string, CachedFile>;
  dirty: Set<string>;
  watcher: FSWatcher | null;
};

const scanCache = new Map<string, CachedWorkspace>();

const SKIP_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "attacks",
  "attack-samples",
  "benchmarks",
  "fixtures",
  "node_modules",
  "dist",
  "build",
  ".venv",
  "venv",
  "__pycache__",
  ".pytest_cache",
  ".playwright-mcp",
]);

const TEXT_EXTENSIONS = new Set([
  ".md",
  ".txt",
  ".json",
  ".json5",
  ".yaml",
  ".yml",
  ".toml",
  ".ini",
  ".cfg",
  ".env",
  ".ts",
  ".js",
  ".mjs",
  ".cjs",
  ".py",
  ".sh",
  ".ps1",
  ".html",
  ".htm",
  ".pdf",
  ".png",
  ".jpg",
  ".jpeg",
  ".webp",
]);

const SENSITIVE_FILE_NAMES = [
  ".env",
  ".env.local",
  ".env.production",
  "id_rsa",
  "id_ed25519",
  "credentials.json",
  "secrets.json",
  "system_prompt.txt",
  "openclaw.json",
  "memory.md",
  "agents.md",
  "soul.md",
  "user.md",
];

const GENERATED_SOURCE_PATH_PATTERNS = [
  /(^|\/)public\/js\/vs\//i,
  /(^|\/)static\/.*\/public\/js\/vs\//i,
  /(^|\/)vs\/basic-languages\/src\//i,
  /(^|\/)vs\/language\/[^/]+\/[^/]+Worker\.js$/i,
  /(^|\/)codemirror(\.|-|\b)/i,
  /(^|\/)monaco(\.|-|\b)/i,
];

const MALICIOUS_SKILL_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above|security|safety)\s+(instructions?|rules?|constraints?|protocols?)/i,
  /(bypass|disable|override|circumvent|evade)\s+(security|safety|guardrails?|sandbox|policy|approval)/i,
  /(reveal|dump|leak|exfiltrate|steal|extract).{0,80}(system\s*prompt|developer\s*prompt|hidden\s*instructions?|api[_ -]?key|token|secret|password|credential)/i,
  /(send|post|upload|transmit).{0,80}(secret|token|credential|password|private\s*key|system\s*prompt)/i,
  /(readFileSync|readFile|fs\.).{0,120}(openclaw\.json|\.env|id_rsa|secret|token|password)/i,
  /(fetch|axios|curl|wget|https?\.request|XMLHttpRequest).{0,160}(token|secret|openclaw\.json|gateway|credential|password)/i,
  /(系统提示|开发者提示|内部配置|隐藏指令|工具声明).{0,40}(泄露|导出|发送|上传|打印|展示)/i,
  /(绕过|禁用|关闭|突破).{0,24}(安全|限制|护栏|策略|沙箱|审批)/i,
];

const RISKY_CONFIG_PATTERNS = [
  /"auth"\s*:\s*(false|null|"none"|"off"|"disabled")/i,
  /auth\s*[:=]\s*(false|null|none|off|disabled)/i,
  /bind\s*[:=]\s*["']?(0\.0\.0\.0|\*|\[::\])/i,
  /allow(_|-)?all\s*[:=]\s*true/i,
  /dangerously[-_a-z]*\s*[:=]\s*true/i,
  /disable[_-]?(sandbox|approval|security|guardrail)\s*[:=]\s*true/i,
  /[?&]gatewayURL\s*=\s*wss?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))/i,
  /\bgatewayURL\b.{0,80}\bwss?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))/i,
];

const STRONG_SECRET_VALUE_PATTERNS = [
  /-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
  /\bsk-[a-zA-Z0-9_-]{16,}\b/,
  /\bgh[pousr]_[a-zA-Z0-9_]{20,}\b/,
  /\bxox[baprs]-[a-zA-Z0-9-]{16,}\b/,
];

const CONFIG_SECRET_VALUE_PATTERNS = [
  ...STRONG_SECRET_VALUE_PATTERNS,
  /^\s*["']?(api[_-]?key|token|secret|password)["']?\s*[:=]\s*["']?[a-zA-Z0-9._+/=-]{12,}/im,
];

const SOURCE_SECRET_VALUE_PATTERNS = [
  ...STRONG_SECRET_VALUE_PATTERNS,
  /\b(api[_-]?key|token|secret|password)\s*[:=]\s*["'][a-zA-Z0-9._+/=-]{20,}["']/i,
];

export async function scanProvenance(workspaceDir: string, config: PluginConfig): Promise<ProvenanceScanResult> {
  const now = Date.now();
  const result: ProvenanceScanResult = {
    workspaceDir,
    scannedFiles: 0,
    skippedFiles: 0,
    findings: [],
    blocked: false,
    cached: false,
    changedFiles: 0,
  };

  if (!config.provenanceScan.enabled || !workspaceDir || !await isDirectory(workspaceDir)) {
    return result;
  }
  const signature = provenanceConfigSignature(config);
  let cached = scanCache.get(workspaceDir);
  if (!cached) {
    cached = { scannedAt: 0, configSignature: signature, files: new Map(), dirty: new Set(), watcher: createWorkspaceWatcher(workspaceDir) };
    scanCache.set(workspaceDir, cached);
  }
  const configChanged = cached.configSignature !== signature;
  const candidates = await listCandidateFiles(workspaceDir, config);
  const currentPaths = new Set(candidates);
  for (const cachedPath of cached.files.keys()) {
    if (!currentPaths.has(cachedPath)) cached.files.delete(cachedPath);
  }
  const scans = await mapConcurrent(candidates, 4, async (filePath) => scanChangedFile(filePath, workspaceDir, cached!, config, configChanged));
  for (const scan of scans) {
    if (scan.skipped) result.skippedFiles += 1;
    if (scan.changed) result.changedFiles += 1;
    if (scan.counted) result.scannedFiles += 1;
  }
  result.findings = Array.from(cached.files.values()).flatMap((entry) => entry.findings);
  result.blocked = result.findings.some((finding) => finding.verdict === "block");
  result.cached = !configChanged && result.changedFiles === 0;
  cached.scannedAt = now;
  cached.configSignature = signature;
  cached.dirty.clear();
  return result;
}

export function clearProvenanceScanCache(): void {
  for (const cached of scanCache.values()) cached.watcher?.close();
  scanCache.clear();
}

async function listCandidateFiles(workspaceDir: string, config: PluginConfig): Promise<string[]> {
  const files: string[] = [];
  const stack = [workspaceDir];

  while (stack.length && files.length < config.provenanceScan.maxFiles) {
    const dir = stack.pop()!;
    try {
      const entries = await opendir(dir);
      for await (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) {
          if (!SKIP_DIRS.has(entry.name)) stack.push(fullPath);
          continue;
        }
        if (!entry.isFile() || !isTextCandidate(fullPath)) continue;
        files.push(fullPath);
        if (files.length >= config.provenanceScan.maxFiles) break;
      }
    } catch {
      continue;
    }
  }
  return files;
}

async function scanChangedFile(
  filePath: string,
  workspaceDir: string,
  cached: CachedWorkspace,
  config: PluginConfig,
  configChanged: boolean,
): Promise<{ changed: boolean; skipped: boolean; counted: boolean }> {
  const relPath = relative(workspaceDir, filePath).replace(/\\/g, "/");
  if (isGeneratedNoisePath(relPath)) {
    cached.files.delete(filePath);
    return { changed: false, skipped: true, counted: false };
  }
  try {
    const fileStat = await stat(filePath, { bigint: true });
    if (fileStat.size > BigInt(config.provenanceScan.maxFileBytes)) {
      cached.files.delete(filePath);
      return { changed: false, skipped: true, counted: false };
    }
    const size = fileStat.size.toString();
    const mtimeNs = fileStat.mtimeNs.toString();
    const previous = cached.files.get(filePath);
    const dirty = cached.dirty.has(relPath) || cached.dirty.has(filePath);
    if (!configChanged && !dirty && previous?.size === size && previous.mtimeNs === mtimeNs) {
      return { changed: false, skipped: false, counted: true };
    }
    const raw = await readFile(filePath);
    const hash = createHash("sha256").update(raw).digest("hex");
    if (!configChanged && previous?.hash === hash) {
      cached.files.set(filePath, { ...previous, size, mtimeNs });
      return { changed: false, skipped: false, counted: true };
    }
    const content = candidateContent(filePath, raw);
    const deterministic = scanDeterministicFile(relPath, content, config);
    cached.files.set(filePath, { size, mtimeNs, hash, findings: deterministic });
    return { changed: true, skipped: false, counted: true };
  } catch {
    cached.files.delete(filePath);
    return { changed: false, skipped: true, counted: false };
  }
}

function scanDeterministicFile(relPath: string, content: string, config: PluginConfig): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  if (config.provenanceScan.scanSkills && isSkillFile(relPath)) findings.push(...scanSkillContent(relPath, content, config));
  if (config.provenanceScan.scanConfig && isConfigFile(relPath)) findings.push(...scanConfigContent(relPath, content, config));
  if (config.provenanceScan.scanSensitiveFiles) findings.push(...scanSensitiveFile(relPath, content, config));
  findings.push(...scanTrustSurface(relPath, content, config));
  return findings;
}

function createWorkspaceWatcher(workspaceDir: string): FSWatcher | null {
  try {
    const watcher = watch(workspaceDir, { recursive: true }, (_event, filename) => {
      const current = scanCache.get(workspaceDir);
      if (!current || !filename) return;
      current.dirty.add(String(filename).replace(/\\/g, "/"));
      current.dirty.add(join(workspaceDir, String(filename)));
    });
    watcher.unref();
    return watcher;
  } catch {
    return null;
  }
}

async function isDirectory(value: string): Promise<boolean> {
  try {
    return (await stat(value)).isDirectory();
  } catch {
    return false;
  }
}

function provenanceConfigSignature(config: PluginConfig): string {
  return JSON.stringify({
    scanSkills: config.provenanceScan.scanSkills,
    scanConfig: config.provenanceScan.scanConfig,
    scanSensitiveFiles: config.provenanceScan.scanSensitiveFiles,
    maxFileBytes: config.provenanceScan.maxFileBytes,
    sensitiveAssets: config.policy.sensitiveAssets,
    semantic: [config.semantic.enabled, config.semantic.judgeProvenance, config.semantic.model, config.semantic.baseUrl],
  });
}

async function mapConcurrent<T, R>(items: T[], concurrency: number, work: (item: T) => Promise<R>): Promise<R[]> {
  const output = new Array<R>(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      output[index] = await work(items[index]);
    }
  });
  await Promise.all(workers);
  return output;
}

function scanSkillContent(relPath: string, content: string, config: PluginConfig): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const matches = matchPatterns(content, MALICIOUS_SKILL_PATTERNS);
  if (matches.length) {
    findings.push(finding("Context Provenance", "deterministic", "block", "skill file contains malicious instruction patterns", 100, {
      path: relPath,
      matched: matches.slice(0, 5),
      preview: clampText(content, config.capture.previewChars),
      ...interventionEvidence("confirmed_attack", {
        attack_class: "tool_hijack",
        causal_certainty: "observed",
        confidence: 1,
      }),
    }));
  }
  return findings;
}

function scanConfigContent(relPath: string, content: string, _config: PluginConfig): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const riskyMatches = matchPatterns(content, RISKY_CONFIG_PATTERNS);
  if (riskyMatches.length) {
    findings.push(finding("Context Provenance", "heuristic", "require_approval", "configuration contains risky security settings", 40, {
      path: relPath,
      matched: riskyMatches.slice(0, 5),
    }));
  }

  const secretMatches = matchPatterns(content, CONFIG_SECRET_VALUE_PATTERNS);
  if (secretMatches.length) {
    findings.push(finding("Context Provenance", "heuristic", "require_approval", "configuration contains hardcoded secret values", 55, {
      path: relPath,
      matched: secretMatches.slice(0, 5).map(() => "[redacted]"),
      confidence: "high",
    }));
  }
  return findings;
}

function scanSensitiveFile(relPath: string, content: string, config: PluginConfig): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const name = basename(relPath).toLowerCase();
  const lowerPath = relPath.toLowerCase();
  const sensitiveByName =
    SENSITIVE_FILE_NAMES.includes(name)
    || config.policy.sensitiveAssets.some((asset) => matchesSensitiveAssetPath(lowerPath, asset));

  if (sensitiveByName) {
    findings.push(finding("Context Provenance", "heuristic", "require_approval", "workspace contains sensitive asset file", 30, {
      path: relPath,
      file: name,
    }));
  }

  if (!isConfigFile(relPath)) {
    const secretMatches = matchPatterns(content, SOURCE_SECRET_VALUE_PATTERNS);
    if (secretMatches.length) {
      findings.push(finding("Context Provenance", "heuristic", "require_approval", "workspace file appears to contain embedded secrets", 45, {
        path: relPath,
        matched: secretMatches.slice(0, 5).map(() => "[redacted]"),
        confidence: "medium",
      }));
    }
  }
  return findings;
}

function scanTrustSurface(relPath: string, content: string, config: PluginConfig): DetectionFinding[] {
  const analysis = analyzeTrustContent(content, {
    path: relPath,
    source: isSkillFile(relPath) ? "skill" : isConfigFile(relPath) ? "config" : isMemoryFile(relPath) ? "memory" : undefined,
    previewChars: config.capture.previewChars,
  });
  return analysis.findings.map((item) => ({
    ...item,
    layer: item.layer === "Tool Boundary" ? "Context Provenance" : item.layer,
    evidence: {
      ...item.evidence,
      path: relPath,
      preview: clampText(content, config.capture.previewChars),
    },
  }));
}

function isGeneratedNoisePath(relPath: string): boolean {
  return GENERATED_SOURCE_PATH_PATTERNS.some((pattern) => pattern.test(relPath));
}

function matchesSensitiveAssetPath(lowerPath: string, asset: string): boolean {
  const normalized = asset.trim().toLowerCase();
  if (!normalized) return false;
  if (normalized.includes("/") || normalized.includes("\\") || normalized.includes(".")) {
    return lowerPath === normalized || lowerPath.endsWith(`/${normalized}`);
  }
  return lowerPath.split("/").some((segment) => {
    const base = segment.replace(/\.[^.]+$/, "");
    return segment === normalized || base === normalized || segment === `.${normalized}`;
  });
}

function isTextCandidate(filePath: string): boolean {
  const ext = extname(filePath).toLowerCase();
  const name = basename(filePath).toLowerCase();
  return TEXT_EXTENSIONS.has(ext) || SENSITIVE_FILE_NAMES.includes(name) || name === "skill.md";
}

function isSkillFile(relPath: string): boolean {
  const normalized = relPath.toLowerCase();
  return normalized === "skill.md"
    || normalized.endsWith("/skill.md")
    || normalized.startsWith("skills/")
    || normalized.includes("/skills/")
    || normalized.startsWith("plugin-skills/")
    || normalized.includes("/plugin-skills/");
}

function isConfigFile(relPath: string): boolean {
  const ext = extname(relPath).toLowerCase();
  const name = basename(relPath).toLowerCase();
  return [".json", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"].includes(ext)
    || name.includes("config")
    || name === "openclaw.json";
}

function isMemoryFile(relPath: string): boolean {
  return /(^|\/)(memory\.md|agents\.md|soul\.md|user\.md)$/i.test(relPath);
}

function candidateContent(filePath: string, raw: Buffer): string {
  const ext = extname(filePath).toLowerCase();
  if ([".pdf", ".png", ".jpg", ".jpeg", ".webp"].includes(ext)) {
    return raw.toString("latin1")
      .replace(/[^\x09\x0a\x0d\x20-\x7e]+/g, " ")
      .replace(/\s{3,}/g, " ");
  }
  return raw.toString("utf8");
}

function matchPatterns(content: string, patterns: RegExp[]): string[] {
  const matches: string[] = [];
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if (match) matches.push(match[0].slice(0, 160));
  }
  return matches;
}

function finding(
  layer: string,
  findingType: "deterministic" | "heuristic" | "learned",
  verdict: "pass" | "require_approval" | "block",
  reason: string,
  score: number,
  evidence: Record<string, unknown>,
): DetectionFinding {
  return { layer, finding_type: findingType, verdict, reason, score, evidence };
}
