import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative } from "node:path";
import type { PluginConfig } from "../config.ts";
import type { DetectionFinding } from "./detect.ts";
import { clampText } from "./redact.ts";
import { semanticJudgeFoundationFile } from "./semantic.ts";
import { analyzeTrustContent } from "./trust.ts";

export type FoundationScanResult = {
  workspaceDir: string;
  scannedFiles: number;
  skippedFiles: number;
  findings: DetectionFinding[];
  blocked: boolean;
  cached: boolean;
};

type CachedScan = {
  scannedAt: number;
  result: FoundationScanResult;
};

const scanCache = new Map<string, CachedScan>();

const SKIP_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
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

export async function scanFoundation(workspaceDir: string, config: PluginConfig): Promise<FoundationScanResult> {
  const now = Date.now();
  const cached = scanCache.get(workspaceDir);
  if (cached && now - cached.scannedAt < config.foundationScan.rescanIntervalMs) {
    return { ...cached.result, cached: true };
  }

  const result: FoundationScanResult = {
    workspaceDir,
    scannedFiles: 0,
    skippedFiles: 0,
    findings: [],
    blocked: false,
    cached: false,
  };

  if (!config.foundationScan.enabled || !workspaceDir || !existsSync(workspaceDir)) {
    scanCache.set(workspaceDir, { scannedAt: now, result });
    return result;
  }

  for (const filePath of listCandidateFiles(workspaceDir, config)) {
    const relPath = relative(workspaceDir, filePath).replace(/\\/g, "/");
    if (isGeneratedNoisePath(relPath)) {
      result.skippedFiles += 1;
      continue;
    }
    let content = "";
    try {
      const stat = statSync(filePath);
      if (stat.size > config.foundationScan.maxFileBytes) {
        result.skippedFiles += 1;
        continue;
      }
      content = readCandidateContent(filePath);
      result.scannedFiles += 1;
    } catch {
      result.skippedFiles += 1;
      continue;
    }

    if (config.foundationScan.scanSkills && isSkillFile(relPath)) {
      result.findings.push(...scanSkillContent(relPath, content, config));
    }
    if (config.foundationScan.scanConfig && isConfigFile(relPath)) {
      result.findings.push(...scanConfigContent(relPath, content, config));
    }
    if (config.foundationScan.scanSensitiveFiles) {
      result.findings.push(...scanSensitiveFile(relPath, content, config));
    }
    result.findings.push(...scanTrustSurface(relPath, content, config));
    if (shouldSemanticScan(relPath, config)) {
      result.findings.push(...await semanticJudgeFoundationFile({
        relPath,
        content,
        roleHint: isSkillFile(relPath) ? "skill" : isConfigFile(relPath) ? "configuration" : "workspace file",
      }, config));
    }

    if (result.scannedFiles >= config.foundationScan.maxFiles) break;
  }

  result.blocked = result.findings.some((finding) => finding.verdict === "block");
  scanCache.set(workspaceDir, { scannedAt: now, result });
  return result;
}

export function clearFoundationScanCache(): void {
  scanCache.clear();
}

function listCandidateFiles(workspaceDir: string, config: PluginConfig): string[] {
  const files: string[] = [];
  const stack = [workspaceDir];

  while (stack.length && files.length < config.foundationScan.maxFiles) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!isTextCandidate(fullPath)) continue;
      files.push(fullPath);
      if (files.length >= config.foundationScan.maxFiles) break;
    }
  }
  return files;
}

function scanSkillContent(relPath: string, content: string, config: PluginConfig): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const matches = matchPatterns(content, MALICIOUS_SKILL_PATTERNS);
  if (matches.length) {
    findings.push(finding("Foundation", "deterministic", "block", "skill file contains malicious instruction patterns", 100, {
      path: relPath,
      matched: matches.slice(0, 5),
      preview: clampText(content, config.capture.previewChars),
    }));
  }
  return findings;
}

function scanConfigContent(relPath: string, content: string, config: PluginConfig): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const riskyMatches = matchPatterns(content, RISKY_CONFIG_PATTERNS);
  if (riskyMatches.length) {
    findings.push(finding("Foundation", "heuristic", "require_approval", "configuration contains risky security settings", 40, {
      path: relPath,
      matched: riskyMatches.slice(0, 5),
    }));
  }

  const secretMatches = matchPatterns(content, CONFIG_SECRET_VALUE_PATTERNS);
  if (secretMatches.length) {
    findings.push(finding("Foundation", "heuristic", "require_approval", "configuration contains hardcoded secret values", 55, {
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
    findings.push(finding("Foundation", "heuristic", "require_approval", "workspace contains sensitive asset file", 30, {
      path: relPath,
      file: name,
    }));
  }

  if (!isConfigFile(relPath)) {
    const secretMatches = matchPatterns(content, SOURCE_SECRET_VALUE_PATTERNS);
    if (secretMatches.length) {
      findings.push(finding("Foundation", "heuristic", "require_approval", "workspace file appears to contain embedded secrets", 45, {
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
    layer: item.layer === "Execution Control" ? "Foundation" : item.layer,
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
  return normalized.endsWith("skill.md") || normalized.includes("/skills/") || normalized.includes("\\skills\\");
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

function readCandidateContent(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  if ([".pdf", ".png", ".jpg", ".jpeg", ".webp"].includes(ext)) {
    return readFileSync(filePath)
      .toString("latin1")
      .replace(/[^\x09\x0a\x0d\x20-\x7e]+/g, " ")
      .replace(/\s{3,}/g, " ");
  }
  return readFileSync(filePath, "utf8");
}

function shouldSemanticScan(relPath: string, config: PluginConfig): boolean {
  if (!config.semantic.enabled || !config.semantic.judgeFoundation) return false;
  return isSkillFile(relPath) || isConfigFile(relPath);
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
