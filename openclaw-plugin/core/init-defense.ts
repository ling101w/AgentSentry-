import { createHash } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync, statSync, type Dirent } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import type { PluginConfig } from "../config.ts";
import type { DetectionFinding } from "./detect.ts";
import { clampText } from "./redact.ts";
import { analyzeTrustContent, finding, riskMax } from "./trust.ts";

export type FoundationComponentKind = "skill" | "plugin" | "config" | "memory" | "workspace";
export type FoundationAdmission = "allow_limited" | "review" | "quarantine";

export type FoundationComponent = {
  id: string;
  kind: FoundationComponentKind;
  path: string;
  root: string;
  sha256: string;
  size: number;
  manifest: {
    present: boolean;
    path: string;
    signed: boolean;
    declaredCapabilities: string[];
  };
  risk: number;
  trust: "trusted" | "review" | "blocked";
  admission: FoundationAdmission;
  admissionReason: string;
};

export type InitializationScanResult = {
  roots: string[];
  components: FoundationComponent[];
  findings: DetectionFinding[];
  blocked: boolean;
  scanned_at: string;
};

/**
 * A quarantined executable component is handled at its own load/call boundary.
 * Only compromised state that can directly alter the active context blocks a
 * whole session before a tool is selected.
 */
export function foundationFindingBlocksSession(finding: Pick<DetectionFinding, "verdict" | "evidence">): boolean {
  if (finding.verdict !== "block") return false;
  const component = finding.evidence.component;
  if (!component || typeof component !== "object" || Array.isArray(component)) return true;
  const kind = String((component as Record<string, unknown>).kind || "");
  return kind === "config" || kind === "memory" || kind === "workspace";
}

const COMPONENT_FILES = new Set([
  "skill.md",
  "package.json",
  "openclaw.plugin.json",
  "openclaw.json",
  "memory.md",
  "user.md",
  "soul.md",
  "agents.md",
]);

const COMPONENT_EXTENSIONS = new Set([".json", ".yaml", ".yml", ".toml", ".md", ".js", ".ts", ".mjs", ".cjs", ".py", ".sh"]);
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "coverage", ".venv", "venv", "__pycache__", ".pytest_cache"]);

export function scanInitializationSurface(workspaceDir: string, config: PluginConfig): InitializationScanResult {
  const roots = initializationRoots(workspaceDir, config);
  const components: FoundationComponent[] = [];
  const findings: DetectionFinding[] = [];
  if (!config.initializationDefense.enabled) {
    return { roots, components, findings, blocked: false, scanned_at: new Date().toISOString() };
  }

  for (const root of roots) {
    for (const filePath of listComponentFiles(root, config.initializationDefense.maxComponents - components.length)) {
      const component = inspectComponent(root, filePath, config);
      if (!component) continue;
      components.push(component);
      findings.push(...componentFindings(component, config));
      if (components.length >= config.initializationDefense.maxComponents) break;
    }
    if (components.length >= config.initializationDefense.maxComponents) break;
  }

  return {
    roots,
    components,
    findings: dedupeFindings(findings),
    blocked: findings.some((item) => item.verdict === "block"),
    scanned_at: new Date().toISOString(),
  };
}

function initializationRoots(workspaceDir: string, config: PluginConfig): string[] {
  const roots = new Set<string>();
  if (workspaceDir && existsSync(workspaceDir)) roots.add(resolve(workspaceDir));
  if (config.initializationDefense.scanGlobalOpenClaw) {
    const base = config.storage.stateDir || process.env.OPENCLAW_STATE_DIR?.trim() || join(homedir(), ".openclaw");
    for (const path of [base, join(base, "skills"), join(base, "plugin-skills")]) {
      if (existsSync(path)) roots.add(resolve(path));
    }
  }
  return [...roots];
}

function listComponentFiles(root: string, limit: number): string[] {
  if (limit <= 0 || !existsSync(root)) return [];
  const output: string[] = [];
  const stack = [root];
  while (stack.length && output.length < limit) {
    const dir = stack.pop()!;
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name.toLowerCase())) stack.push(fullPath);
        continue;
      }
      if (!entry.isFile() || !isComponentCandidate(fullPath)) continue;
      output.push(fullPath);
      if (output.length >= limit) break;
    }
  }
  return output;
}

function inspectComponent(root: string, filePath: string, config: PluginConfig): FoundationComponent | null {
  try {
    const stat = statSync(filePath);
    if (!stat.isFile() || stat.size > config.provenanceScan.maxFileBytes) return null;
    const raw = readFileSync(filePath);
    const text = raw.toString("utf8");
    const kind = componentKind(filePath);
    const relPath = relative(root, filePath).replace(/\\/g, "/");
    const analysis = analyzeTrustContent(text, {
      source: kind === "skill" ? "skill" : kind === "config" ? "config" : kind === "memory" ? "memory" : "workspace",
      sourceId: relPath,
      path: relPath,
      previewChars: config.capture.previewChars,
    });
    const explicitCapabilities = declaredCapabilities(filePath, text);
    const manifestPath = nearestManifest(filePath);
    const signed = manifestPath ? manifestHasSecuritySignature(manifestPath) : false;
    const risk = Math.max(riskMax(analysis.risk_vector), explicitCapabilitiesRisk(explicitCapabilities, kind));
    const admission = admissionForComponent({ kind, risk, manifestPath, signed, capabilities: explicitCapabilities, analysis });
    const trust = admission.admission === "quarantine" ? "blocked" : admission.admission === "review" ? "review" : "trusted";
    return {
      id: componentId(root, filePath, raw),
      kind,
      path: relPath,
      root,
      sha256: createHash("sha256").update(raw).digest("hex"),
      size: stat.size,
      manifest: {
        present: Boolean(manifestPath),
        path: manifestPath ? relative(root, manifestPath).replace(/\\/g, "/") : "",
        signed,
        declaredCapabilities: explicitCapabilities,
      },
      risk,
      trust,
      admission: admission.admission,
      admissionReason: admission.reason,
    };
  } catch {
    return null;
  }
}

function componentFindings(component: FoundationComponent, config: PluginConfig): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  const evidence = {
    component: {
      id: component.id,
      kind: component.kind,
      path: component.path,
      sha256: component.sha256,
      size: component.size,
      manifest: component.manifest,
      trust: component.trust,
      risk: component.risk,
      admission: component.admission,
      admission_reason: component.admissionReason,
    },
  };
  if ((component.kind === "skill" || component.kind === "plugin") && !component.manifest.present && component.admission !== "allow_limited") {
    findings.push(finding("Foundation Integrity", "deterministic", "require_approval", "初始化防线发现组件缺少安全清单，需要人工确认能力边界", 45, evidence));
  }
  if ((component.kind === "skill" || component.kind === "plugin") && component.manifest.present && !component.manifest.signed) {
    findings.push(finding("Foundation Integrity", "heuristic", "require_approval", "初始化防线发现组件清单未携带玄鉴签名，按第三方组件处理", 35, evidence));
  }
  if (component.admission === "quarantine") {
    findings.push(finding("Foundation Integrity", "deterministic", "block", "初始化防线发现高危组件行为，已加入隔离清单，禁止直接装载或执行", 100, evidence));
  } else if (component.risk >= 45) {
    findings.push(finding("Foundation Integrity", "heuristic", "require_approval", "初始化防线发现组件存在敏感能力或高影响副作用，需要审批", 55, evidence));
  }
  if (component.manifest.declaredCapabilities.includes("network_write") && component.manifest.declaredCapabilities.includes("file_read")) {
    findings.push(finding("Foundation Integrity", "deterministic", "require_approval", "组件同时声明文件读取和外部写入能力，需要确认是否存在数据外发路径", 60, evidence));
  }
  if (component.kind === "config" && component.path.toLowerCase().endsWith("openclaw.json")) {
    findings.push(finding("Foundation Integrity", "deterministic", "pass", "OpenClaw 配置文件已纳入初始化完整性盘点", 0, evidence));
  }
  return findings.slice(0, config.initializationDefense.maxComponents);
}

function admissionForComponent(input: {
  kind: FoundationComponentKind;
  risk: number;
  manifestPath: string;
  signed: boolean;
  capabilities: string[];
  analysis: ReturnType<typeof analyzeTrustContent>;
}): { admission: FoundationAdmission; reason: string } {
  const blockedByContent = input.analysis.findings.some((item) => item.verdict === "block");
  if (blockedByContent || input.risk >= 85) {
    return { admission: "quarantine", reason: "检测到高危能力组合或明确恶意行为" };
  }
  if (input.kind === "skill" && isLowRiskSkill(input.capabilities, input.risk)) {
    return {
      admission: "allow_limited",
      reason: input.signed ? "签名 Skill 的能力边界为低风险" : "本地低风险 Skill 未发现进程执行、持久化、敏感读取或外部写入能力",
    };
  }
  if (input.signed && input.risk < 45) {
    return { admission: "allow_limited", reason: "签名组件的能力边界处于低风险范围" };
  }
  return {
    admission: "review",
    reason: input.manifestPath ? "组件具有待确认能力或未完成签名验证" : "组件缺少可验证的能力清单",
  };
}

function isLowRiskSkill(capabilities: string[], risk: number): boolean {
  if (risk >= 45) return false;
  const restricted = new Set(["network_write", "process_exec", "persistent_state", "sensitive_read", "file_write"]);
  return capabilities.every((capability) => !restricted.has(capability));
}

function isComponentCandidate(filePath: string): boolean {
  const name = basename(filePath).toLowerCase();
  const normalized = filePath.replace(/\\/g, "/");
  return COMPONENT_FILES.has(name) || COMPONENT_EXTENSIONS.has(extname(filePath).toLowerCase()) && /(^|\/)(skills?|plugin-skills?|plugins?|\.openclaw)(\/|$)/i.test(normalized);
}

function componentKind(filePath: string): FoundationComponentKind {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  const name = basename(normalized);
  if (name === "skill.md" || /\/skills?\//i.test(normalized)) return "skill";
  if (name === "openclaw.plugin.json" || /\/plugins?\//i.test(normalized) || /\/plugin-skills?\//i.test(normalized)) return "plugin";
  if (["openclaw.json", ".env"].includes(name) || [".json", ".yaml", ".yml", ".toml"].includes(extname(name))) return "config";
  if (["memory.md", "user.md", "soul.md", "agents.md"].includes(name) || /\/memory\//i.test(normalized)) return "memory";
  return "workspace";
}

function nearestManifest(filePath: string): string {
  let dir = dirname(filePath);
  for (let depth = 0; depth < 4; depth += 1) {
    for (const name of ["agentsentry.tool-manifest.json", "openclaw.plugin.json", "package.json"]) {
      const candidate = join(dir, name);
      if (existsSync(candidate) && safeIsFile(candidate)) return candidate;
    }
    const next = dirname(dir);
    if (next === dir) break;
    dir = next;
  }
  return "";
}

function safeIsFile(path: string): boolean {
  try {
    return lstatSync(path).isFile();
  } catch {
    return false;
  }
}

function manifestHasSecuritySignature(path: string): boolean {
  try {
    const text = readFileSync(path, "utf8");
    if (basename(path).toLowerCase() === "agentsentry.tool-manifest.json") {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      return typeof parsed.signature === "string" && typeof parsed.digest === "string";
    }
    const parsed = JSON.parse(text) as Record<string, unknown>;
    const security = parsed.agentsentry || parsed.security || parsed.openclaw;
    return Boolean(security && typeof security === "object" && ("signature" in security || "digest" in security));
  } catch {
    return false;
  }
}

function declaredCapabilities(filePath: string, text: string): string[] {
  const capabilities = new Set<string>();
  const reads = /\b(readFileSync|readFile|fs\.read|cat\s+|open\(|loads?|reads?|读取|加载|访问)\b/i.test(text);
  const writes = /\b(writeFileSync|writeFile|fs\.write|sed\s+-i|tee\s+|saves?|writes?|写入|保存)\b/i.test(text);
  const networkClient = /\b(fetch|axios|https?\.request|curl|wget|XMLHttpRequest|requests?\.(?:get|post|put|patch))\b/i.test(text);
  const networkWrite = /\b(posts?|puts?|patch(?:es)?|uploads?|sends?|transmits?|webhook|提交|上传|发送|外发)\b/i.test(text)
    || /-X\s*(?:POST|PUT|PATCH)\b/i.test(text)
    || /method\s*[:=]\s*["'](?:POST|PUT|PATCH)["']/i.test(text);
  const sensitiveResource = /(?:openclaw\.json|\.env\b|\.ssh\/(?:id_|config)|id_(?:rsa|ed25519|ecdsa|dsa)|process\.env\.|credentials?|gateway(?:Auth)?Token|私钥|凭据|认证令牌)/i.test(text);

  if (reads) capabilities.add("file_read");
  if (writes) capabilities.add("file_write");
  if (networkClient) capabilities.add(networkWrite ? "network_write" : "network_read");
  if (/\b(exec|spawn|child_process|bash|powershell|cmd\.exe)\b/i.test(text)) capabilities.add("process_exec");
  if (/(cron|crontab|systemd|startup|launchagent|开机启动|定时任务)/i.test(text) && writes) capabilities.add("persistent_state");
  if (reads && sensitiveResource) capabilities.add("sensitive_read");
  if (capabilities.has("sensitive_read")) capabilities.add("file_read");
  if (basename(filePath).toLowerCase() === "skill.md" && !capabilities.size) capabilities.add("declared_skill");
  return [...capabilities].sort();
}

function explicitCapabilitiesRisk(capabilities: string[], kind: FoundationComponentKind): number {
  let risk = 0;
  if (kind === "skill" || kind === "plugin") risk = Math.max(risk, 20);
  if (capabilities.includes("network_write")) risk = Math.max(risk, 45);
  if (capabilities.includes("file_read")) risk = Math.max(risk, 35);
  if (capabilities.includes("sensitive_read")) risk = Math.max(risk, 80);
  if (capabilities.includes("process_exec")) risk = Math.max(risk, 85);
  if (capabilities.includes("persistent_state")) risk = Math.max(risk, 75);
  if (capabilities.includes("network_write") && capabilities.includes("sensitive_read")) risk = 95;
  return risk;
}

function componentId(root: string, filePath: string, content: Buffer): string {
  return `cmp_${createHash("sha256").update(`${root}\n${filePath}\n`).update(content).digest("hex").slice(0, 24)}`;
}

function dedupeFindings(findings: DetectionFinding[]): DetectionFinding[] {
  const seen = new Set<string>();
  return findings.filter((item) => {
    const evidence = item.evidence ? clampText(JSON.stringify(item.evidence), 360) : "";
    const key = `${item.layer}:${item.verdict}:${item.reason}:${evidence}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
