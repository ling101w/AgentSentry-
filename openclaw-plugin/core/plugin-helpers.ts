import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { RecordSeverity } from "./records.ts";

type JudgeFinding = {
  finding_type?: unknown;
  verdict?: unknown;
  score?: unknown;
  evidence?: Record<string, unknown>;
};

type ResponseCoverSettings = {
  enabled: boolean;
  coverAssistantAfterContamination: boolean;
};

type NotificationSettings = {
  enableProactiveNotifications: boolean;
  minSeverity: "warning" | "danger";
};

export type ProvenanceRootOptions = {
  homeDir?: string;
  skillsPathList?: string;
};

export function shouldReturnJudgeAnalysis(findings: JudgeFinding[], riskScore: number, decision: string): boolean {
  const hasJudgeFinding = findings.some((finding) => {
    const evidence = finding.evidence as Record<string, unknown> | undefined;
    return finding.finding_type === "semantic" && typeof evidence?.semanticRisk === "string";
  });
  if (!hasJudgeFinding) return false;
  return decision === "deny" || riskScore >= 55 || findings.some((finding) =>
    finding.verdict === "block" || Number(finding.score || 0) >= 60
  );
}

export function severityForDecision(decision: string): RecordSeverity {
  if (decision === "deny") return "danger";
  if (decision === "ask") return "warning";
  return "success";
}

export function severityForVerdict(verdict: string): RecordSeverity {
  if (verdict === "block") return "danger";
  if (verdict === "require_approval") return "warning";
  return "info";
}

export function shouldCoverAssistantResponse(
  settings: ResponseCoverSettings,
  coverNextAssistantResponse: boolean,
  role: string,
): boolean {
  return settings.enabled
    && settings.coverAssistantAfterContamination
    && coverNextAssistantResponse
    && role === "assistant";
}

export function shouldNotify(settings: NotificationSettings, severity: "warning" | "danger"): boolean {
  if (!settings.enableProactiveNotifications) return false;
  return settings.minSeverity === "warning" || severity === "danger";
}

export function notificationRoute(ctx: Record<string, unknown>): { channel: string; target: string } | null {
  const provider = typeof ctx.messageProvider === "string" ? ctx.messageProvider.toLowerCase() : "";
  const sessionKey = typeof ctx.sessionKey === "string" ? ctx.sessionKey : "";
  const target = sessionKey.split(":").pop() || "";
  if (!target) return null;
  if (provider === "feishu") return { channel: "feishu", target };
  if (provider === "qqbot") return { channel: "qqbot", target };
  return null;
}

export function provenanceRootsFor(workspaceDir: string, options: ProvenanceRootOptions = {}): string[] {
  const homeDir = options.homeDir ?? homedir();
  const skillsPathList = options.skillsPathList ?? String(process.env.OPENCLAW_SKILLS_DIR || "");
  const candidates = [
    workspaceDir,
    join(homeDir, ".openclaw", "plugin-skills"),
    join(homeDir, ".openclaw", "skills"),
    ...skillsPathList
      .split(delimiter)
      .map((item) => item.trim())
      .filter(Boolean),
  ];
  const roots: string[] = [];
  for (const candidate of candidates) {
    if (!candidate || !existsSync(candidate)) continue;
    const root = resolve(candidate);
    if (roots.some((existing) => isSameOrNestedPath(existing, root))) continue;
    roots.push(root);
  }
  return roots;
}

function isSameOrNestedPath(parent: string, candidate: string): boolean {
  const rel = relative(parent, candidate);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}
