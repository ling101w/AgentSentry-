import type { RecordSeverity } from "../core/records.ts";
export function optionalInt(value: unknown, min: number, max: number): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

export function recordParam(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
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

export function firstMatch(text: string, pattern: RegExp): string {
  return pattern.exec(text)?.[0] || "";
}


export function stripIpv6Brackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}
