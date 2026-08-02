import type { DetectionFinding } from "../detect.ts";
import { readFirstString } from "../adapters/openclaw-tools.ts";
import { hostFromUrl } from "../security/url.ts";
import { safeStringify } from "../redact.ts";
import type { AgentSentryAction, BehaviorProfile, PolicySnapshot, PolicyState, TaskSpec } from "../policy/types.ts";

export const BEHAVIOR_WARMUP_SAMPLES = 10;
export const BEHAVIOR_WINDOW_SIZE = 40;
export const BEHAVIOR_SAMPLE_TTL_MS = 30 * 60 * 1000;

export function behaviorAnomalyFindings(action: AgentSentryAction, state: PolicySnapshot, now = Date.now()): DetectionFinding[] {
  const key = profileKey(action.tool, taskClassFor(state.taskSpec));
  const profile = state.behaviorProfiles.get(key);
  const samples = activeSamples(profile, now);
  if (samples.length < BEHAVIOR_WARMUP_SAMPLES) return [];
  const current = behaviorSnapshot(action, now);
  const findings: DetectionFinding[] = [];
  const evidenceBase = { tool: action.tool, task_class: taskClassFor(state.taskSpec), sample_count: samples.length, window_size: BEHAVIOR_WINDOW_SIZE };

  if (current.host && action.tool === "call_api" && establishedNovelty(samples.map((item) => item.host), current.host)) {
    findings.push(finding("tool target host deviates from warm behavior window", 35, { ...evidenceBase, host: current.host, learned_hosts: frequentValues(samples.map((item) => item.host)) }));
  }
  if (current.recipient && action.tool === "send_email" && establishedNovelty(samples.map((item) => item.recipient), current.recipient)) {
    findings.push(finding("email recipient deviates from warm behavior window", 35, { ...evidenceBase, recipient: current.recipient, learned_recipients: frequentValues(samples.map((item) => item.recipient)) }));
  }
  if (current.pathRoot && ["read_file", "write_file"].includes(action.tool) && establishedNovelty(samples.map((item) => item.pathRoot), current.pathRoot)) {
    findings.push(finding("file path root deviates from warm behavior window", 25, { ...evidenceBase, root: current.pathRoot, learned_roots: frequentValues(samples.map((item) => item.pathRoot)) }));
  }

  const paramBytesP90 = percentile(samples.map((item) => item.paramBytes), 0.9);
  if (paramBytesP90 > 0 && current.paramBytes > Math.max(paramBytesP90 * 4, paramBytesP90 + 4096)) {
    findings.push(finding("tool parameter size is anomalous for the sliding behavior window", 25, { ...evidenceBase, param_bytes: current.paramBytes, window_p90_param_bytes: paramBytesP90 }));
  }
  const paramKeysP90 = percentile(samples.map((item) => item.paramKeys), 0.9);
  if (paramKeysP90 > 0 && current.paramKeys > Math.max(paramKeysP90 * 3, paramKeysP90 + 8)) {
    findings.push(finding("tool parameter shape is anomalous for the sliding behavior window", 20, { ...evidenceBase, param_keys: current.paramKeys, window_p90_param_keys: paramKeysP90 }));
  }
  return findings;
}

export function observeBehavior(state: PolicyState, action: AgentSentryAction, now = Date.now()): void {
  const taskClass = taskClassFor(state.taskSpec);
  const key = profileKey(action.tool, taskClass);
  const existing = state.behaviorProfiles.get(key);
  const samples = activeSamples(existing, now);
  samples.push(behaviorSnapshot(action, now));
  const profile: BehaviorProfile = { tool: action.tool, taskClass, samples: samples.slice(-BEHAVIOR_WINDOW_SIZE) };
  state.behaviorProfiles.delete(key);
  state.behaviorProfiles.set(key, profile);
  while (state.behaviorProfiles.size > 64) {
    const oldest = state.behaviorProfiles.keys().next().value;
    if (oldest === undefined) break;
    state.behaviorProfiles.delete(oldest);
  }
}

export function taskClassFor(taskSpec: TaskSpec): string {
  const kinds = Array.from(new Set(taskSpec.capabilities.map((item) => item.kind))).sort();
  return kinds.length ? kinds.join("+") : "unscoped";
}

function profileKey(tool: string, taskClass: string): string {
  return `${tool}::${taskClass}`;
}

function activeSamples(profile: BehaviorProfile | undefined, now: number): BehaviorProfile["samples"] {
  if (!profile) return [];
  const cutoff = now - BEHAVIOR_SAMPLE_TTL_MS;
  return profile.samples.filter((sample) => sample.observedAt >= cutoff).slice(-BEHAVIOR_WINDOW_SIZE);
}

function establishedNovelty(values: string[], current: string): boolean {
  const filtered = values.filter(Boolean);
  if (!filtered.length || filtered.includes(current)) return false;
  const counts = valueCounts(filtered);
  const dominant = Math.max(...counts.values());
  return dominant >= Math.max(7, Math.ceil(filtered.length * 0.7));
}

function frequentValues(values: string[]): string[] {
  return Array.from(valueCounts(values.filter(Boolean)).entries())
    .sort((left, right) => right[1] - left[1])
    .slice(0, 8)
    .map(([value]) => value);
}

function valueCounts(values: string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
  return counts;
}

function behaviorSnapshot(action: AgentSentryAction, observedAt: number): BehaviorProfile["samples"][number] {
  const filePath = readFirstString(action.args, ["path", "file", "filename", "target"]);
  return {
    observedAt,
    host: hostFromUrl(readFirstString(action.args, ["url", "href", "endpoint", "target"])),
    recipient: readFirstString(action.args, ["recipient", "to", "email", "target"]).toLowerCase(),
    pathRoot: pathRoot(filePath),
    paramBytes: safeStringify(action.args).length,
    paramKeys: countKeys(action.args),
  };
}

function percentile(values: number[], ratio: number): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * ratio))];
}

function pathRoot(value: string): string {
  const normalized = value.replace(/\\/g, "/");
  if (/^[a-z]:\//i.test(normalized)) return normalized.slice(0, 2).toLowerCase();
  if (normalized.startsWith("/")) return `/${normalized.replace(/^\/+/, "").split("/")[0]}`;
  return normalized.split("/")[0] || "";
}

function countKeys(value: unknown): number {
  if (!value || typeof value !== "object") return 0;
  if (Array.isArray(value)) return value.reduce<number>((sum, item) => sum + countKeys(item), 0);
  return Object.values(value as Record<string, unknown>).reduce<number>((sum, item) => sum + 1 + countKeys(item), 0);
}

function finding(reason: string, score: number, evidence: Record<string, unknown>): DetectionFinding {
  return { layer: "Behavior Baseline", finding_type: "learned", verdict: "require_approval", reason, score, evidence };
}
