import type { PluginConfig } from "../../config.ts";
import type { DetectionFinding } from "../detect.ts";
import type { TaskSpec } from "../task-spec/index.ts";
import { safeStringify } from "../redact.ts";
import { assessAction, type PolicyActionInput } from "./action-assessment.ts";
import { hostFromUrl, readFirstString } from "./value-utils.ts";

export const BEHAVIOR_WARMUP_SAMPLES = 10;
export const BEHAVIOR_WINDOW_SIZE = 40;
export const BEHAVIOR_SAMPLE_TTL_MS = 30 * 60 * 1000;

type BehaviorSample = {
  observedAt: number;
  host: string;
  recipient: string;
  pathRoot: string;
  paramBytes: number;
  paramKeys: number;
};

export type BehaviorProfile = {
  tool: string;
  taskClass: string;
  samples: BehaviorSample[];
};

type BehaviorState = {
  behaviorProfiles: Map<string, BehaviorProfile>;
  taskSpec?: TaskSpec;
};

export function behaviorAnomalyFindingsFor(
  action: PolicyActionInput,
  state: BehaviorState,
  config: PluginConfig,
  now = Date.now(),
): DetectionFinding[] {
  const taskClass = taskClassFor(state.taskSpec);
  const samples = activeSamples(state.behaviorProfiles.get(profileKey(action.tool, taskClass)), now);
  if (samples.length < BEHAVIOR_WARMUP_SAMPLES) return [];

  const current = behaviorSnapshot(action, now);
  const findings: DetectionFinding[] = [];
  const assessment = assessAction(action, config);
  const evidence = { tool: action.tool, task_class: taskClass, sample_count: samples.length, window_size: BEHAVIOR_WINDOW_SIZE };
  if (current.host && (action.tool === "call_api" || assessment.externalSink) && establishedNovelty(samples.map((item) => item.host), current.host)) {
    findings.push(finding("tool target host deviates from the warm sliding behavior window", 35, { ...evidence, host: current.host, learned_hosts: frequentValues(samples.map((item) => item.host)) }));
  }
  if (current.recipient && action.tool === "send_email" && establishedNovelty(samples.map((item) => item.recipient), current.recipient)) {
    findings.push(finding("email recipient deviates from the warm sliding behavior window", 35, { ...evidence, recipient: current.recipient, learned_recipients: frequentValues(samples.map((item) => item.recipient)) }));
  }
  if (current.pathRoot && (action.tool === "read_file" || action.tool === "write_file") && establishedNovelty(samples.map((item) => item.pathRoot), current.pathRoot)) {
    findings.push(finding("file path root deviates from the warm sliding behavior window", 25, { ...evidence, root: current.pathRoot, learned_roots: frequentValues(samples.map((item) => item.pathRoot)) }));
  }

  const bytesP90 = percentile(samples.map((item) => item.paramBytes), 0.9);
  if (bytesP90 > 0 && current.paramBytes > Math.max(bytesP90 * 4, bytesP90 + 4096)) {
    findings.push(finding("tool parameter size is anomalous for the sliding behavior window", 25, { ...evidence, param_bytes: current.paramBytes, window_p90_param_bytes: bytesP90 }));
  }
  const keysP90 = percentile(samples.map((item) => item.paramKeys), 0.9);
  if (keysP90 > 0 && current.paramKeys > Math.max(keysP90 * 3, keysP90 + 8)) {
    findings.push(finding("tool parameter shape is anomalous for the sliding behavior window", 20, { ...evidence, param_keys: current.paramKeys, window_p90_param_keys: keysP90 }));
  }
  return findings;
}

export function updateBehaviorProfile(state: BehaviorState, action: PolicyActionInput, now = Date.now()): void {
  const taskClass = taskClassFor(state.taskSpec);
  const key = profileKey(action.tool, taskClass);
  const samples = activeSamples(state.behaviorProfiles.get(key), now);
  samples.push(behaviorSnapshot(action, now));
  state.behaviorProfiles.delete(key);
  state.behaviorProfiles.set(key, { tool: action.tool, taskClass, samples: samples.slice(-BEHAVIOR_WINDOW_SIZE) });
  while (state.behaviorProfiles.size > 64) {
    const oldest = state.behaviorProfiles.keys().next().value;
    if (oldest === undefined) break;
    state.behaviorProfiles.delete(oldest);
  }
}

export function behaviorProfileKey(tool: string, taskSpec?: TaskSpec): string {
  return profileKey(tool, taskClassFor(taskSpec));
}

function taskClassFor(taskSpec?: TaskSpec): string {
  if (!taskSpec?.capabilities.length) return "unscoped";
  return Array.from(new Set(taskSpec.capabilities.map((item) => `${item.resourceType}:${item.action}:${item.effect}`))).sort().join("+");
}

function profileKey(tool: string, taskClass: string): string {
  return `${tool}::${taskClass}`;
}

function activeSamples(profile: BehaviorProfile | undefined, now: number): BehaviorSample[] {
  const cutoff = now - BEHAVIOR_SAMPLE_TTL_MS;
  return (profile?.samples || []).filter((sample) => sample.observedAt >= cutoff).slice(-BEHAVIOR_WINDOW_SIZE);
}

function behaviorSnapshot(action: PolicyActionInput, observedAt: number): BehaviorSample {
  const path = readFirstString(action.args, ["path", "file", "filename", "target"]);
  const serialized = safeStringify(action.args) || "";
  return {
    observedAt,
    host: hostFromUrl(readFirstString(action.args, ["url", "href", "endpoint", "target"])),
    recipient: readFirstString(action.args, ["recipient", "to", "email", "target"]).toLowerCase(),
    pathRoot: rootFromPath(path),
    paramBytes: Buffer.byteLength(serialized, "utf8"),
    paramKeys: countKeys(action.args),
  };
}

function establishedNovelty(values: string[], current: string): boolean {
  const filtered = values.filter(Boolean);
  if (!filtered.length || filtered.includes(current)) return false;
  const dominant = Math.max(...valueCounts(filtered).values());
  return dominant >= Math.max(7, Math.ceil(filtered.length * 0.7));
}

function frequentValues(values: string[]): string[] {
  return Array.from(valueCounts(values.filter(Boolean)).entries()).sort((left, right) => right[1] - left[1]).slice(0, 8).map(([value]) => value);
}

function valueCounts(values: string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
  return counts;
}

function percentile(values: number[], ratio: number): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * ratio))];
}

function rootFromPath(path: string): string {
  const normalized = path.trim().replace(/\\/g, "/");
  if (!normalized) return "";
  if (normalized.startsWith("//") && !normalized.startsWith("///")) {
    const [server = "", share = ""] = normalized.slice(2).split("/").filter(Boolean);
    return share ? `//${server.toLowerCase()}/${share.toLowerCase()}` : `//${server.toLowerCase()}`;
  }
  if (/^[a-z]:/i.test(normalized)) return normalized.slice(0, 2).toLowerCase();
  if (normalized.startsWith("/")) return `/${normalized.replace(/^\/+/, "").split("/")[0]}`;
  return normalized.replace(/^(?:\.\/)+/, "").split("/")[0] || ".";
}

function countKeys(value: unknown, visited = new WeakSet<object>()): number {
  if (!value || typeof value !== "object" || visited.has(value)) return 0;
  visited.add(value);
  if (Array.isArray(value)) return value.reduce((sum, item) => sum + countKeys(item, visited), 0);
  return Object.values(value as Record<string, unknown>).reduce<number>(
    (sum, item) => sum + 1 + countKeys(item, visited),
    0,
  );
}

function finding(reason: string, score: number, evidence: Record<string, unknown>): DetectionFinding {
  return { layer: "Behavior Baseline", finding_type: "behavioral", verdict: "require_approval", reason, score, evidence };
}
