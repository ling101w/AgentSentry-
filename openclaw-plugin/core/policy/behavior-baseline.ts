import type { PluginConfig } from "../../config.ts";
import type { DetectionFinding } from "../detect.ts";
import { safeStringify } from "../redact.ts";
import { assessAction, type PolicyActionInput } from "./action-assessment.ts";
import { hostFromUrl, readFirstString } from "./value-utils.ts";

export type BehaviorProfile = {
  calls: number;
  hosts: string[];
  recipients: string[];
  pathRoots: string[];
  maxParamBytes: number;
  maxParamKeys: number;
};

type BehaviorState = {
  behaviorProfiles: Map<string, BehaviorProfile>;
};

export function behaviorAnomalyFindingsFor(
  action: PolicyActionInput,
  state: BehaviorState,
  config: PluginConfig,
): DetectionFinding[] {
  const profile = state.behaviorProfiles.get(action.tool);
  if (!profile || profile.calls < 2) return [];
  const current = behaviorSnapshot(action);
  const findings: DetectionFinding[] = [];
  const assessment = assessAction(action, config);
  if (current.host && profile.hosts.length && !profile.hosts.includes(current.host) && (action.tool === "call_api" || assessment.externalSink)) {
    findings.push(finding("Behavior Baseline", "behavioral", "require_approval", "tool target host deviates from the statistical session baseline", 35, {
      tool: action.tool,
      host: current.host,
      learned_hosts: profile.hosts.slice(-6),
    }));
  }
  if (current.recipient && profile.recipients.length && !profile.recipients.includes(current.recipient) && action.tool === "send_email") {
    findings.push(finding("Behavior Baseline", "behavioral", "require_approval", "email recipient deviates from the statistical session baseline", 35, {
      tool: action.tool,
      recipient: current.recipient,
      learned_recipients: profile.recipients.slice(-6),
    }));
  }
  if (current.pathRoot && profile.pathRoots.length && !profile.pathRoots.includes(current.pathRoot) && (action.tool === "read_file" || action.tool === "write_file")) {
    findings.push(finding("Behavior Baseline", "behavioral", "require_approval", "file path root deviates from the statistical session baseline", 25, {
      tool: action.tool,
      root: current.pathRoot,
      learned_roots: profile.pathRoots.slice(-6),
    }));
  }
  if (profile.maxParamBytes > 0 && current.paramBytes > Math.max(profile.maxParamBytes * 4, profile.maxParamBytes + 4096)) {
    findings.push(finding("Behavior Baseline", "behavioral", "require_approval", "tool parameter size is anomalous for this session", 25, {
      tool: action.tool,
      param_bytes: current.paramBytes,
      learned_max_param_bytes: profile.maxParamBytes,
    }));
  }
  if (profile.maxParamKeys > 0 && current.paramKeys > Math.max(profile.maxParamKeys * 3, profile.maxParamKeys + 8)) {
    findings.push(finding("Behavior Baseline", "behavioral", "require_approval", "tool parameter shape is anomalous for this session", 20, {
      tool: action.tool,
      param_keys: current.paramKeys,
      learned_max_param_keys: profile.maxParamKeys,
    }));
  }
  return findings;
}

export function updateBehaviorProfile(state: BehaviorState, action: PolicyActionInput): void {
  const snapshot = behaviorSnapshot(action);
  const existing = state.behaviorProfiles.get(action.tool) || {
    calls: 0,
    hosts: [],
    recipients: [],
    pathRoots: [],
    maxParamBytes: 0,
    maxParamKeys: 0,
  };
  existing.calls += 1;
  if (snapshot.host) pushCapped(existing.hosts, snapshot.host, 12);
  if (snapshot.recipient) pushCapped(existing.recipients, snapshot.recipient, 12);
  if (snapshot.pathRoot) pushCapped(existing.pathRoots, snapshot.pathRoot, 12);
  existing.maxParamBytes = Math.max(existing.maxParamBytes, snapshot.paramBytes);
  existing.maxParamKeys = Math.max(existing.maxParamKeys, snapshot.paramKeys);
  state.behaviorProfiles.delete(action.tool);
  state.behaviorProfiles.set(action.tool, existing);
  if (state.behaviorProfiles.size > 24) {
    const first = state.behaviorProfiles.keys().next().value;
    if (first !== undefined) state.behaviorProfiles.delete(first);
  }
}

function behaviorSnapshot(action: PolicyActionInput): {
  host: string;
  recipient: string;
  pathRoot: string;
  paramBytes: number;
  paramKeys: number;
} {
  const url = readFirstString(action.args, ["url", "href", "endpoint", "target"]);
  const path = readFirstString(action.args, ["path", "file", "filename", "target"]);
  const serializedArgs = safeStringify(action.args) || "";
  return {
    host: hostFromUrl(url),
    recipient: readFirstString(action.args, ["recipient", "to", "email", "target"]).toLowerCase(),
    pathRoot: rootFromPath(path),
    paramBytes: Buffer.byteLength(serializedArgs, "utf8"),
    paramKeys: countKeys(action.args),
  };
}

function rootFromPath(path: string): string {
  const normalized = path.trim().replace(/\\/g, "/");
  if (!normalized) return "";
  if (normalized.startsWith("//") && !normalized.startsWith("///")) {
    const [server = "", share = ""] = normalized.slice(2).split("/").filter(Boolean);
    if (!server) return "//";
    return share ? `//${server.toLowerCase()}/${share.toLowerCase()}` : `//${server.toLowerCase()}`;
  }
  if (/^[a-z]:/i.test(normalized)) return normalized.slice(0, 2).toLowerCase();
  if (normalized.startsWith("/")) {
    const first = normalized.replace(/^\/+/, "").split("/", 1)[0];
    return first ? `/${first}` : "/";
  }
  const relative = normalized.replace(/^(?:\.\/)+/, "");
  return relative.split("/", 1)[0] || ".";
}

function countKeys(value: unknown): number {
  if (!value || typeof value !== "object") return 0;
  const pending: object[] = [value];
  const visited = new WeakSet<object>();
  let total = 0;
  while (pending.length) {
    const current = pending.pop()!;
    if (visited.has(current)) continue;
    visited.add(current);
    if (Array.isArray(current)) {
      for (const item of current) {
        if (item && typeof item === "object") pending.push(item);
      }
      continue;
    }
    for (const [, item] of Object.entries(current as Record<string, unknown>)) {
      total += 1;
      if (item && typeof item === "object") pending.push(item);
    }
  }
  return total;
}

function pushCapped(items: string[], value: string, limit: number): void {
  if (!value) return;
  const existingIndex = items.indexOf(value);
  if (existingIndex >= 0) items.splice(existingIndex, 1);
  items.push(value);
  if (items.length > limit) items.splice(0, items.length - limit);
}

function finding(
  layer: string,
  findingType: DetectionFinding["finding_type"],
  verdict: "pass" | "require_approval" | "block",
  reason: string,
  score: number,
  evidence: Record<string, unknown>,
): DetectionFinding {
  return { layer, finding_type: findingType, verdict, reason, score, evidence };
}
