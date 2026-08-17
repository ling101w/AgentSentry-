import { deriveTaskSpecV2 } from "./extractor.ts";
import type { TaskCapability, TaskSpec } from "./types.ts";

const CANONICAL_TOOLS = [
  "read_webpage",
  "call_api",
  "read_file",
  "write_file",
  "send_email",
  "memory_read",
  "memory_write",
  "shell_exec",
  "calendar_write",
  "cloud_file_write",
  "cloud_file_share",
];
const AUTHORIZATION_IDLE_TURNS = 12;

export type AuthorizationMessageKind =
  | "new_task"
  | "task_continuation"
  | "preference"
  | "confirmation"
  | "data_only"
  | "chatter";

export type AuthorizationState = {
  activeTask: string;
  turn: number;
  lastMessage: string;
  lastKind: AuthorizationMessageKind;
  taskSpec: TaskSpec;
  preferences: string[];
  explicitDenials: string[];
  temporaryApprovals: string[];
  expiresAtTurn: number;
};

export type AuthorizationUpdate = {
  state: AuthorizationState;
  changed: boolean;
  kind: AuthorizationMessageKind;
};

export function createAuthorizationState(sensitiveAssets: string[]): AuthorizationState {
  const taskSpec = deriveTaskSpecV2("", sensitiveAssets, "user");
  return {
    activeTask: "",
    turn: 0,
    lastMessage: "",
    lastKind: "chatter",
    taskSpec,
    preferences: [],
    explicitDenials: [],
    temporaryApprovals: [],
    expiresAtTurn: 0,
  };
}

export function updateAuthorizationState(
  previous: AuthorizationState | undefined,
  rawMessage: string,
  sensitiveAssets: string[],
): AuthorizationUpdate {
  const base = previous || createAuthorizationState(sensitiveAssets);
  const current = authorizationExpired(base) ? createAuthorizationState(sensitiveAssets) : base;
  const message = extractAuthoritativeUserRequest(rawMessage);
  if (!message || message === current.lastMessage) {
    return { state: current, changed: false, kind: current.lastKind };
  }

  const derived = deriveTaskSpecV2(message, sensitiveAssets, "user");
  const kind = classifyMessage(message, current, derived);
  const turn = current.turn + 1;

  if (kind === "chatter" || kind === "data_only" || kind === "confirmation") {
    return {
      state: {
        ...current,
        turn,
        lastMessage: message,
        lastKind: kind,
        taskSpec: {
          ...current.taskSpec,
          task_mode: kind,
        },
        expiresAtTurn: kind === "confirmation" && current.activeTask
          ? turn + AUTHORIZATION_IDLE_TURNS
          : current.expiresAtTurn,
      },
      changed: true,
      kind,
    };
  }

  const shouldMerge = Boolean(current.activeTask)
    && (kind === "task_continuation" || kind === "preference" || derived.capabilities.length === 0);
  const taskSpec = shouldMerge ? mergeTaskSpecs(current.taskSpec, derived, message) : derived;
  const preferences = kind === "preference"
    ? unique([...current.preferences, message]).slice(-16)
    : current.preferences;
  const explicitDenials = unique([...current.explicitDenials, ...derived.denied_tools]);

  return {
    state: {
      ...current,
      activeTask: taskSpec.task,
      turn,
      lastMessage: message,
      lastKind: kind,
      taskSpec: {
        ...taskSpec,
        task_mode: kind,
        denied_tools: unique([...taskSpec.denied_tools, ...explicitDenials]),
        allowed_tools: taskSpec.allowed_tools.filter((tool) => !explicitDenials.includes(tool)),
        forbidden_tools: CANONICAL_TOOLS.filter((tool) => !taskSpec.allowed_tools.includes(tool) || explicitDenials.includes(tool)),
      },
      preferences,
      explicitDenials,
      expiresAtTurn: turn + AUTHORIZATION_IDLE_TURNS,
    },
    changed: true,
    kind,
  };
}

function authorizationExpired(state: AuthorizationState): boolean {
  return Boolean(state.activeTask && state.expiresAtTurn > 0 && state.turn >= state.expiresAtTurn);
}

export function extractAuthoritativeUserRequest(text: string): string {
  const normalized = String(text || "").normalize("NFKC").trim();
  if (!normalized) return "";
  const marker = normalized.lastIndexOf("【原始请求】");
  if (marker >= 0) {
    const original = normalized.slice(marker + "【原始请求】".length).trim();
    if (original) return original;
  }
  return normalized;
}

function classifyMessage(
  message: string,
  current: AuthorizationState,
  derived: TaskSpec,
): AuthorizationMessageKind {
  const stripped = stripQuotedAndCode(message).trim();
  const compact = stripped.replace(/\s+/g, "");
  if (!compact) return "data_only";
  if (isDataOnlyMessage(message)) return "data_only";
  if (isChatter(compact)) return "chatter";
  if (isConfirmation(compact)) return "confirmation";
  if (isOrdinaryPreference(stripped, derived)) return "preference";
  if (!current.activeTask) return "new_task";
  if (isContinuation(stripped) || derived.denied_tools.length > 0) return "task_continuation";
  if (derived.capabilities.length === 0) return "chatter";
  if (sameTaskFamily(current.taskSpec, derived)) return "task_continuation";
  return "new_task";
}

function mergeTaskSpecs(left: TaskSpec, right: TaskSpec, message: string): TaskSpec {
  const capabilities = mergeCapabilities([...left.capabilities, ...right.capabilities]);
  const denied = unique([...left.denied_tools, ...right.denied_tools]);
  const allowed = unique([...left.allowed_tools, ...right.allowed_tools]).filter((tool) => !denied.includes(tool));
  return {
    ...left,
    task: `${left.task || "用户任务"}\n补充授权: ${message}`.slice(0, 2400),
    capabilities,
    denied_tools: denied,
    allowed_tools: allowed,
    forbidden_tools: CANONICAL_TOOLS.filter((tool) => !allowed.includes(tool)),
    allowed_targets: unique([...left.allowed_targets, ...right.allowed_targets]),
    sensitive_assets: unique([...left.sensitive_assets, ...right.sensitive_assets]),
    delegations: mergeDelegations(left.delegations, right.delegations),
    output_policy: allowed.includes("send_email")
      ? "External delivery is limited to explicitly authorized recipients and payloads."
      : left.output_policy || right.output_policy,
  };
}

function mergeCapabilities(capabilities: TaskCapability[]): TaskCapability[] {
  const merged = new Map<string, TaskCapability>();
  for (const capability of capabilities) {
    const key = `${capability.action}:${capability.resourceType}:${capability.effect}`;
    const current = merged.get(key);
    if (!current) {
      merged.set(key, structuredClone(capability));
      continue;
    }
    current.targets = unique([...current.targets, ...capability.targets]);
    current.constraints.allowedMethods = mergeOptional(current.constraints.allowedMethods, capability.constraints.allowedMethods);
    current.constraints.allowedPaths = mergeOptional(current.constraints.allowedPaths, capability.constraints.allowedPaths);
    current.constraints.allowedHosts = mergeOptional(current.constraints.allowedHosts, capability.constraints.allowedHosts);
    current.constraints.allowedRecipients = mergeOptional(current.constraints.allowedRecipients, capability.constraints.allowedRecipients);
    current.constraints.allowedOperations = mergeOptional(current.constraints.allowedOperations, capability.constraints.allowedOperations);
    current.evidence.explicitSpan = `${current.evidence.explicitSpan}; ${capability.evidence.explicitSpan}`.slice(0, 320);
    current.evidence.confidence = Math.max(current.evidence.confidence, capability.evidence.confidence);
  }
  return [...merged.values()];
}

function sameTaskFamily(left: TaskSpec, right: TaskSpec): boolean {
  const leftSet = new Set(left.capabilities.map((item) => `${item.resourceType}:${item.action}`));
  return right.capabilities.some((item) => leftSet.has(`${item.resourceType}:${item.action}`));
}

function isOrdinaryPreference(text: string, spec: TaskSpec): boolean {
  if (!spec.allowed_tools.includes("memory_write")) return false;
  if (spec.allowed_tools.some((tool) => ["send_email", "shell_exec", "call_api", "calendar_write", "cloud_file_write", "cloud_file_share"].includes(tool))) return false;
  return !/(忽略|绕过|禁用|关闭|静默|无需|不必).{0,40}(安全|审批|策略|审计|确认|规则)/i.test(text)
    && !/(私钥|密钥|凭据|token|api[_ -]?key|\.env|openclaw\.json|curl\s*\|)/i.test(text);
}

function isContinuation(text: string): boolean {
  const trimmed = text.trim();
  return /^(?:另外|还有|顺便|接着|然后|再|补充|继续|同时|对了|此外|并且|把|将|请再)(?:\s|，|,|。|：|:|$)?/i.test(trimmed)
    || /^(?:please also|also|then)\b/i.test(trimmed)
    || /(上一|刚才|前面|这个任务|该任务|这份|这个文件|这个页面|摘要|报告|结果)/i.test(trimmed);
}

function isChatter(compact: string): boolean {
  return /^(谢谢|好的|好|嗯|明白|知道了|可以了|继续|你能做什么|介绍一下|hello|hi|thanks|ok|okay)$/i.test(compact)
    || compact.length <= 8 && /^(好|嗯|行|可以|收到|继续|ok|yes)$/i.test(compact);
}

function isConfirmation(compact: string): boolean {
  return /^(确认|允许|同意|批准|可以执行|执行吧|继续执行|yes|approve|approved|allow)$/i.test(compact);
}

function isDataOnlyMessage(text: string): boolean {
  return /^\s*(?:```|>|原文[:：]|内容[:：]|以下是|下面是|请总结以下|请分析以下)/i.test(text);
}

function stripQuotedAndCode(text: string): string {
  return text
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/"[^"\n]*"/g, " ")
    .replace(/“[^”\n]*”/g, " ")
    .replace(/‘[^’\n]*’/g, " ")
    .replace(/「[^」\n]*」/g, " ")
    .replace(/『[^』\n]*』/g, " ");
}

function mergeOptional(left?: string[], right?: string[]): string[] | undefined {
  const merged = unique([...(left || []), ...(right || [])]);
  return merged.length ? merged : undefined;
}

function mergeDelegations(
  left: TaskSpec["delegations"],
  right: TaskSpec["delegations"],
): TaskSpec["delegations"] {
  const merged = [...(left || []), ...(right || [])];
  const uniqueDelegations = merged.filter((item, index, all) => all.findIndex((candidate) =>
    candidate.sourceType === item.sourceType
    && candidate.sender === item.sender
    && candidate.subject === item.subject
  ) === index);
  return uniqueDelegations.length ? uniqueDelegations : undefined;
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}
