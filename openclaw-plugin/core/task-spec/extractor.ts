import { createHash } from "node:crypto";
import type {
  CapabilityAction,
  CapabilityEffect,
  CapabilityResource,
  CapabilitySource,
  TaskCapability,
  TaskSpec,
} from "./types.ts";

const CANONICAL_TOOLS = [
  "read_webpage",
  "call_api",
  "read_file",
  "write_file",
  "send_email",
  "memory_read",
  "memory_write",
  "shell_exec",
];

const ACTION_DENIALS: Array<[string, RegExp]> = [
  ["send_email", /(?:不要|别|不得|禁止|不能|无需).{0,18}(?:发送|发邮件|发给|邮件|外发)|\b(?:do not|don't|never|must not|no)\b.{0,24}\b(?:send|email|mail|forward)\b/i],
  ["write_file", /(?:不要|别|不得|禁止|不能|无需).{0,18}(?:写入|保存|修改|创建)|\b(?:do not|don't|never|must not|no)\b.{0,24}\b(?:write|save|edit|create)\b/i],
  ["shell_exec", /(?:不要|别|不得|禁止|不能|无需).{0,18}(?:执行|运行|命令|终端)|\b(?:do not|don't|never|must not|no)\b.{0,24}\b(?:execute|run|shell|command)\b/i],
  ["memory_write", /(?:不要|别|不得|禁止|不能|无需).{0,18}(?:记住|记忆|长期保存|持久)|\b(?:do not|don't|never|must not|no)\b.{0,24}\b(?:remember|persist|memory)\b/i],
];

type Clause = { text: string; start: number; end: number; dataOnly: boolean };

type Candidate = {
  action: CapabilityAction;
  resourceType: CapabilityResource;
  effect: CapabilityEffect;
  targets: string[];
  allowedMethods?: string[];
  allowedPaths?: string[];
  allowedHosts?: string[];
  allowedRecipients?: string[];
  confidence: number;
};

export function deriveTaskSpecV2(
  task: string,
  sensitiveAssets: string[],
  source: CapabilitySource = "user",
): TaskSpec {
  const normalized = normalizeTaskText(task);
  const hash = createHash("sha256").update(normalized, "utf8").digest("hex");
  const capabilities: TaskCapability[] = [];

  for (const clause of splitClauses(normalized)) {
    if (!clause.text.trim() || clause.dataOnly) continue;
    for (const candidate of candidatesForClause(clause.text)) {
      const concrete = targetIsConcrete(candidate);
      if (!concrete) continue;
      capabilities.push({
        action: candidate.action,
        resourceType: candidate.resourceType,
        targets: unique(candidate.targets),
        effect: candidate.effect,
        constraints: compactConstraints(candidate),
        evidence: {
          sourceMessageHash: hash,
          source,
          explicitSpan: clause.text.trim().slice(0, 320),
          explicitAuthorization: true,
          insideQuotation: false,
          negated: false,
          targetIsConcrete: true,
          confidence: candidate.confidence,
        },
        expiresAfterTurn: 1,
      });
    }
  }

  const merged = mergeCapabilities(capabilities);
  const deniedTools = ACTION_DENIALS
    .filter(([, pattern]) => testPattern(pattern, normalized))
    .map(([tool]) => tool);
  const allowedTools = unique(merged.flatMap(capabilityTools));
  if (/\b(?:search|look up|find)\b|(?:搜索|检索|查找)/i.test(stripNonAuthoritativeText(normalized))) {
    allowedTools.push("web_search");
  }
  const effectiveAllowed = unique(allowedTools.filter((tool) => !deniedTools.includes(tool)));
  const targets = unique(merged.flatMap((capability) => capability.targets.filter(isNetworkTarget)));

  return {
    version: 2,
    task,
    capabilities: merged,
    denied_tools: unique(deniedTools),
    allowed_tools: effectiveAllowed,
    forbidden_tools: CANONICAL_TOOLS.filter((tool) => !effectiveAllowed.includes(tool)),
    allowed_targets: targets,
    sensitive_assets: [...sensitiveAssets],
    output_policy: effectiveAllowed.includes("send_email")
      ? "External delivery is limited to explicitly authorized recipients and payloads."
      : "Only answer the user; do not create unrequested external side effects.",
  };
}

export function stripNonAuthoritativeText(text: string): string {
  const ranges = nonAuthoritativeRanges(text);
  if (!ranges.length) return text;
  const chars = text.split("");
  for (const [start, end] of ranges) {
    for (let index = start; index < end && index < chars.length; index += 1) chars[index] = " ";
  }
  return chars.join("");
}

function candidatesForClause(clause: string): Candidate[] {
  const candidates: Candidate[] = [];
  const recipients = extractEmails(clause);
  const paths = extractPaths(clause);
  const urls = extractUrls(clause);

  if (recipients.length && explicitSend(clause) && !analysisOnly(clause) && !negatedAction(clause, "send")) {
    candidates.push({
      action: "send",
      resourceType: "email",
      effect: "external_side_effect",
      targets: recipients,
      allowedRecipients: recipients.map((item) => item.toLowerCase()),
      allowedPaths: paths,
      confidence: 0.98,
    });
  }

  if (paths.length && explicitWrite(clause) && !negatedAction(clause, "write")) {
    candidates.push({
      action: "write",
      resourceType: "file",
      effect: "persistent_change",
      targets: paths,
      allowedPaths: paths,
      confidence: 0.96,
    });
  }

  if (paths.length && explicitRead(clause) && !negatedAction(clause, "read")) {
    candidates.push({
      action: "read",
      resourceType: "file",
      effect: "read_only",
      targets: paths,
      allowedPaths: paths,
      confidence: 0.96,
    });
  }

  if (urls.length && explicitNetworkRead(clause) && !negatedAction(clause, "read")) {
    candidates.push({
      action: "read",
      resourceType: "api",
      effect: "read_only",
      targets: urls,
      allowedMethods: ["GET", "HEAD"],
      allowedHosts: urls.map(hostFromTarget).filter(Boolean),
      confidence: 0.96,
    });
  }

  if (urls.length && explicitNetworkRequest(clause) && !negatedAction(clause, "request")) {
    const networkWrite = /\b(?:post|put|patch|delete|upload|submit|send|publish)\b|(?:上报|上传|提交|发布|外发|写入接口)/i.test(clause);
    candidates.push({
      action: "request",
      resourceType: "api",
      effect: networkWrite ? "external_side_effect" : "read_only",
      targets: urls,
      allowedMethods: networkWrite ? ["POST", "PUT", "PATCH"] : ["GET", "HEAD"],
      allowedHosts: urls.map(hostFromTarget).filter(Boolean),
      confidence: networkWrite ? 0.97 : 0.9,
    });
  }

  if (explicitShell(clause) && !negatedAction(clause, "execute")) {
    const commands = extractInlineCommands(clause);
    const systemRead = /(?:系统版本|目录大小|磁盘|内存|cpu|uname|du\b|df\b|os-release)|\b(?:system version|disk usage|cpu info)\b/i.test(clause);
    if (commands.length || systemRead) {
      candidates.push({
        action: "execute",
        resourceType: "shell",
        effect: "external_side_effect",
        targets: commands.length ? commands : ["system:read-only"],
        confidence: commands.length ? 0.98 : 0.9,
      });
    }
  }

  if (explicitMemoryWrite(clause) && !negatedAction(clause, "persist")) {
    candidates.push({
      action: "persist",
      resourceType: "memory",
      effect: "persistent_change",
      targets: [`memory:${fingerprint(clause)}`],
      confidence: 0.94,
    });
  }

  return dedupeCandidates(candidates);
}

function explicitSend(text: string): boolean {
  return /\b(?:please\s+)?(?:send|email|mail|forward)\b/i.test(text)
    || /(?:请|帮我|现在|直接)?(?:把|将).{0,80}(?:发送给|发给|邮件给)/i.test(text)
    || /(?:请|帮我)?给\s*[^，,。；;]{1,80}(?:发|发送).{0,30}(?:邮件|报告|文件|消息)/i.test(text)
    || /^\s*(?:(?:请|帮我|现在|直接)\s*)?(?:发送|发邮件|外发).{0,80}(?:给|到)/i.test(text);
}

function explicitWrite(text: string): boolean {
  return /\b(?:please\s+)?(?:write|save|edit|create|update)\b/i.test(text)
    || /(?:请|帮我|把|将).{0,60}(?:写入|保存到|另存为|修改|创建)/i.test(text)
    || /(?:写入|保存到|另存为|修改|创建)\s*[^，,。；;]{1,120}$/i.test(text);
}

function explicitRead(text: string): boolean {
  return /\b(?:please\s+)?(?:read|open|inspect|review|summarize)\b/i.test(text)
    || /(?:请|帮我|查看|读取|打开|审查|总结).{0,80}(?:文件|文档|报告|代码|\.\w+)/i.test(text);
}

function explicitNetworkRead(text: string): boolean {
  return /\b(?:visit|open|fetch|read|inspect|review|summarize|check)\b/i.test(text)
    || /(?:访问|打开|读取|查看|检查|总结).{0,80}(?:网页|网站|页面|链接|https?:|mock:)/i.test(text);
}

function explicitNetworkRequest(text: string): boolean {
  return /\b(?:call|request|post|put|patch|delete|upload|submit|publish)\b/i.test(text)
    || /(?:调用|请求|上报|上传|提交|发布).{0,100}(?:接口|api|https?:|mock:)/i.test(text);
}

function explicitShell(text: string): boolean {
  return /\b(?:run|execute)\b.{0,80}\b(?:command|build|test|git|npm|pytest|shell)\b/i.test(text)
    || /(?:执行|运行).{0,80}(?:命令|构建|测试|git|npm|pytest|shell|powershell)/i.test(text)
    || /(?:系统版本|目录大小|磁盘使用|内存信息|cpu信息)/i.test(text);
}

function explicitMemoryWrite(text: string): boolean {
  return /\b(?:please\s+)?(?:remember|persist|store in (?:long[- ]term )?memory)\b/i.test(text)
    || /(?:请|帮我)?(?:记住|写入长期记忆|保存为长期偏好|记录到经验库|记录经验)/i.test(text);
}

function analysisOnly(text: string): boolean {
  if (!/^\s*(?:分析|解释|讨论|总结|翻译|引用|analy[sz]e|explain|discuss|summari[sz]e|translate|quote)/i.test(text)) return false;
  return !/(?:并|然后|接着|随后|and then|then).{0,80}(?:把|将|给|发送|发邮件|保存|写入|执行|运行|记住|send|email|write|save|execute|run|remember)/i.test(text);
}

function negatedAction(text: string, action: CapabilityAction): boolean {
  const actionPatterns: Record<CapabilityAction, string> = {
    read: "读取|打开|查看|访问|总结|read|open|visit|summari[sz]e",
    write: "写入|保存|修改|创建|write|save|edit|create",
    send: "发送|发邮件|发给|邮件|外发|send|email|mail|forward",
    execute: "执行|运行|命令|execute|run|command",
    request: "调用|请求|上报|上传|提交|call|request|post|upload|submit",
    persist: "记住|记忆|持久|remember|memory|persist",
  };
  const pattern = actionPatterns[action];
  return new RegExp(`(?:不要|别|不得|禁止|不能|无需|仅分析|只分析|只总结|仅总结).{0,40}(?:${pattern})`, "i").test(text)
    || new RegExp(`\\b(?:do not|don't|never|must not|without)\\b.{0,40}\\b(?:${pattern})\\b`, "i").test(text);
}

function splitClauses(text: string): Clause[] {
  const ranges = nonAuthoritativeRanges(text);
  const clauses: Clause[] = [];
  const separator = /[\n。！？!?；;]|(?:，|,)\s*(?:但|但是|不过|however\b|but\b)/gi;
  let start = 0;
  for (const match of text.matchAll(separator)) {
    const end = match.index ?? start;
    const clauseText = maskRanges(text, start, end, ranges);
    clauses.push({ text: clauseText, start, end, dataOnly: !clauseText.trim() });
    start = end + match[0].length;
  }
  const clauseText = maskRanges(text, start, text.length, ranges);
  clauses.push({ text: clauseText, start, end: text.length, dataOnly: !clauseText.trim() });
  return clauses;
}

function nonAuthoritativeRanges(text: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  const patterns = [
    /```[\s\S]*?```/g,
    /"[^"\n]*"/g,
    /“[^”\n]*”/g,
    /‘[^’\n]*’/g,
    /「[^」\n]*」/g,
    /『[^』\n]*』/g,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      ranges.push([match.index ?? 0, (match.index ?? 0) + match[0].length]);
    }
  }
  const dataFrame = /(?:summari[sz]e|analy[sz]e|translate|quote|总结|分析|翻译|引用)(?:\s+the)?(?:\s+following|以下|下面)(?:\s*(?:text|content|文字|内容))?\s*[:：]/gi;
  for (const match of text.matchAll(dataFrame)) {
    const start = (match.index ?? 0) + match[0].length;
    ranges.push([start, text.length]);
  }
  return mergeRanges(ranges);
}

function maskRanges(text: string, start: number, end: number, ranges: Array<[number, number]>): string {
  const chars = text.slice(start, end).split("");
  for (const [rangeStart, rangeEnd] of ranges) {
    const localStart = Math.max(0, rangeStart - start);
    const localEnd = Math.min(chars.length, rangeEnd - start);
    for (let index = localStart; index < localEnd; index += 1) chars[index] = " ";
  }
  return chars.join("");
}

function mergeRanges(ranges: Array<[number, number]>): Array<[number, number]> {
  const sorted = [...ranges].sort((left, right) => left[0] - right[0]);
  const merged: Array<[number, number]> = [];
  for (const range of sorted) {
    const last = merged[merged.length - 1];
    if (!last || range[0] > last[1]) merged.push([...range]);
    else last[1] = Math.max(last[1], range[1]);
  }
  return merged;
}

function extractEmails(text: string): string[] {
  return unique(text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || []);
}

function extractUrls(text: string): string[] {
  return unique((text.match(/\b(?:https?:\/\/|mock:\/\/)[^\s，。；;）)\]}>"']+/gi) || []).map(cleanTarget));
}

function extractPaths(text: string): string[] {
  const paths = text.match(/(?:[A-Za-z]:[\\/]|~[\\/]|\.\.\/?|\.\/)?[A-Za-z0-9_.@-]+(?:[\\/][A-Za-z0-9_.@* -]+)*\.(?:md|txt|json|jsonl|ya?ml|toml|ini|env|py|ts|tsx|js|jsx|css|html|csv|pdf|docx?|xlsx?|log)|(?:^|[\s("'`])\.env(?:\.[A-Za-z0-9_-]+)?/gi) || [];
  return unique(paths.map((item) => item.trim().replace(/^[\s("'`]+|[\s，,。；;）)\]}>"'`]+$/g, "")));
}

function extractInlineCommands(text: string): string[] {
  const commands: string[] = [];
  for (const match of text.matchAll(/`([^`\n]+)`/g)) commands.push(match[1].trim());
  for (const match of text.matchAll(/(?:执行命令|运行命令|run command|execute command)\s*[:：]\s*([^。；;\n]+)/gi)) {
    commands.push(match[1].trim());
  }
  if (/\brun\s+(?:the\s+)?tests?\b/i.test(text) || /(?:运行|执行)\s*测试/i.test(text)) commands.push("task:test");
  if (/\brun\s+(?:the\s+)?build\b/i.test(text) || /(?:运行|执行)\s*构建/i.test(text)) commands.push("task:build");
  if (/\bgit\s+(?:status|diff|log|show)\b/i.test(text)) {
    const match = text.match(/\bgit\s+(?:status|diff|log|show)(?:\s+[^，,。；;\n]+)?/i);
    if (match) commands.push(match[0].trim());
  }
  return unique(commands);
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
    current.evidence.confidence = Math.max(current.evidence.confidence, capability.evidence.confidence);
    current.evidence.explicitSpan = `${current.evidence.explicitSpan}; ${capability.evidence.explicitSpan}`.slice(0, 320);
  }
  return [...merged.values()];
}

function compactConstraints(candidate: Candidate): TaskCapability["constraints"] {
  const output: TaskCapability["constraints"] = {};
  if (candidate.allowedMethods?.length) output.allowedMethods = unique(candidate.allowedMethods.map((item) => item.toUpperCase()));
  if (candidate.allowedPaths?.length) output.allowedPaths = unique(candidate.allowedPaths);
  if (candidate.allowedHosts?.length) output.allowedHosts = unique(candidate.allowedHosts.map((item) => item.toLowerCase()));
  if (candidate.allowedRecipients?.length) output.allowedRecipients = unique(candidate.allowedRecipients.map((item) => item.toLowerCase()));
  return output;
}

function capabilityTools(capability: TaskCapability): string[] {
  if (capability.resourceType === "file" && capability.action === "read") return ["read_file"];
  if (capability.resourceType === "file" && capability.action === "write") return ["write_file"];
  if (capability.resourceType === "email" && capability.action === "send") return ["send_email"];
  if (capability.resourceType === "api" && capability.action === "read") return ["read_webpage", "call_api"];
  if (capability.resourceType === "api" && capability.action === "request") return ["call_api"];
  if (capability.resourceType === "shell" && capability.action === "execute") return ["shell_exec"];
  if (capability.resourceType === "memory" && capability.action === "persist") return ["memory_read", "memory_write"];
  if (capability.resourceType === "memory" && capability.action === "read") return ["memory_read"];
  return [];
}

function targetIsConcrete(candidate: Candidate): boolean {
  if (candidate.resourceType === "memory") return candidate.targets.length > 0;
  if (candidate.resourceType === "shell") return candidate.targets.length > 0;
  return candidate.targets.some((target) => Boolean(target.trim()));
}

function hostFromTarget(target: string): string {
  try {
    return new URL(target).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function cleanTarget(value: string): string {
  return value.replace(/[.,;:\])}>'"，。；：）】》”’]+$/g, "");
}

function normalizeTaskText(text: string): string {
  return text.normalize("NFKC").replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00ad]/g, "").trim();
}

function isNetworkTarget(value: string): boolean {
  return /^(?:https?:\/\/|mock:\/\/)/i.test(value);
}

function fingerprint(value: string): string {
  return createHash("sha256").update(value.trim(), "utf8").digest("hex").slice(0, 16);
}

function testPattern(pattern: RegExp, text: string): boolean {
  pattern.lastIndex = 0;
  return pattern.test(text);
}

function dedupeCandidates(candidates: Candidate[]): Candidate[] {
  const seen = new Set<string>();
  return candidates.filter((candidate) => {
    const key = `${candidate.action}:${candidate.resourceType}:${candidate.effect}:${candidate.targets.sort().join("|")}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function mergeOptional(left?: string[], right?: string[]): string[] | undefined {
  const merged = unique([...(left || []), ...(right || [])]);
  return merged.length ? merged : undefined;
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}
