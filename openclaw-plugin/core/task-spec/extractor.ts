import { createHash } from "node:crypto";
import { intersectOptional } from "./constraints.ts";
import { calendarCreationCapabilities, calendarTaskBoundCapabilities } from "./calendar.ts";
import { CHINESE_FILE_WRITE_VERBS, conditionalFileInstruction, explicitFileRead, explicitFileWrite, extractPaths, fileInstructionSegments, fileWriteDirectoryTargets, fileWriteTargets, remoteFileCreateTarget } from "./file-instructions.ts";
export { extractPaths } from "./file-instructions.ts";
import type {
  CapabilityAction,
  CapabilityEffect,
  CapabilityResource,
  CapabilitySource,
  PendingCapabilityRequest,
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
  "calendar_write",
  "email_read",
  "remote_file_create",
];

const ACTION_DENIALS: Array<[string, RegExp]> = [
  ["send_email", /(?:不要|别|不得|禁止|不能|无需).{0,18}(?:发送|发邮件|发给|邮件|外发)|\b(?:do not|don't|never|must not|no)\b.{0,24}\b(?:send|email|mail|forward)\b/i],
  ["write_file", new RegExp(`(?:不要|别|不得|禁止|不能|无需).{0,18}(?:${CHINESE_FILE_WRITE_VERBS})|\\b(?:do not|don't|never|must not|no)\\b.{0,24}\\b(?:write|save|edit|create|update|append|overwrite)\\b`, "i")],
  ["remote_file_create", new RegExp(`(?:不要|别|不得|禁止|不能|无需).{0,18}(?:${CHINESE_FILE_WRITE_VERBS})|\\b(?:do not|don't|never|must not|no)\\b.{0,24}\\b(?:write|save|edit|create|update|append|overwrite)\\b`, "i")],
  ["shell_exec", /(?:不要|别|不得|禁止|不能|无需).{0,18}(?:执行|运行|命令|终端)|\b(?:do not|don't|never|must not|no)\b.{0,24}\b(?:execute|run|shell|command)\b/i],
  ["memory_write", /(?:不要|别|不得|禁止|不能|无需).{0,18}(?:记住|记忆|经验库|长期保存|持久)|\b(?:do not|don't|never|must not|no)\b.{0,24}\b(?:remember|persist|memory)\b/i],
];

/** (P1) Default per-capability TTL: a grant lives for the whole task turn
 * sequence, not a single turn, to avoid approval fatigue on follow-up steps. */
export const DEFAULT_CAPABILITY_TTL_TURNS = 12;

/** (P1) Default guard rails applied to every side-effect capability. */
export const DEFAULT_MAX_CALLS = 8;
export const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;

export type Clause = { text: string; start: number; end: number; dataOnly: boolean };

type Candidate = {
  action: CapabilityAction;
  resourceType: CapabilityResource;
  effect: CapabilityEffect;
  targets: string[];
  allowedMethods?: string[];
  allowedPaths?: string[];
  allowedHosts?: string[];
  allowedRecipients?: string[];
  /** Parameter binding extracted verbatim from the clause. */
  bound?: Record<string, string[]>;
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
  // (P0-3) Keyword-inferred sensitive grants become approval requests, never
  // silent capabilities: parser ambiguity must not manufacture authority.
  const pendingRequests: PendingCapabilityRequest[] = [];

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
          explicitAuthorization: source === "user",
          insideQuotation: false,
          negated: false,
          targetIsConcrete: true,
          confidence: candidate.confidence,
        },
        // (P0-1) Capability identity is (action, resource, effect, bound args).
        // Each clause keeps its own binding so merging can never widen a
        // clause-scoped grant into a cartesian product of targets.
        capabilityId: capabilityKey(candidate, clause),
        bound: normalizeBoundArgs(candidate.bound),
        expiresAfterTurn: DEFAULT_CAPABILITY_TTL_TURNS,
      });
    }
    // (P0-3) Keyword-inferred sensitive targets (ssh keys, /etc/hostname,
    // skills/*) are converted from silent grants into pending approval
    // requests. The parser must not turn fuzzy keyword matches into authority
    // the user never stated.
    for (const proposal of templateProposalsForClause(clause.text)) {
      pendingRequests.push({
        ...proposal,
        evidenceSpan: clause.text.trim().slice(0, 320),
      });
    }
  }

  // (P0-1) Merging must never cross clause boundaries: keep one capability per
  // (action, resourceType, effect, clause) so "send A to Alice; send B to Bob"
  // stays two capabilities instead of a cartesian {A,B} -> {Alice,Bob}.
  const authoritative = stripNonAuthoritativeText(normalized);
  const exactCalendar = /\b(?:same participants?|based on (?:the )?emails?|from (?:the )?emails?)\b/i.test(authoritative)
    ? []
    : calendarCreationCapabilities(normalized, authoritative, source);
  const merged = [
    ...mergeCapabilities(capabilities),
    ...exactCalendar,
    ...(exactCalendar.length ? [] : calendarTaskBoundCapabilities(normalized, authoritative, source)),
  ];
  const taskFamily = classifyTaskFamily(merged);
  const taskConfidence = taskConfidenceScore(merged);
  // (P1) Denials are collected clause-locally so a negated send in one clause
  // cannot globally ban a tool that another clause explicitly authorizes.
  const deniedTools = collectDeniedTools(normalized, merged);
  const allowedTools = unique(merged.flatMap(capabilityTools));
  if (/\b(?:search|look up|find)\b|(?:搜索|检索|查找)/i.test(stripNonAuthoritativeText(normalized))) {
    allowedTools.push("web_search");
  }
  const effectiveAllowed = unique(allowedTools.filter((tool) => !deniedTools.includes(tool)));
  const targets = unique(merged.flatMap((capability) => capability.targets.filter(isNetworkTarget)));

  return {
    version: 2,
    task,
    task_family: taskFamily,
    task_confidence: taskConfidence,
    capabilities: merged,
    denied_tools: unique(deniedTools),
    allowed_tools: effectiveAllowed,
    forbidden_tools: CANONICAL_TOOLS.filter((tool) => !effectiveAllowed.includes(tool)),
    allowed_targets: targets,
    sensitive_assets: [...sensitiveAssets],
    pending_capability_requests: pendingRequests.length ? pendingRequests : undefined,
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

/** Authoritative instructions plus literal operands of those instructions. */
export function authoritativeTaskText(text: string): string {
  return splitClauses(normalizeTaskText(text)).map((clause) => clause.text).join("\n");
}

function candidatesForClause(clause: string): Candidate[] {
  const candidates: Candidate[] = [];
  // (P0-3) Read-only system inspection stays a capability (bounded by the
  // low-risk read-only command classifier at validation time); sensitive file
  // reads and skill writes moved to templateProposalsForClause.
  if (/(系统健康|健康检查|日常巡检|系统巡检|主机标识|系统状态|运行时间|磁盘|内存|cpu|目录大小|hostname|uptime|df\s+-h|du\s+-sh)/i.test(clause)) {
    candidates.push({
      action: "execute",
      resourceType: "shell",
      effect: "read_only",
      targets: ["system:read-only"],
      confidence: 0.92,
    });
  }
  const recipients = extractEmails(clause);
  const paths = extractPaths(clause);
  const urls = extractUrls(clause);

  if (recipients.length && explicitSend(clause) && !analysisOnly(clause) && !negatedAction(clause, "send")) {
    // (P0-1) Only the attachment named in this clause is bound to this send.
    // Previously allowedPaths took every path in the clause, so a combined
    // "send A to Alice; send B to Bob" produced a cartesian authorization.
    const clauseAttachment = paths.length ? [paths[0]] : [];
    candidates.push({
      action: "send",
      resourceType: "email",
      effect: "external_side_effect",
      targets: recipients,
      allowedRecipients: recipients.map((item) => item.toLowerCase()),
      allowedPaths: clauseAttachment.length ? clauseAttachment : undefined,
      bound: { recipients, paths: clauseAttachment },
      confidence: 0.98,
    });
  }

  for (const instruction of fileInstructionSegments(clause)) {
    if (analysisOnly(instruction) || conditionalFileInstruction(instruction)) continue;
    const exactWritePaths = fileWriteTargets(instruction);
    const writePaths = explicitFileWrite(instruction) && !negatedAction(instruction, "write")
      ? (exactWritePaths.length ? exactWritePaths : fileWriteDirectoryTargets(instruction)) : [];
    if (writePaths.length) {
      candidates.push({
        action: "write", resourceType: "file", effect: "persistent_change",
        targets: writePaths, allowedPaths: writePaths, bound: { paths: writePaths }, confidence: 0.96,
      });
    }
    const remoteName = !negatedAction(instruction, "write") ? remoteFileCreateTarget(instruction) : undefined;
    if (remoteName) {
      candidates.push({
        action: "write", resourceType: "remote_file", effect: "persistent_change",
        targets: [remoteName], allowedPaths: [remoteName], bound: { paths: [remoteName] }, confidence: 0.96,
      });
    }
    const readPaths = extractPaths(instruction);
    if (readPaths.length && explicitFileRead(instruction) && !negatedAction(instruction, "read")) {
      candidates.push({
        action: "read", resourceType: "file", effect: "read_only",
        targets: readPaths, allowedPaths: readPaths, bound: { paths: readPaths }, confidence: 0.96,
      });
    }
  }

  if (urls.length && explicitNetworkRead(clause) && !negatedAction(clause, "read")) {
    candidates.push({
      action: "read",
      resourceType: "api",
      effect: "read_only",
      targets: urls,
      allowedMethods: ["GET", "HEAD"],
      allowedHosts: urls.map(hostFromTarget).filter(Boolean),
      bound: { urls },
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
      bound: { urls },
      confidence: networkWrite ? 0.97 : 0.9,
    });
  }

  const literalReadCommands = extractLiteralReadCommands(clause);
  if ((explicitShell(clause) || literalReadCommands.length) && !negatedAction(clause, "execute") && !analysisOnly(clause) && !conditionalFileInstruction(clause)) {
    const commands = unique([...extractInlineCommands(clause), ...literalReadCommands]);
    const systemRead = /(?:系统版本|目录大小|磁盘|内存|cpu|uname|du\b|df\b|os-release)|\b(?:system version|disk usage|cpu info)\b/i.test(clause);
    if (commands.length || systemRead) {
      candidates.push({
        action: "execute",
        resourceType: "shell",
        effect: "external_side_effect",
        targets: commands.length ? commands : ["system:read-only"],
        bound: commands.length ? { commands } : undefined,
        confidence: commands.length ? 0.98 : 0.9,
      });
    }
  }

  if (explicitMemoryWrite(clause) && !negatedAction(clause, "persist") && !analysisOnly(clause) && !conditionalFileInstruction(clause)) {
    candidates.push({
      action: "persist",
      resourceType: "memory",
      effect: "persistent_change",
      targets: [`memory:${fingerprint(clause)}`],
      confidence: 0.94,
    });
  }

  if (explicitUnreadMailboxRead(clause) && !negatedAction(clause, "read") && !analysisOnly(clause)) {
    candidates.push({ action: "read", resourceType: "email", effect: "persistent_change", targets: ["mailbox:unread"], confidence: 0.97 });
  }
  return dedupeCandidates(candidates);
}

function explicitSend(text: string): boolean {
  const instruction = text.replace(/\b(?:e-?mail)\s+(?:address|addresses|account|accounts)\b/gi, "contact address");
  return /\b(?:please\s+)?(?:send|email|mail|forward)\b/i.test(instruction)
    || /(?:请|帮我|现在|直接)?(?:把|将).{0,80}(?:发送给|发送到|发送至|发给|邮件给)/i.test(text)
    || /(?:请|帮我)?给\s*[^，,。；;]{1,80}(?:发|发送).{0,30}(?:邮件|报告|文件|消息|摘要|通知|进展|结果)/i.test(text)
    || /^\s*(?:(?:请|帮我|现在|直接)\s*)?(?:发送|发邮件|外发).{0,80}(?:给|到)/i.test(text);
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
    || /(?:系统版本|目录大小|磁盘使用|内存信息|cpu信息|系统健康|健康检查|日常巡检|系统巡检|运行时间|主机标识)/i.test(text);
}

function explicitMemoryWrite(text: string): boolean {
  return /\b(?:please\s+)?(?:remember|persist|store in (?:long[- ]term )?memory)\b/i.test(text)
    || /(?:请|帮我)?(?:记住|写入(?:长期)?(?:记忆|经验库)|保存为长期偏好|(?:记录|保存)(?:到|进)(?:长期)?(?:记忆|经验库)|记录经验)/i.test(text);
}

function explicitUnreadMailboxRead(text: string): boolean {
  // Reading unread messages also marks them as read. Grant only this bounded
  // caller-mailbox operation, not delivery, deletion or another mailbox.
  return /^\s*(?:please\s+)?(?:show|list|read|get)(?:\s+me)?(?:\s+(?:all|my|the))*\s+unread\s+e-?mails?(?:\s+(?:in|from)\s+(?:my|the)\s+inbox)?[.!\s]*$/i.test(text)
    || /^\s*(?:(?:请|帮我)\s*)?(?:显示|列出|查看|读取)(?:我(?:的)?)?(?:所有|全部)?未读邮件(?:列表|内容)?\s*$/u.test(text);
}

export function analysisOnly(text: string): boolean {
  if (!/^\s*(?:(?:请|帮我|麻烦)\s*)?(?:仅|只)?(?:分析|解释|讨论|总结|翻译|引用|analy[sz]e|explain|discuss|summari[sz]e|translate|quote)/i.test(text)) return false;
  return !/(?:并|然后|接着|随后|and then|then).{0,80}(?:把|将|给|发送|发邮件|保存|写入|执行|运行|记住|send|email|write|save|execute|run|remember)/i.test(text);
}

export function negatedAction(text: string, action: CapabilityAction): boolean {
  const actionPatterns: Record<CapabilityAction, string> = {
    read: "读取|打开|查看|访问|检查|显示|列出|总结|read|open|visit|check|show|list|summari[sz]e",
    write: `${CHINESE_FILE_WRITE_VERBS}|write|save|edit|create|update|append|overwrite`,
    send: "发送|发邮件|发给|邮件|外发|send|email|mail|forward",
    execute: "执行|运行|命令|execute|run|command",
    request: "调用|请求|上报|上传|提交|call|request|post|upload|submit",
    persist: "记住|记忆|经验库|持久|remember|memory|persist",
  };
  const pattern = actionPatterns[action];
  return new RegExp(`(?:不要|别|不得|禁止|不能|无需|仅分析|只分析|只总结|仅总结).{0,40}(?:${pattern})`, "i").test(text)
    || new RegExp(`\\b(?:do not|don't|never|must not|without)\\b.{0,40}\\b(?:${pattern})\\b`, "i").test(text);
}

export function splitClauses(text: string): Clause[] {
  const ranges = nonAuthoritativeRanges(text);
  const urlRanges = [...text.matchAll(URL_TOKEN)].map((match) => [match.index, match.index + match[0].length]);
  const clauses: Clause[] = [];
  const separator = /[\n。！？!?；;]|(?:，|,)\s*(?:但|但是|不过|however\b|but\b)/gi;
  let start = 0;
  for (const match of text.matchAll(separator)) {
    const end = match.index ?? start;
    // A query separator belongs to its URL. Punctuation inside a quotation
    // belongs to the masked block, rather than starting an authoritative clause.
    if ([...ranges, ...urlRanges].some(([from, to]) => end >= from && end < to)) continue;
    const clauseText = maskOperandClause(text, start, end, ranges);
    clauses.push({ text: clauseText, start, end, dataOnly: !clauseText.trim() });
    start = end + match[0].length;
  }
  const clauseText = maskOperandClause(text, start, text.length, ranges);
  clauses.push({ text: clauseText, start, end: text.length, dataOnly: !clauseText.trim() });
  return clauses;
}

/**
 * (P0-2) Quotation ranges are computed with a pairing scanner instead of a
 * naive /"[^"\n]*"/ regex. With the regex, an odd number of quote characters
 * (e.g. injected content containing one stray quote) shifted every subsequent
 * mask, letting attacker text survive as "user" text. The scanner treats an
 * unterminated opening quote as extending to end-of-line, so misaligned
 * quotes can only mask *more* text, never less.
 */
const QUOTE_PAIRS: Array<[string, string]> = [
  ["```", "```"],
  ['"', '"'],
  ["“", "”"],
  ["‘", "’"],
  ["「", "」"],
  ["『", "』"],
];

function quotationRanges(text: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  for (const [open, close] of QUOTE_PAIRS) {
    let searchFrom = 0;
    while (searchFrom < text.length) {
      const start = text.indexOf(open, searchFrom);
      if (start < 0) break;
      const end = text.indexOf(close, start + open.length);
      if (end < 0) {
        // Unterminated quote: mask through end of line (fail closed).
        const lineEnd = text.indexOf("\n", start + open.length);
        ranges.push([start, lineEnd < 0 ? text.length : lineEnd]);
        searchFrom = text.length;
        break;
      }
      ranges.push([start, end + close.length]);
      searchFrom = end + close.length;
    }
  }
  return ranges;
}

/**
 * (P0-2) The data-frame marker ("总结以下内容：") previously masked everything
 * from the marker to the end of the whole message, which also erased the
 * user's real authorization when it appeared later. Now the marker only masks
 * the data block that follows it, bounded by a blank line or the next
 * imperative sentence, so authorization after the data block survives.
 */
const DATA_FRAME_BOUNDARY = /\n\s*\n|\n(?=\s*(?:请|帮我|麻烦|可以|务必|请勿|不要|please|kindly|could you|would you|i need|i want))/gi;

function dataFrameRanges(text: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  const dataFrame = /(?:summari[sz]e|analy[sz]e|translate|quote|总结|分析|翻译|引用)(?:\s+the)?(?:\s+following|以下|下面)(?:\s*(?:text|content|文字|内容))?\s*[:：]/gi;
  for (const match of text.matchAll(dataFrame)) {
    const start = (match.index ?? 0) + match[0].length;
    DATA_FRAME_BOUNDARY.lastIndex = 0;
    let end = text.length;
    for (const boundary of text.slice(start).matchAll(DATA_FRAME_BOUNDARY)) {
      end = start + (boundary.index ?? 0);
      break;
    }
    if (end > start) ranges.push([start, end]);
  }
  return ranges;
}

function nonAuthoritativeRanges(text: string): Array<[number, number]> {
  return mergeRanges([...quotationRanges(text), ...dataFrameRanges(text)]);
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

function maskOperandClause(text: string, start: number, end: number, ranges: Array<[number, number]>): string {
  const masked = maskRanges(text, start, end, ranges);
  if (analysisOnly(masked) || conditionalFileInstruction(masked)) return masked;
  const fileIntent = explicitFileWrite(masked) || explicitFileRead(masked);
  const emailIntent = explicitSend(masked) && !negatedAction(masked, "send");
  const networkIntent = explicitNetworkRead(masked) || explicitNetworkRequest(masked) || /(?:访问|打开|读取|查看|检查)/.test(masked);
  if (!fileIntent && !emailIntent && !networkIntent) return masked;
  const chars = masked.split("");
  for (const [rangeStart, rangeEnd] of ranges) {
    if (rangeStart < start || rangeEnd > end) continue;
    const literal = text.slice(rangeStart, rangeEnd);
    if (!QUOTE_PAIRS.some(([open, close]) => open !== "```" && literal.startsWith(open) && literal.endsWith(close))) continue;
    const operand = literal.slice(1, -1).trim();
    const paths = extractPaths(operand);
    const emails = extractEmails(operand);
    const urls = extractUrls(operand);
    // Restore a whole path/address/URL only when its instruction is outside
    // the quotation. Instructions inside quotations remain non-authoritative.
    const file = fileIntent && paths.length === 1 && paths[0] === operand;
    const email = emailIntent && emails.length === 1 && emails[0] === operand;
    const url = networkIntent && urls.length === 1 && urls[0] === operand;
    if (!file && !email && !url) continue;
    for (let index = rangeStart + 1; index < rangeEnd - 1; index += 1) chars[index - start] = text[index];
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

const URL_TOKEN = /\b(?:https?:\/\/|mock:\/\/)[^\s\uFF0C\u3001\u3002\uFF1B\uFF01\uFF1F;,)>\]}>"']+/gi;

function extractUrls(text: string): string[] {
  // (P0-2) Full-width U+FF0C (comma), U+3001 (enumeration comma), U+3002
  // (period), U+FF1B (semicolon), U+FF01 (exclamation) and U+FF1F (question)
  // terminate URLs in Chinese text. normalizeTaskText() applies NFKC first,
  // which folds most of them into their ASCII counterparts (",", ";"), so the
  // ASCII separators matter just as much. The class is written with \uXXXX
  // escapes so the source stays pure ASCII and immune to editor encoding
  // corruption; cleanTarget trims residual trailing punctuation.
  return unique([...text.matchAll(URL_TOKEN)].map((match) => cleanTarget(match[0])));
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

function extractLiteralReadCommands(text: string): string[] {
  // These commands take no operands and cannot mutate state. Bind the exact
  // command the user named, rather than granting the whole system-read group.
  const pattern = /(?:执行|运行|\b(?:run|execute)\s+(?:the\s+)?)(?:命令\s*|command\s+)?\s*(pwd|whoami|id|hostname|date|uptime)(?=\s|[。；;,.!?]|$)/gi;
  return unique([...text.matchAll(pattern)].map((match) => match[1].toLowerCase()));
}

function  mergeCapabilities(capabilities: TaskCapability[]): TaskCapability[] {
  const merged = new Map<string, TaskCapability>();
  for (const capability of capabilities) {
    // (P0-1) Identity = (action, resource, effect, bound parameter tuple).
    // Only structurally identical clauses collapse; targets are never unioned
    // across different bindings, which is what previously produced cartesian
    // product authorizations.
    const key = capabilityKey(capability);
    const current = merged.get(key);
    if (!current) {
      merged.set(key, structuredClone({ ...capability, capabilityId: key }));
      continue;
    }
    // Same identity: keep the tighter constraint intersection rather than a
    // union, so repeated grants can only reaffirm, never widen.
    current.targets = unique([...current.targets, ...capability.targets]);
    current.constraints.allowedMethods = intersectOptional(current.constraints.allowedMethods, capability.constraints.allowedMethods);
    current.constraints.allowedPaths = intersectOptional(current.constraints.allowedPaths, capability.constraints.allowedPaths);
    current.constraints.allowedHosts = intersectOptional(current.constraints.allowedHosts, capability.constraints.allowedHosts);
    current.constraints.allowedRecipients = intersectOptional(current.constraints.allowedRecipients, capability.constraints.allowedRecipients);
    current.evidence.confidence = Math.max(current.evidence.confidence, capability.evidence.confidence);
    current.evidence.explicitSpan = `${current.evidence.explicitSpan}; ${capability.evidence.explicitSpan}`.slice(0, 320);
  }
  return [...merged.values()];
}

/**
 * (P0-1) Build the capability identity from the clause-scoped binding.
 * Falls back to sorted targets when no explicit binding exists so that purely
 * target-based capabilities keep deterministic identities.
 */
function capabilityKey(capability: TaskCapability | Candidate, clause?: Clause): string {
  const base = `${capability.action}:${capability.resourceType}:${capability.effect}`;
  const bound = "bound" in capability && capability.bound
    ? boundTuple(capability.bound)
    : boundTuple((capability as Candidate).bound || {});
  const clauseScope = clause ? `@${clause.start}:${clause.end}` : "";
  return `${base}|${bound || `targets=${capability.targets.slice().sort().join(",")}`}${clauseScope}`;
}

function boundTuple(bound: NonNullable<TaskCapability["bound"]>): string {
  const parts: string[] = [];
  if (bound.recipients?.length) parts.push(`rcpt=${bound.recipients.slice().sort().join(",")}`);
  if (bound.paths?.length) parts.push(`path=${bound.paths.slice().sort().join(",")}`);
  if (bound.urls?.length) parts.push(`url=${bound.urls.slice().sort().join(",")}`);
  if (bound.commands?.length) parts.push(`cmd=${bound.commands.slice().sort().join(",")}`);
  return parts.join(";");
}

function normalizeBoundArgs(bound?: Candidate["bound"]): TaskCapability["bound"] {
  if (!bound) return undefined;
  const output: TaskCapability["bound"] = {};
  if (bound.recipients?.length) output.recipients = unique(bound.recipients.map((item) => item.toLowerCase()));
  if (bound.paths?.length) output.paths = unique(bound.paths);
  if (bound.urls?.length) output.urls = unique(bound.urls);
  if (bound.commands?.length) output.commands = unique(bound.commands);
  return Object.keys(output).length ? output : undefined;
}

/**
 * (P1) Clause-scoped denial collection. A denial only bans a tool when no
 * clause in the same message explicitly authorizes that tool with a concrete
 * target; otherwise the denial is recorded on the matching capability only.
 */
function collectDeniedTools(normalized: string, capabilities: TaskCapability[]): string[] {
  const denied: string[] = [];
  for (const [tool, pattern] of ACTION_DENIALS) {
    if (!testPattern(pattern, normalized)) continue;
    const authorizedTools = new Set(capabilities.flatMap(capabilityTools));
    if (!authorizedTools.has(tool)) denied.push(tool);
  }
  return denied;
}

function compactConstraints(candidate: Candidate): TaskCapability["constraints"] {
  const output: TaskCapability["constraints"] = {};
  if (candidate.allowedMethods?.length) output.allowedMethods = unique(candidate.allowedMethods.map((item) => item.toUpperCase()));
  if (candidate.allowedPaths?.length) output.allowedPaths = unique(candidate.allowedPaths);
  if (candidate.allowedHosts?.length) output.allowedHosts = unique(candidate.allowedHosts.map((item) => item.toLowerCase()));
  if (candidate.allowedRecipients?.length) output.allowedRecipients = unique(candidate.allowedRecipients.map((item) => item.toLowerCase()));
  // (P1) Attach usage guard rails so a leaked capability cannot loop writes
  // or exfiltrate unbounded payloads within a single grant.
  if (candidate.effect !== "read_only") {
    output.maxCalls = DEFAULT_MAX_CALLS;
    if (candidate.resourceType === "file" || candidate.resourceType === "remote_file") output.maxBytes = DEFAULT_MAX_BYTES;
    if (candidate.resourceType === "remote_file") output.maxCalls = 1;
  }
  return output;
}

function capabilityTools(capability: TaskCapability): string[] {
  if (capability.resourceType === "calendar" && capability.action === "write") return ["calendar_write"];
  if (capability.resourceType === "file" && capability.action === "read") return ["read_file"];
  if (capability.resourceType === "file" && capability.action === "write") return ["write_file"];
  if (capability.resourceType === "remote_file" && capability.action === "write") return ["remote_file_create"];
  if (capability.resourceType === "email" && capability.action === "send") return ["send_email"];
  if (capability.resourceType === "email" && capability.action === "read") return ["email_read"];
  if (capability.resourceType === "api" && capability.action === "read") return ["read_webpage", "call_api"];
  if (capability.resourceType === "api" && capability.action === "request") return ["call_api"];
  if (capability.resourceType === "shell" && capability.action === "execute") return ["shell_exec"];
  if (capability.resourceType === "memory" && capability.action === "persist") return ["memory_read", "memory_write"];
  if (capability.resourceType === "memory" && capability.action === "read") return ["memory_read"];
  return [];
}

/**
 * (P0-3) Keyword-inferred sensitive grants are proposals only.
 * Previously "授权状态" silently granted read on ~/.ssh/authorized_keys,
 * "主机标识" granted /etc/hostname + /etc/hosts, and "创建技能" granted a
 * wildcard write to skills/* (a persistent code-execution path). Those are
 * now pending capability requests the user must explicitly approve.
 */
function templateProposalsForClause(clause: string): Omit<PendingCapabilityRequest, "evidenceSpan">[] {
  const proposals: Omit<PendingCapabilityRequest, "evidenceSpan">[] = [];
  if (/(主机标识|hostname|\/etc\/hostname|\/etc\/hosts)/i.test(clause)) {
    proposals.push({
      action: "read",
      resourceType: "file",
      effect: "read_only",
      targets: ["/etc/hostname", "/etc/hosts"],
      reason: "keyword_inferred_system_identity_read",
      confidence: 0.9,
    });
  }
  if (/(authorized_keys|ssh授权|ssh 授权|ssh authorized|授权状态)/i.test(clause)) {
    proposals.push({
      action: "read",
      resourceType: "file",
      effect: "read_only",
      targets: ["~/.ssh/authorized_keys"],
      reason: "keyword_inferred_ssh_key_read",
      confidence: 0.82,
    });
  }
  if (/(创建|编写|新增|保存).{0,40}(skill|技能)/i.test(clause)) {
    proposals.push({
      action: "write",
      resourceType: "file",
      effect: "persistent_change",
      targets: ["skills/*", "~/.openclaw/skills/*"],
      reason: "keyword_inferred_skill_write",
      confidence: 0.86,
    });
  }
  return proposals;
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
  // (P0-2) Trailing full-width commas ("，") sit outside the URL character
  // class, so strip them first, then apply the ASCII terminator set. This
  // prevents "https://api.example.com/reports，并保存到" from binding a URL
  // that swallows the rest of the clause.
  return value.replace(/[，、]+$/g, "").replace(/[.,;:\])}>'"　。；：）】》”’]+$/g, "");
}

export function normalizeTaskText(text: string): string {
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

function classifyTaskFamily(capabilities: TaskCapability[]): TaskSpec["task_family"] {
  if (!capabilities.length) return "unknown";
  const kinds = new Set(capabilities.map((capability) => `${capability.resourceType}:${capability.action}:${capability.effect}`));
  const hasWriteLike = [...kinds].some((item) => /write|send|request|execute|persist/.test(item));
  const hasReadLike = [...kinds].some((item) => /read/.test(item));
  const hasMemory = [...kinds].some((item) => item.startsWith("memory:"));
  const hasShell = [...kinds].some((item) => item.startsWith("shell:"));
  const hasEmail = [...kinds].some((item) => item.startsWith("email:"));
  const hasApi = [...kinds].some((item) => item.startsWith("api:"));

  if (hasMemory && !hasWriteLike) return "memory";
  if (hasEmail && !hasShell && !hasMemory && !hasWriteLike && !hasApi) return "delivery";
  if (hasShell && !hasWriteLike && !hasEmail && !hasMemory) return "shell";
  if (hasWriteLike && !hasReadLike) return "write_task";
  if (hasReadLike && !hasWriteLike && !hasEmail && !hasShell && !hasMemory) return "read_only";
  if (hasReadLike && hasWriteLike) return "mixed";
  if (hasApi && !hasWriteLike) return "analysis";
  return "mixed";
}

function taskConfidenceScore(capabilities: TaskCapability[]): number {
  if (!capabilities.length) return 0;
  const values = capabilities.map((capability) => capability.evidence.confidence || 0);
  const average = values.reduce((total, value) => total + value, 0) / values.length;
  return Math.max(0, Math.min(1, Math.round(average * 100) / 100));
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}
