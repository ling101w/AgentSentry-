import { flattenText } from "../adapters/openclaw-tools.ts";
import { extractUrlTargets } from "../security/url.ts";
import { toolsForCapabilities } from "./capability.ts";
import { buildAuthorizationGraph } from "./graph.ts";
import type { Capability, TaskSpec } from "../policy/types.ts";

const EXPLICIT_NO_EMAIL = ["do not email", "don't email", "no email", "不要发", "别发", "不要发送", "不要给任何人发"];
const ALL_GUARDED_TOOLS = ["read_file", "write_file", "read_webpage", "call_api", "web_search", "send_email", "memory_read", "memory_write", "shell_exec"];

export function deriveTaskSpec(task: string, sensitiveAssets: string[]): TaskSpec {
  const lowered = task.toLowerCase();
  const capabilities: Capability[] = [];
  const explicitUrls = extractUrlTargets(task);
  const pathScopes = extractPathScopes(task);
  const recipients = extractRecipients(task);
  const explicitNoEmail = containsAny(lowered, EXPLICIT_NO_EMAIL);

  if (explicitUrls.length) capabilities.push({ kind: "network.fetch", origins: explicitUrls });
  else if (containsAny(lowered, ["webpage", "website", "browser", "search", "github", "url", "网页", "网站", "搜索", "检索", "查找", "客户邮件", "read email", "pdf", "图片", "图像", "页面"])) {
    capabilities.push({ kind: "network.fetch", origins: ["*"] });
  }
  if (containsAny(lowered, ["read file", "open file", "读取文件", "打开文件", "查看", "阅读", "file", "文件"])) {
    capabilities.push({ kind: "fs.read", roots: pathScopes.length ? pathScopes : ["."] });
  }
  if (containsAny(lowered, ["write", "save", "edit", "create", "report", "install", "保存", "写入", "生成报告", "修改文件", "创建文件", "编辑", "安装"])) {
    capabilities.push({ kind: "fs.write", roots: pathScopes.length ? pathScopes : ["."] });
  }
  const emailSendIntent = containsAny(lowered, ["send to", "send email", "email to", "mail to", "发邮件", "发送给", "发给", "发送邮件"])
    || (recipients.length > 0 && /\b(?:email|mail)\b|邮件|邮箱|\b发\b|发一封/i.test(task));
  if (!explicitNoEmail && emailSendIntent) {
    capabilities.push({ kind: "email.send", ...(recipients.length ? { recipients } : {}) });
  }
  if (containsAny(lowered, ["memory", "remember", "preference", "experience", "knowledge base", "记住", "记忆", "身份", "叫我", "我的名字", "长期经验", "长期偏好", "记录经验"])) {
    capabilities.push({ kind: "memory.read", namespace: "*" }, { kind: "memory.write", namespace: "*" });
  }
  if (containsAny(lowered, ["shell", "command", "terminal", "powershell", "运行命令", "执行命令", "系统版本", "目录大小", "磁盘", "cpu", "uname", "du ", "df ", "os-release"])) {
    capabilities.push({ kind: "execution.shell" });
  }

  const merged = mergeCapabilities(capabilities);
  const allowedTools = toolsForCapabilities(merged);
  return {
    task,
    capabilities: merged,
    authorization_graph: buildAuthorizationGraph(task, merged),
    allowed_tools: allowedTools,
    forbidden_tools: ALL_GUARDED_TOOLS.filter((tool) => !allowedTools.includes(tool)),
    allowed_targets: unique(merged.flatMap((item) => item.kind === "network.fetch" ? item.origins : [])),
    sensitive_assets: sensitiveAssets,
    output_policy: merged.some((item) => item.kind === "email.send")
      ? "Email only approved recipients when explicitly requested."
      : "Only answer the user; do not exfiltrate data.",
  };
}

export function extractLatestUserText(messages: unknown): string {
  if (!Array.isArray(messages)) return "";
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index] as Record<string, unknown>;
    if (message?.role === "user") return flattenText(message.content).trim();
  }
  return "";
}

function extractRecipients(task: string): string[] {
  return unique((task.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || []).map((item) => item.toLowerCase()));
}

function extractPathScopes(task: string): string[] {
  const withoutUrls = task.replace(/\b(?:https?|mock):\/\/\S+/gi, " ");
  const matches = withoutUrls.match(/(?:[A-Za-z]:[\\/][^\s,，。;；]+|\\\\[^\s,，。;；]+|\.{0,2}[\\/]?[A-Za-z0-9_.-]+(?:[\\/][A-Za-z0-9_.-]+)+|[A-Za-z0-9_-]+\.(?:md|txt|json|ya?ml|toml|ini|cfg|env|ts|js|mjs|cjs|py|sh|ps1|html?))/gi) || [];
  return unique(matches.map((item) => item.replace(/[.,;:，。；：）)】\]]+$/g, "")));
}

function mergeCapabilities(capabilities: Capability[]): Capability[] {
  const output: Capability[] = [];
  for (const capability of capabilities) {
    const existing = output.find((item) => item.kind === capability.kind);
    if (!existing) {
      output.push(capability);
      continue;
    }
    if (existing.kind === "fs.read" && capability.kind === "fs.read") existing.roots = unique([...existing.roots, ...capability.roots]);
    if (existing.kind === "fs.write" && capability.kind === "fs.write") existing.roots = unique([...existing.roots, ...capability.roots]);
    if (existing.kind === "network.fetch" && capability.kind === "network.fetch") existing.origins = unique([...existing.origins, ...capability.origins]);
    if (existing.kind === "email.send" && capability.kind === "email.send") {
      if (!existing.recipients || !capability.recipients) delete existing.recipients;
      else existing.recipients = unique([...existing.recipients, ...capability.recipients]);
    }
  }
  return output;
}

function containsAny(value: string, markers: string[]): boolean {
  return markers.some((marker) => value.includes(marker.toLowerCase()));
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}
