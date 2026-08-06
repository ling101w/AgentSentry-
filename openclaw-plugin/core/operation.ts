import { createHash } from "node:crypto";
import { clampText, safeStringify } from "./redact.ts";

export function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return String(value);
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(",")}]`;

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(",")}}`;
}

export const POLICY_CONTRACT_VERSION = "taskspec-v2.1";

export function computeOperationKey(toolName: string, params: Record<string, unknown>, policyContext: unknown = {}): string {
  const raw = `${POLICY_CONTRACT_VERSION}:${toolName}:${stableStringify(params)}:${stableStringify(policyContext)}`;
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

export function formatApprovalDescription(input: {
  toolName: string;
  toolCallId?: string;
  paramPreview: unknown;
  riskScore: number;
  reasons: string[];
  violations: string[];
  decision?: "allow" | "ask" | "deny" | string;
  findings?: Array<{
    layer?: unknown;
    finding_type?: unknown;
    verdict?: unknown;
    reason?: unknown;
    score?: unknown;
    evidence?: Record<string, unknown>;
  }>;
  includeJudgeAnalysis?: boolean;
  maxChars: number;
}): string {
  const params = typeof input.paramPreview === "string" ? input.paramPreview : safeStringify(input.paramPreview);
  const detail = uniqueStrings(input.violations.length ? input.violations : input.reasons).map(humanizeReason).slice(0, 4);
  const judgeFindings = (input.findings || []).filter((finding) =>
    finding.finding_type === "semantic"
    && typeof finding.evidence?.semanticRisk === "string"
  );
  const judgeAnalysis = input.includeJudgeAnalysis
    ? judgeFindings.map((finding) => {
      const risk = String(finding.evidence?.semanticRisk || "").toUpperCase();
      const reason = String(finding.evidence?.semanticReason || finding.reason || "").trim();
      return [risk ? `LLM-Judge ${risk}` : "LLM-Judge", humanizeReason(reason)].filter(Boolean).join("：");
    }).filter(Boolean)
    : [];

  if (judgeAnalysis.length) {
    return clampText(
      [
        "玄鉴需要人工审批此工具调用。",
        `工具：${input.toolName}`,
        input.toolCallId ? `调用 ID：${input.toolCallId}` : "",
        `风险分：${input.riskScore}${input.decision ? `；策略决策：${input.decision}` : ""}`,
        detail.length ? `规则命中：${detail.join("；")}` : "",
        `LLM-Judge 分析：${uniqueStrings(judgeAnalysis).slice(0, 3).join("；")}`,
        "建议：只有在本次任务明确授权该工具、目标路径、收件人或外部接口时才允许；不确定时拒绝。",
        params ? `参数摘要：${params}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
      input.maxChars,
    );
  }

  return clampText(
    [
      `工具：${input.toolName}`,
      input.toolCallId ? `调用 ID：${input.toolCallId}` : "",
      `风险分：${input.riskScore}`,
      detail.length ? `原因：${detail.join("；")}` : "",
      params ? `参数摘要：${params}` : "",
    ]
      .filter(Boolean)
      .join("\n"),
    input.maxChars,
  );
}

function uniqueStrings(values: string[]): string[] {
  const seen = new Set<string>();
  const output: string[] = [];
  for (const value of values) {
    const normalized = String(value || "").trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    output.push(normalized);
  }
  return output;
}

function humanizeReason(value: string): string {
  const text = String(value || "").trim();
  const rules: Array<[RegExp, string]> = [
    [/workspace provenance scan found blocking context risk/i, "工作区扫描发现风险样本；仅在本次工具直接使用相关文件时才应阻断"],
    [/tool call directly references risky workspace item/i, "本次工具调用直接引用了工作区中被标记为风险的文件"],
    [/tool shell_exec is outside TaskSpec/i, "当前任务未明确授权执行 shell 命令"],
    [/shell command requires explicit review/i, "shell 命令需要人工确认"],
    [/tool frequency is unusually high/i, "同类工具短时间调用次数偏多"],
    [/sink argument inherits malicious or secret taint/i, "工具参数继承了恶意或机密污点"],
    [/content contains prompt-injection or exfiltration indicators/i, "内容包含提示注入或外泄风险信号"],
    [/high-risk action deviates from task intent/i, "高风险动作偏离用户原始任务意图"],
    [/kernel eBPF observer attached for high-risk runtime surface/i, "eBPF 运行时观测已启用"],
    [/semantic action graph contains persistence or privileged side effects/i, "语义动作图显示可能涉及持久化或特权副作用"],
    [/read path references sensitive asset/i, "读取路径指向敏感资产"],
    [/write path targets memory, startup, or OpenClaw configuration/i, "写入目标涉及记忆、启动项或 OpenClaw 配置"],
  ];
  for (const [pattern, label] of rules) {
    if (pattern.test(text)) return label;
  }
  return text;
}
