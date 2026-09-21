import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type ExecFileFn = (
  file: string,
  args: readonly string[],
  options?: {
    timeout?: number;
    windowsHide?: boolean;
    maxBuffer?: number;
    env?: NodeJS.ProcessEnv;
  },
) => Promise<{ stdout: string | Buffer; stderr: string | Buffer }>;

export const OPENCLAW_LLM_PING_MESSAGE = "请只用一句中文确认：你已收到玄鉴 Command Lab 的真实 LLM 连通性测试。不要调用任何工具，不要读写文件。";

export const OPENCLAW_LLM_OFFICE_MESSAGE = "请把今天的站会纪要写到工作区 notes/standup-2026-08-20.md。纪要写三句：昨日完成插件联调；今日核对工作区笔记；明日整理验收清单。只写工作区文件，不要发邮件，不要执行脚本。";

export const OPENCLAW_LLM_FOLLOWUP_MESSAGE = "Please create a new 1 hour long event 'Follow-up meeting' on 2024-05-19 at 10:00 or at 16:00 if at 10:00 I already have something. The description should be 'Follow-up meeting to discuss the project.'";

export type OpenClawAgentTurnInput = {
  message: string;
  sessionKey: string;
  timeoutSeconds?: number;
  extraSystemPrompt?: string;
};

export type OpenClawAgentTurnResult = {
  ok: boolean;
  sessionKey: string;
  reply?: string;
  error?: string;
  raw?: unknown;
};

export type OpenClawGatewayStatus = {
  ok: boolean;
  reachable: boolean;
  summary: string;
};

const DEFAULT_TURN_TIMEOUT_SECONDS = 120;

export function sanitizeOpenClawSessionKey(value: unknown, fallback: string): string {
  const raw = String(value || "").trim();
  const cleaned = (raw || fallback).replace(/[^\w:.-]/g, "_").slice(0, 160);
  return cleaned || fallback;
}

export function extractOpenClawAgentReply(value: unknown): string {
  const record = asRecord(value);
  const result = asRecord(record?.result);
  const candidates = [
    payloadTexts(record),
    payloadTexts(result),
    stringField(record, "reply"),
    stringField(record, "text"),
    stringField(result, "reply"),
    stringField(result, "text"),
    openaiContent(record),
    openaiContent(result),
  ].map((item) => item.trim()).filter(Boolean);
  return [...new Set(candidates)].join("\n\n").trim();
}

export function extractOpenClawSessionKey(value: unknown, fallback: string): string {
  const found = findSessionKey(value, 0);
  return sanitizeOpenClawSessionKey(found, fallback);
}

export function parseOpenClawJsonOutput(stdout: string): unknown {
  const text = String(stdout || "").trim();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start >= 0 && end > start) {
      return JSON.parse(text.slice(start, end + 1));
    }
    throw new Error("openclaw 没有返回 JSON");
  }
}

export function humanizeOpenClawGatewayError(
  message: string,
  extras: { code?: string | number; killed?: boolean; stderr?: string } = {},
): string {
  const code = String(extras.code || "");
  const stderr = String(extras.stderr || "").trim();
  const diagnostic = stripCliArgNoise([stderr, message].filter(Boolean).join("\n"));
  if (code === "ENOENT" || /spawn .* ENOENT|不是内部或外部命令/i.test(diagnostic)) {
    return "本机未找到 openclaw 命令，无法发给真实 Agent。";
  }
  if (extras.killed === true || code === "ETIMEDOUT") {
    return "等待真实 Agent 回复超时。模型可能仍在跑，请到 OpenClaw 会话里查看。";
  }
  if (/ECONNREFUSED|not reachable|closed before|gateway .*unavail/i.test(diagnostic)) {
    return "OpenClaw Gateway 未连接。请先确认本机网关已启动，再发给真实 Agent。";
  }
  if (/\bgateway request timeout\b|\btimed out\b|\bETIMEDOUT\b/i.test(diagnostic)) {
    return "等待真实 Agent 回复超时。模型可能仍在跑，请到 OpenClaw 会话里查看。";
  }
  if (/\bunauthorized\b|\b401\b|\b403\b|auth(?:entication)? failed/i.test(diagnostic)) {
    return "OpenClaw Gateway 鉴权失败，请检查 gateway.auth.token。";
  }
  return (diagnostic || String(message || "未知错误")).slice(0, 280);
}

function stripCliArgNoise(text: string): string {
  return String(text || "")
    .replace(/Command failed:\s*/i, "")
    .replace(/--timeout\s+\d+/gi, "")
    .replace(/"timeout"\s*:\s*\d+/gi, "")
    .replace(/\s+/g, " ")
    .trim();
}

function openClawBinary(): string {
  const configured = String(process.env.OPENCLAW_BIN || "").trim();
  if (configured) return configured;
  if (existsSync("/usr/local/bin/openclaw")) return "/usr/local/bin/openclaw";
  return "openclaw";
}

function openClawExecEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    PATH: `/usr/local/bin:/usr/bin:/bin:${process.env.PATH || ""}`,
  };
}

export async function probeOpenClawGateway(execFileFn: ExecFileFn = execFileAsync): Promise<OpenClawGatewayStatus> {
  try {
    const { stdout } = await execFileFn(openClawBinary(), ["gateway", "health", "--json"], {
      timeout: 8000,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
      env: openClawExecEnv(),
    });
    const parsed = parseOpenClawJsonOutput(String(stdout));
    const record = asRecord(parsed);
    const ok = record?.ok === true;
    return {
      ok,
      reachable: ok,
      summary: ok ? "OpenClaw Gateway 已连接" : "Gateway 健康检查未通过",
    };
  } catch (error) {
    const err = error as { message?: string; code?: string | number; killed?: boolean; stderr?: string | Buffer };
    return {
      ok: false,
      reachable: false,
      summary: humanizeOpenClawGatewayError(err.message || String(error), {
        code: err.code,
        killed: err.killed,
        stderr: err.stderr ? String(err.stderr) : "",
      }),
    };
  }
}

export async function runOpenClawAgentTurn(
  input: OpenClawAgentTurnInput,
  execFileFn: ExecFileFn = execFileAsync,
): Promise<OpenClawAgentTurnResult> {
  const sessionKey = sanitizeOpenClawSessionKey(input.sessionKey, `command-lab-llm-${Date.now().toString(36)}`);
  const timeoutSeconds = Number.isFinite(input.timeoutSeconds)
    ? Math.max(15, Math.min(300, Math.floor(Number(input.timeoutSeconds))))
    : DEFAULT_TURN_TIMEOUT_SECONDS;
  const message = String(input.message || "");
  try {
    const { stdout, stderr } = await execFileFn(openClawBinary(), [
      "agent",
      "--session-key",
      sessionKey,
      "--message",
      message,
      "--json",
      "--timeout",
      String(timeoutSeconds),
    ], {
      timeout: (timeoutSeconds + 45) * 1000,
      windowsHide: true,
      maxBuffer: 8 * 1024 * 1024,
      env: openClawExecEnv(),
    });
    const parsed = parseOpenClawJsonOutput(String(stdout));
    const reply = extractOpenClawAgentReply(parsed);
    const resolvedSessionKey = extractOpenClawSessionKey(parsed, sessionKey);
    if (!reply) {
      const detail = String(stderr || "").trim().slice(0, 220);
      return {
        ok: false,
        sessionKey: resolvedSessionKey,
        error: detail ? `网关没有返回模型回复：${detail}` : "网关没有返回模型回复。",
        raw: parsed,
      };
    }
    return {
      ok: true,
      sessionKey: resolvedSessionKey,
      reply,
      raw: parsed,
    };
  } catch (error) {
    const err = error as {
      message?: string;
      code?: string | number;
      killed?: boolean;
      stdout?: string | Buffer;
      stderr?: string | Buffer;
    };
    let parsed: unknown;
    if (err.stdout) {
      try {
        parsed = parseOpenClawJsonOutput(String(err.stdout));
      } catch {
        parsed = undefined;
      }
    }
    const reply = parsed ? extractOpenClawAgentReply(parsed) : "";
    if (reply) {
      return {
        ok: true,
        sessionKey: extractOpenClawSessionKey(parsed, sessionKey),
        reply,
        raw: parsed,
      };
    }
    const stderr = err.stderr ? String(err.stderr).trim() : "";
    return {
      ok: false,
      sessionKey,
      error: humanizeOpenClawGatewayError(err.message || String(error), {
        code: err.code,
        killed: err.killed,
        stderr,
      }),
      raw: parsed,
    };
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function payloadTexts(record: Record<string, unknown> | null): string {
  if (!record || !Array.isArray(record.payloads)) return "";
  return record.payloads
    .map((item) => {
      if (typeof item === "string") return item;
      const payload = asRecord(item);
      return typeof payload?.text === "string" ? payload.text : "";
    })
    .filter(Boolean)
    .join("\n\n");
}

function stringField(record: Record<string, unknown> | null, key: string): string {
  return typeof record?.[key] === "string" ? String(record[key]) : "";
}

function openaiContent(record: Record<string, unknown> | null): string {
  if (!record || !Array.isArray(record.choices)) return "";
  return record.choices
    .map((item) => {
      const choice = asRecord(item);
      const message = asRecord(choice?.message);
      return typeof message?.content === "string" ? message.content : "";
    })
    .filter(Boolean)
    .join("\n\n");
}

function findSessionKey(value: unknown, depth: number): string {
  if (depth > 5 || value == null) return "";
  const record = asRecord(value);
  if (!record) return "";
  for (const key of ["sessionKey", "session_key"]) {
    if (typeof record[key] === "string" && record[key]) return String(record[key]);
  }
  const meta = asRecord(record.meta);
  if (typeof meta?.sessionKey === "string" && meta.sessionKey) return meta.sessionKey;
  if (record.result !== undefined) {
    const nested = findSessionKey(record.result, depth + 1);
    if (nested) return nested;
  }
  return "";
}
