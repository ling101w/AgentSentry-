import { describe, expect, it } from "vitest";
import {
  extractOpenClawAgentReply,
  extractOpenClawSessionKey,
  humanizeOpenClawGatewayError,
  parseOpenClawJsonOutput,
  probeOpenClawGateway,
  runOpenClawAgentTurn,
  sanitizeOpenClawSessionKey,
} from "../../server/openclaw-agent.ts";

describe("openclaw agent lab helpers", () => {
  it("reads gateway payload text and session key", () => {
    const payload = {
      result: {
        payloads: [{ text: "已收到玄鉴连通性测试。" }],
        sessionKey: "agent:main:command-lab-llm-1",
      },
    };
    expect(extractOpenClawAgentReply(payload)).toBe("已收到玄鉴连通性测试。");
    expect(extractOpenClawSessionKey(payload, "fallback")).toBe("agent:main:command-lab-llm-1");
  });

  it("does not treat the user prompt as the model reply", () => {
    const payload = {
      message: "请只用一句中文确认",
      result: { payloads: [{ text: "收到。" }] },
    };
    expect(extractOpenClawAgentReply(payload)).toBe("收到。");
  });

  it("parses noisy CLI stdout and sanitizes session keys", () => {
    expect(parseOpenClawJsonOutput("debug\n{\"ok\":true}\n")).toEqual({ ok: true });
    expect(sanitizeOpenClawSessionKey("agent:main:ok", "x")).toBe("agent:main:ok");
    expect(sanitizeOpenClawSessionKey("bad key;rm -rf", "fallback")).toBe("bad_key_rm_-rf");
  });

  it("maps gateway failures into operator-facing Chinese errors", () => {
    expect(humanizeOpenClawGatewayError("connect ECONNREFUSED 127.0.0.1:18789")).toContain("未连接");
    expect(humanizeOpenClawGatewayError("spawn openclaw ENOENT", { code: "ENOENT" })).toContain("未找到 openclaw");
    expect(humanizeOpenClawGatewayError("gateway request timeout for agent")).toContain("超时");
    expect(humanizeOpenClawGatewayError(
      'Command failed: openclaw agent --timeout 165000 --params {"timeout":120}',
      { code: "ENOENT" },
    )).toContain("未找到 openclaw");
    expect(humanizeOpenClawGatewayError(
      'Command failed: openclaw agent --timeout 165000 --params {"timeout":120}',
    )).not.toContain("超时");
  });

  it("probes and sends through an injected CLI runner", async () => {
    const status = await probeOpenClawGateway(async () => ({ stdout: "{\"ok\":true}", stderr: "" }));
    expect(status).toMatchObject({ ok: true, reachable: true });

    const result = await runOpenClawAgentTurn(
      { message: "ping", sessionKey: "command-lab-llm-test", timeoutSeconds: 30, extraSystemPrompt: "不要出现在用户消息里" },
      async (file, args) => {
        expect(String(file).endsWith("openclaw")).toBe(true);
        expect(args).toContain("agent");
        expect(args).toContain("--message");
        expect(args).toContain("ping");
        expect(args).not.toContain("不要出现在用户消息里");
        expect(args).toContain("--session-key");
        expect(args).not.toContain("--expect-final");
        return {
          stdout: JSON.stringify({
            payloads: [{ text: "pong" }],
            sessionKey: "agent:main:command-lab-llm-test",
          }),
          stderr: "",
        };
      },
    );
    expect(result).toMatchObject({
      ok: true,
      reply: "pong",
      sessionKey: "agent:main:command-lab-llm-test",
    });
  });
});
