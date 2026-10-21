import type { PluginConfig } from "../config.ts";
export type SemanticJudgeOverride = "default" | "on" | "off";
export function parseSemanticJudgeOverride(value: unknown): SemanticJudgeOverride {
  if (value === true) return "on";
  if (value === false) return "off";
  const normalized = String(value ?? "default").trim().toLowerCase();
  if (["on", "enable", "enabled", "true", "1", "judge"].includes(normalized)) return "on";
  if (["off", "disable", "disabled", "false", "0", "none"].includes(normalized)) return "off";
  return "default";
}

export function configWithSemanticOverride(config: PluginConfig, mode: SemanticJudgeOverride, timeoutMs?: number): PluginConfig {
  const next = structuredClone(config);
  if (mode === "on") {
    next.semantic.enabled = true;
    next.semantic.mode = "full";
  }
  if (mode === "off") {
    next.semantic.enabled = false;
    next.semantic.mode = "off";
  }
  if (timeoutMs !== undefined) next.semantic.timeoutMs = timeoutMs;
  return next;
}

export function semanticJudgeProfile(mode: SemanticJudgeOverride, config: PluginConfig): Record<string, unknown> {
  return {
    mode,
    enabled: config.semantic.enabled,
    scheduling: config.semantic.mode,
    tool_calls: config.semantic.judgeToolCalls,
    messages: config.semantic.judgeMessages,
    memory_writes: config.semantic.judgeMemoryWrites,
    provenance: config.semantic.judgeProvenance,
    model: config.semantic.model,
    timeout_ms: config.semantic.timeoutMs,
  };
}
