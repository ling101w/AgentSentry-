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

export function computeOperationKey(toolName: string, params: Record<string, unknown>): string {
  const raw = `${toolName}:${stableStringify(params)}`;
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

export function formatApprovalDescription(input: {
  toolName: string;
  toolCallId?: string;
  paramPreview: unknown;
  riskScore: number;
  reasons: string[];
  violations: string[];
  maxChars: number;
}): string {
  const params = typeof input.paramPreview === "string" ? input.paramPreview : safeStringify(input.paramPreview);
  const detail = input.violations.length ? input.violations.join("; ") : input.reasons.join("; ");
  return clampText(
    [
      `Tool: ${input.toolName}`,
      input.toolCallId ? `ToolCallId: ${input.toolCallId}` : "",
      `Risk: ${input.riskScore}`,
      params ? `Params: ${params}` : "",
      detail ? `Reason: ${detail}` : "",
    ]
      .filter(Boolean)
      .join("\n"),
    input.maxChars,
  );
}
