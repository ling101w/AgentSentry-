import type { EbpfRuntimeAudit } from "../../core/system-monitor.ts";
export type LabAction = {
  toolName: string;
  params: Record<string, unknown>;
};

export type LabContent = {
  contentType: string;
  body: string | Buffer;
};

export type ExecutionStatus = "executed" | "blocked" | "skipped" | "failed";

export type BusinessExecution = {
  ok: boolean;
  output?: unknown;
  error?: string;
  reason?: string;
  artifact?: string;
  status?: number;
  findings?: unknown[];
  memory_guard?: Record<string, unknown>;
  runtime_audit?: EbpfRuntimeAudit | null;
};
