import { existsSync, mkdirSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { createHash } from "node:crypto";
import type { PluginConfig } from "../config.ts";
import type { AgentSentryAction } from "./policy.ts";
import { isOpenClawMemoryDocumentPath } from "./policy/action-assessment.ts";

export type RollbackSnapshot = {
  id: string;
  operation_key: string;
  tool: string;
  path: string;
  existed: boolean;
  content_base64: string | null;
  sha256: string | null;
  created_at: string;
  reason: string;
};

export type OperationCheckpoint = {
  id: string;
  operation_key: string;
  tool: string;
  workspace_dir: string;
  created_at: string;
  file_snapshots: RollbackSnapshot[];
  session_state: Record<string, unknown> | null;
  execution_history: Array<Record<string, unknown>>;
  boundary: {
    kind: "file-workspace-session";
    reversible: string[];
    irreversible: string[];
  };
};

export type RollbackRestoreResult = {
  restored: RollbackSnapshot[];
  errors: Array<{ id: string; path: string; error: string }>;
  checkpoint?: OperationCheckpoint | null;
};

const MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024;

export class RollbackManager {
  readonly path: string;
  readonly checkpointPath: string;
  private snapshots: RollbackSnapshot[] = [];
  private checkpoints: OperationCheckpoint[] = [];

  constructor(private readonly config: PluginConfig) {
    const stateDir = config.storage.stateDir || process.env.OPENCLAW_STATE_DIR?.trim() || join(homedir(), ".openclaw");
    this.path = join(stateDir, "agentsentry", "rollback-checkpoints.json");
    this.checkpointPath = join(stateDir, "agentsentry", "operation-checkpoints.json");
    this.load();
  }

  checkpoint(action: AgentSentryAction, workspaceDir: string, operationKey: string): RollbackSnapshot[] {
    if (!this.config.rollback.enabled) return [];
    const paths = targetPaths(action, workspaceDir);
    const created: RollbackSnapshot[] = [];
    for (const target of paths) {
      const reason = rollbackReason(action, target, this.config.rollback.protectedPaths);
      if (!reason) continue;
      try {
        const snapshot = snapshotPath(target, action.tool, operationKey, reason);
        this.snapshots.push(snapshot);
        created.push(snapshot);
      } catch {
        // Rollback is a safety net; policy decisions remain the authority.
      }
    }
    if (created.length) {
      this.snapshots = this.snapshots.slice(-this.config.rollback.maxSnapshots);
      this.save();
    }
    return created;
  }

  checkpointOperation(input: {
    action: AgentSentryAction;
    workspaceDir: string;
    operationKey: string;
    sessionState?: Record<string, unknown> | null;
  }): OperationCheckpoint | null {
    if (!this.config.rollback.enabled) return null;
    const fileSnapshots = this.checkpoint(input.action, input.workspaceDir, input.operationKey);
    const checkpoint: OperationCheckpoint = {
      id: snapshotId(`operation:${input.operationKey}`, input.operationKey),
      operation_key: input.operationKey,
      tool: input.action.tool,
      workspace_dir: input.workspaceDir,
      created_at: new Date().toISOString(),
      file_snapshots: fileSnapshots,
      session_state: sanitizeSessionState(input.sessionState || null),
      execution_history: Array.isArray(input.sessionState?.history)
        ? (input.sessionState!.history as Array<Record<string, unknown>>).slice(-20)
        : [],
      boundary: {
        kind: "file-workspace-session",
        reversible: [
          "workspace file writes captured by file checkpoints",
          "OpenClaw memory/config files captured by protected path checkpoints",
          "workspace-shadow shell writes before sandbox commit",
          "in-memory policy labels, TaskSpec and action graph while the plugin process is alive",
        ],
        irreversible: [
          "emails already delivered to a remote server",
          "external API side effects already accepted by a remote service",
          "network reads or writes performed outside workspace-shadow isolation",
          "process state outside the OpenClaw plugin process",
        ],
      },
    };
    this.checkpoints.push(checkpoint);
    this.checkpoints = this.checkpoints.slice(-this.config.rollback.maxSnapshots);
    this.save();
    return checkpoint;
  }

  restoreOperation(operationKey: string): RollbackRestoreResult {
    const candidates = this.snapshots.filter((snapshot) => snapshot.operation_key === operationKey);
    const checkpoint = [...this.checkpoints].reverse().find((item) => item.operation_key === operationKey) || null;
    const result: RollbackRestoreResult = { restored: [], errors: [], checkpoint };
    for (const snapshot of candidates.reverse()) {
      try {
        if (snapshot.existed) {
          mkdirSync(dirname(snapshot.path), { recursive: true });
          writeFileSync(snapshot.path, Buffer.from(snapshot.content_base64 || "", "base64"));
        } else if (existsSync(snapshot.path)) {
          unlinkSync(snapshot.path);
        }
        result.restored.push(snapshot);
      } catch (error) {
        result.errors.push({
          id: snapshot.id,
          path: snapshot.path,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return result;
  }

  reset(): void {
    this.snapshots = [];
    this.checkpoints = [];
    rmSync(this.path, { force: true });
    rmSync(this.checkpointPath, { force: true });
  }

  listCheckpoints(limit = 50): OperationCheckpoint[] {
    const safeLimit = Math.min(Math.max(Math.trunc(limit) || 50, 1), 1000);
    return structuredClone(this.checkpoints.slice(-safeLimit).reverse());
  }

  private load(): void {
    if (!existsSync(this.path)) return;
    try {
      const parsed = JSON.parse(readFileSync(this.path, "utf8")) as { snapshots?: unknown };
      if (!Array.isArray(parsed.snapshots)) return;
      this.snapshots = parsed.snapshots.map(normalizeSnapshot).filter((item): item is RollbackSnapshot => Boolean(item));
    } catch {
      this.snapshots = [];
    }
    if (!existsSync(this.checkpointPath)) return;
    try {
      const parsed = JSON.parse(readFileSync(this.checkpointPath, "utf8")) as { checkpoints?: unknown };
      if (!Array.isArray(parsed.checkpoints)) return;
      this.checkpoints = parsed.checkpoints.map(normalizeOperationCheckpoint).filter((item): item is OperationCheckpoint => Boolean(item));
    } catch {
      this.checkpoints = [];
    }
  }

  private save(): void {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify({ snapshots: this.snapshots }, null, 2) + "\n", "utf8");
    writeFileSync(this.checkpointPath, JSON.stringify({ checkpoints: this.checkpoints }, null, 2) + "\n", "utf8");
  }
}

function sanitizeSessionState(value: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!value) return null;
  return structuredClone({
    currentTask: value.currentTask || "",
    taskSpec: value.taskSpec || null,
    authorizationState: value.authorizationState || null,
    contaminated: Boolean(value.contaminated),
    provenanceBlocked: Boolean(value.provenanceBlocked),
    aggregateRisk: value.aggregateRisk || null,
    taintedSources: Array.isArray(value.taintedSources) ? value.taintedSources.slice(-40) : [],
    taintFlows: Array.isArray(value.taintFlows) ? value.taintFlows.slice(-40) : [],
    dataProvenance: Array.isArray(value.dataProvenance) ? value.dataProvenance.slice(-120) : [],
    ifcBranches: Array.isArray(value.ifcBranches) ? value.ifcBranches.slice(-80) : [],
    persistentMemoryLabels: Array.isArray(value.persistentMemoryLabels) ? value.persistentMemoryLabels.slice(-80) : [],
    semanticActionGraph: value.semanticActionGraph || null,
    dynamicSecurity: value.dynamicSecurity || null,
  });
}

function targetPaths(action: AgentSentryAction, workspaceDir: string): string[] {
  if (action.tool !== "write_file" && action.tool !== "memory_write") return [];
  const values = new Set<string>();
  for (const key of ["path", "file", "filename", "target"]) {
    const raw = action.args[key];
    if (typeof raw === "string" && raw.trim()) values.add(resolveTarget(raw.trim(), workspaceDir));
  }
  return [...values];
}

function resolveTarget(path: string, workspaceDir: string): string {
  if (isAbsolute(path)) return resolve(path);
  const base = workspaceDir && isAbsolute(workspaceDir) ? workspaceDir : process.cwd();
  return resolve(base, path);
}

function rollbackReason(action: AgentSentryAction, target: string, protectedPaths: string[]): string {
  const normalized = target.replace(/\\/g, "/");
  if (action.tool === "memory_write" || isOpenClawMemoryDocumentPath(normalized)) return "memory checkpoint before persistent write";
  const lower = normalized.toLowerCase();
  for (const protectedPath of protectedPaths) {
    const needle = protectedPath.replace(/\\/g, "/").toLowerCase();
    if (!needle) continue;
    if (lower.endsWith(`/${needle}`) || lower === needle || lower.includes(`/${needle}`)) return "protected configuration checkpoint";
  }
  return action.tool === "write_file" ? "file checkpoint before write" : "";
}

function snapshotPath(path: string, tool: string, operationKey: string, reason: string): RollbackSnapshot {
  const existed = existsSync(path);
  let content: Buffer | null = null;
  if (existed) {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > MAX_SNAPSHOT_BYTES) {
      return {
        id: snapshotId(path, operationKey),
        operation_key: operationKey,
        tool,
        path,
        existed,
        content_base64: null,
        sha256: null,
        created_at: new Date().toISOString(),
        reason: `${reason}; content not captured`,
      };
    }
    content = readFileSync(path);
  }
  return {
    id: snapshotId(path, operationKey),
    operation_key: operationKey,
    tool,
    path,
    existed,
    content_base64: content ? content.toString("base64") : null,
    sha256: content ? createHash("sha256").update(content).digest("hex") : null,
    created_at: new Date().toISOString(),
    reason,
  };
}

function snapshotId(path: string, operationKey: string): string {
  return createHash("sha256").update(`${operationKey}\n${path}\n${Date.now()}\n${Math.random()}`).digest("hex").slice(0, 24);
}

function normalizeSnapshot(value: unknown): RollbackSnapshot | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const obj = value as Record<string, unknown>;
  if (typeof obj.id !== "string" || typeof obj.operation_key !== "string" || typeof obj.path !== "string") return null;
  return {
    id: obj.id,
    operation_key: obj.operation_key,
    tool: typeof obj.tool === "string" ? obj.tool : "unknown_tool",
    path: obj.path,
    existed: typeof obj.existed === "boolean" ? obj.existed : false,
    content_base64: typeof obj.content_base64 === "string" ? obj.content_base64 : null,
    sha256: typeof obj.sha256 === "string" ? obj.sha256 : null,
    created_at: typeof obj.created_at === "string" ? obj.created_at : new Date().toISOString(),
    reason: typeof obj.reason === "string" ? obj.reason : "rollback checkpoint",
  };
}

function normalizeOperationCheckpoint(value: unknown): OperationCheckpoint | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const obj = value as Record<string, unknown>;
  if (typeof obj.id !== "string" || typeof obj.operation_key !== "string" || typeof obj.tool !== "string") return null;
  const fileSnapshots = Array.isArray(obj.file_snapshots)
    ? obj.file_snapshots.map(normalizeSnapshot).filter((item): item is RollbackSnapshot => Boolean(item))
    : [];
  return {
    id: obj.id,
    operation_key: obj.operation_key,
    tool: obj.tool,
    workspace_dir: typeof obj.workspace_dir === "string" ? obj.workspace_dir : "",
    created_at: typeof obj.created_at === "string" ? obj.created_at : new Date().toISOString(),
    file_snapshots: fileSnapshots,
    session_state: obj.session_state && typeof obj.session_state === "object" && !Array.isArray(obj.session_state)
      ? obj.session_state as Record<string, unknown>
      : null,
    execution_history: Array.isArray(obj.execution_history)
      ? obj.execution_history.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === "object" && !Array.isArray(item))).slice(-20)
      : [],
    boundary: {
      kind: "file-workspace-session",
      reversible: Array.isArray((obj.boundary as Record<string, unknown> | undefined)?.reversible)
        ? ((obj.boundary as Record<string, unknown>).reversible as unknown[]).map(String)
        : [],
      irreversible: Array.isArray((obj.boundary as Record<string, unknown> | undefined)?.irreversible)
        ? ((obj.boundary as Record<string, unknown>).irreversible as unknown[]).map(String)
        : [],
    },
  };
}
