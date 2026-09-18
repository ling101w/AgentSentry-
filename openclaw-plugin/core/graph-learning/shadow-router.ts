import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface, type Interface } from "node:readline";
import { performance } from "node:perf_hooks";
import type { PluginConfig } from "../../config.ts";
import type { ProductionGraphInput } from "./production-graph.ts";

export type GraphShadowRoute = "shadow_allow" | "shadow_review" | "judge_fallback" | "unavailable";

export type GraphShadowScore = {
  schema_version: "production-gat-online-score-v1";
  model_version: string;
  graph_probability: number;
  threshold: number;
  ood_score: number;
  ood_threshold: number;
  route: GraphShadowRoute;
  latency_ms: number;
  fallback_reason?: string;
};

export type GraphShadowStatus = {
  enabled: boolean;
  configured: boolean;
  state: "disabled" | "stopped" | "starting" | "ready" | "unavailable";
  requests: number;
  successes: number;
  fallbacks: number;
  last_error?: string;
};

type SidecarResponse = {
  id: string;
  ok: boolean;
  model_version?: string;
  graph_probability?: number;
  threshold?: number;
  ood_score?: number;
  ood_threshold?: number;
  route?: GraphShadowRoute;
  error?: string;
};

type PendingRequest = {
  resolve: (value: GraphShadowScore | null) => void;
  timer: ReturnType<typeof setTimeout>;
  startedAt: number;
};

const MAX_LINE_CHARS = 256 * 1024;
const SIDECAR_START_TIMEOUT_MS = 10_000;

export class GraphShadowRouter {
  private readonly config: PluginConfig["graphLearning"];
  private child: ChildProcessWithoutNullStreams | null = null;
  private output: Interface | null = null;
  private startPromise: Promise<boolean> | null = null;
  private pending = new Map<string, PendingRequest>();
  private sequence = 0;
  private state: GraphShadowStatus["state"];
  private requests = 0;
  private successes = 0;
  private fallbacks = 0;
  private lastError = "";

  constructor(config: PluginConfig) {
    this.config = config.graphLearning;
    this.state = this.config.enabled ? "stopped" : "disabled";
  }

  status(): GraphShadowStatus {
    return {
      enabled: this.config.enabled,
      configured: Boolean(this.config.pythonPath && this.config.scriptPath && this.config.checkpointPath),
      state: this.state,
      requests: this.requests,
      successes: this.successes,
      fallbacks: this.fallbacks,
      ...(this.lastError ? { last_error: this.lastError } : {}),
    };
  }

  enabled(): boolean {
    return this.config.enabled;
  }

  async score(input: ProductionGraphInput): Promise<GraphShadowScore | null> {
    this.requests += 1;
    if (!this.config.enabled) return null;
    if (!(await this.ensureStarted())) {
      this.fallbacks += 1;
      return unavailableScore(this.config, this.lastError || "sidecar unavailable");
    }
    const id = `shadow_${process.pid}_${++this.sequence}`;
    const startedAt = performance.now();
    return new Promise<GraphShadowScore | null>((resolve) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        this.fallbacks += 1;
        this.lastError = `sidecar timeout after ${this.config.timeoutMs}ms`;
        resolve(unavailableScore(this.config, this.lastError, performance.now() - startedAt));
      }, this.config.timeoutMs);
      this.pending.set(id, { resolve, timer: timeout, startedAt });
      try {
        this.child?.stdin.write(`${JSON.stringify({ id, input })}\n`);
      } catch {
        clearTimeout(timeout);
        this.pending.delete(id);
        this.fallbacks += 1;
        this.lastError = "sidecar stdin write failed";
        resolve(unavailableScore(this.config, this.lastError, performance.now() - startedAt));
      }
    });
  }

  async close(): Promise<void> {
    this.startPromise = null;
    this.output?.close();
    this.output = null;
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.resolve(unavailableScore(this.config, "sidecar closed", performance.now() - request.startedAt));
    }
    this.pending.clear();
    if (this.child) {
      this.child.kill();
      this.child = null;
    }
    this.state = this.config.enabled ? "stopped" : "disabled";
  }

  private ensureStarted(): Promise<boolean> {
    if (this.state === "ready" && this.child) return Promise.resolve(true);
    if (this.startPromise) return this.startPromise;
    if (!this.config.pythonPath || !this.config.scriptPath || !this.config.checkpointPath) {
      this.state = "unavailable";
      this.lastError = "pythonPath, scriptPath, or checkpointPath is not configured";
      return Promise.resolve(false);
    }
    this.state = "starting";
    this.startPromise = new Promise<boolean>((resolve) => {
      let settled = false;
      const finish = (ready: boolean): void => {
        if (settled) return;
        settled = true;
        if (!ready) {
          this.state = "unavailable";
          this.fallbacks += 1;
        }
        resolve(ready);
      };
      try {
        const args = [this.config.scriptPath, "--checkpoint", this.config.checkpointPath];
        if (this.config.projectRoot) args.push("--project-root", this.config.projectRoot);
        const child = spawn(this.config.pythonPath, args, {
          cwd: this.config.projectRoot || undefined,
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
        });
        this.child = child;
        this.output = createInterface({ input: child.stdout, crlfDelay: Infinity });
        this.output.on("line", (line) => this.handleLine(line, finish));
        child.stderr.on("data", (chunk) => {
          const text = String(chunk).trim();
          if (text) this.lastError = text.slice(0, 300);
        });
        child.once("error", (error) => {
          this.lastError = error.message.slice(0, 300);
          finish(false);
        });
        child.once("close", (code) => {
          if (this.child === child) this.child = null;
          if (this.state === "ready" || !settled) {
            this.state = "unavailable";
            this.lastError = this.lastError || `sidecar exited with code ${code ?? "unknown"}`;
            for (const request of this.pending.values()) {
              clearTimeout(request.timer);
              request.resolve(unavailableScore(this.config, this.lastError, performance.now() - request.startedAt));
            }
            this.pending.clear();
            finish(false);
          }
        });
        setTimeout(() => {
          this.lastError = this.lastError || `sidecar did not become ready within ${SIDECAR_START_TIMEOUT_MS}ms`;
          finish(false);
        }, SIDECAR_START_TIMEOUT_MS);
      } catch (error) {
        this.lastError = error instanceof Error ? error.message.slice(0, 300) : String(error).slice(0, 300);
        finish(false);
      }
    }).finally(() => {
      this.startPromise = null;
    });
    return this.startPromise;
  }

  private handleLine(line: string, finish: (ready: boolean) => void): void {
    if (line.length > MAX_LINE_CHARS) {
      this.lastError = "sidecar response line exceeded size limit";
      finish(false);
      return;
    }
    let parsed: SidecarResponse & { ready?: boolean; model_version?: string };
    try {
      parsed = JSON.parse(line) as SidecarResponse & { ready?: boolean };
    } catch {
      this.lastError = "sidecar returned invalid JSON";
      return;
    }
    if (parsed.ready === true) {
      this.state = "ready";
      this.lastError = "";
      finish(true);
      return;
    }
    const pending = this.pending.get(parsed.id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pending.delete(parsed.id);
    const latency = performance.now() - pending.startedAt;
    if (!parsed.ok || !Number.isFinite(parsed.graph_probability) || !Number.isFinite(parsed.ood_score)) {
      this.fallbacks += 1;
      pending.resolve(unavailableScore(this.config, parsed.error || "sidecar returned an invalid score", latency));
      return;
    }
    this.successes += 1;
    const graphProbability = Number(parsed.graph_probability);
    const oodScore = Number(parsed.ood_score);
    const threshold = finiteOr(parsed.threshold, this.config.threshold);
    pending.resolve({
      schema_version: "production-gat-online-score-v1",
      model_version: parsed.model_version || "unknown",
      graph_probability: clamp01(graphProbability),
      threshold,
      ood_score: Math.max(0, oodScore),
      ood_threshold: finiteOr(parsed.ood_threshold, this.config.oodThreshold),
      route: parsed.route === "judge_fallback" ? "judge_fallback" : graphProbability >= threshold ? "shadow_review" : "shadow_allow",
      latency_ms: Math.round(latency * 1000) / 1000,
    });
  }
}

function unavailableScore(config: PluginConfig["graphLearning"], reason: string, latency = 0): GraphShadowScore {
  return {
    schema_version: "production-gat-online-score-v1",
    model_version: "unavailable",
    graph_probability: 0,
    threshold: config.threshold,
    ood_score: Number.POSITIVE_INFINITY,
    ood_threshold: config.oodThreshold,
    route: "unavailable",
    latency_ms: Math.round(Math.max(0, latency) * 1000) / 1000,
    fallback_reason: reason,
  };
}

function finiteOr(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function clamp01(value: number): number {
  return Math.max(0, Math.min(1, value));
}
