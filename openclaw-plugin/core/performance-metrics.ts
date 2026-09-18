export const TOOL_CALL_PERFORMANCE_SCHEMA_VERSION = "tool-call-performance-v1" as const;

export const TOOL_CALL_STAGE_NAMES = [
  "preprocessing",
  "preliminary_policy",
  "semantic_action_graph",
  "graph_training_projection",
  "semantic_tool_judge",
  "semantic_memory_judge",
  "semantic_ambiguous_judge",
  "final_policy",
  "decision_ready",
  "effects_and_checkpoint",
  "total_until_audit",
] as const;

export type ToolCallStageName = (typeof TOOL_CALL_STAGE_NAMES)[number];

export type ToolCallPerformanceSample = {
  schema_version: typeof TOOL_CALL_PERFORMANCE_SCHEMA_VERSION;
  recorded_at: string;
  stages_ms: Record<ToolCallStageName, number>;
  semantic_action_graph_evaluations: number;
  judge_routes: {
    tool: boolean;
    memory: boolean;
    ambiguous: boolean;
    total: number;
  };
  graph_projection: {
    nodes: number;
    edges: number;
    truncated: boolean;
  };
  decision: "allow" | "ask" | "deny";
  deterministic_disposition: "allow" | "deny" | "ambiguous";
};

export type StagePerformanceSummary = {
  count: number;
  avg_ms: number;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
  max_ms: number;
};

export type ToolCallPerformanceSnapshot = {
  ok: true;
  schema_version: "tool-call-performance-summary-v1";
  sample_count: number;
  window_limit: number;
  recorded_from: string | null;
  recorded_to: string | null;
  judge_routed_samples: number;
  judge_route_rate: number;
  judge_routes_total: number;
  semantic_action_graph_evaluations: number;
  decisions: Record<"allow" | "ask" | "deny", number>;
  stages: Record<ToolCallStageName, StagePerformanceSummary>;
};

export class ToolCallPerformanceTracker {
  private readonly maxSamples: number;
  private samples: ToolCallPerformanceSample[] = [];

  constructor(maxSamples = 2048) {
    this.maxSamples = boundedInteger(maxSamples, 1, 10_000, 2048);
  }

  record(sample: ToolCallPerformanceSample): void {
    this.samples.push(normalizeSample(sample));
    if (this.samples.length > this.maxSamples) this.samples = this.samples.slice(-this.maxSamples);
  }

  reset(): void {
    this.samples = [];
  }

  snapshot(): ToolCallPerformanceSnapshot {
    const decisions = { allow: 0, ask: 0, deny: 0 };
    let judgeRoutedSamples = 0;
    let judgeRoutesTotal = 0;
    let graphEvaluations = 0;
    for (const sample of this.samples) {
      decisions[sample.decision] += 1;
      judgeRoutesTotal += sample.judge_routes.total;
      graphEvaluations += sample.semantic_action_graph_evaluations;
      if (sample.judge_routes.total > 0) judgeRoutedSamples += 1;
    }

    const stages = Object.fromEntries(TOOL_CALL_STAGE_NAMES.map((stage) => [
      stage,
      summarize(this.samples.map((sample) => sample.stages_ms[stage])),
    ])) as Record<ToolCallStageName, StagePerformanceSummary>;

    return {
      ok: true,
      schema_version: "tool-call-performance-summary-v1",
      sample_count: this.samples.length,
      window_limit: this.maxSamples,
      recorded_from: this.samples[0]?.recorded_at || null,
      recorded_to: this.samples.at(-1)?.recorded_at || null,
      judge_routed_samples: judgeRoutedSamples,
      judge_route_rate: ratio(judgeRoutedSamples, this.samples.length),
      judge_routes_total: judgeRoutesTotal,
      semantic_action_graph_evaluations: graphEvaluations,
      decisions,
      stages,
    };
  }
}

export function emptyToolCallPerformanceSnapshot(): ToolCallPerformanceSnapshot {
  return new ToolCallPerformanceTracker(2048).snapshot();
}

export function roundDurationMs(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return Math.round(value * 1000) / 1000;
}

function normalizeSample(sample: ToolCallPerformanceSample): ToolCallPerformanceSample {
  const stages = Object.fromEntries(TOOL_CALL_STAGE_NAMES.map((stage) => [
    stage,
    roundDurationMs(sample.stages_ms[stage]),
  ])) as Record<ToolCallStageName, number>;
  const judgeRoutes = {
    tool: Boolean(sample.judge_routes.tool),
    memory: Boolean(sample.judge_routes.memory),
    ambiguous: Boolean(sample.judge_routes.ambiguous),
    total: 0,
  };
  judgeRoutes.total = Number(judgeRoutes.tool) + Number(judgeRoutes.memory) + Number(judgeRoutes.ambiguous);
  return {
    ...sample,
    recorded_at: validTimestamp(sample.recorded_at),
    stages_ms: stages,
    semantic_action_graph_evaluations: boundedInteger(sample.semantic_action_graph_evaluations, 0, 8, 0),
    judge_routes: judgeRoutes,
    graph_projection: {
      nodes: boundedInteger(sample.graph_projection.nodes, 0, 10_000, 0),
      edges: boundedInteger(sample.graph_projection.edges, 0, 20_000, 0),
      truncated: Boolean(sample.graph_projection.truncated),
    },
  };
}

function summarize(values: number[]): StagePerformanceSummary {
  const sorted = values.map(roundDurationMs).sort((left, right) => left - right);
  if (!sorted.length) return { count: 0, avg_ms: 0, p50_ms: 0, p95_ms: 0, p99_ms: 0, max_ms: 0 };
  return {
    count: sorted.length,
    avg_ms: roundDurationMs(sorted.reduce((total, value) => total + value, 0) / sorted.length),
    p50_ms: quantile(sorted, 0.5),
    p95_ms: quantile(sorted, 0.95),
    p99_ms: quantile(sorted, 0.99),
    max_ms: sorted.at(-1) || 0,
  };
}

function quantile(sorted: number[], quantileValue: number): number {
  const index = Math.max(0, Math.min(sorted.length - 1, Math.ceil(sorted.length * quantileValue) - 1));
  return sorted[index] || 0;
}

function ratio(numerator: number, denominator: number): number {
  return denominator > 0 ? Math.round((numerator / denominator) * 10_000) / 10_000 : 0;
}

function boundedInteger(value: number, minimum: number, maximum: number, fallback: number): number {
  return Number.isInteger(value) ? Math.max(minimum, Math.min(maximum, value)) : fallback;
}

function validTimestamp(value: string): string {
  return Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : new Date().toISOString();
}
