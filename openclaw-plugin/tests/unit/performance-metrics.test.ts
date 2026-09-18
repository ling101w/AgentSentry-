import { describe, expect, it } from "vitest";
import {
  TOOL_CALL_PERFORMANCE_SCHEMA_VERSION,
  TOOL_CALL_STAGE_NAMES,
  ToolCallPerformanceTracker,
  roundDurationMs,
  type ToolCallPerformanceSample,
} from "../../core/performance-metrics.ts";

function sample(totalMs: number, decision: ToolCallPerformanceSample["decision"], routes = 0): ToolCallPerformanceSample {
  const stages = Object.fromEntries(TOOL_CALL_STAGE_NAMES.map((stage) => [stage, totalMs])) as ToolCallPerformanceSample["stages_ms"];
  return {
    schema_version: TOOL_CALL_PERFORMANCE_SCHEMA_VERSION,
    recorded_at: "2026-09-15T00:00:00.000Z",
    stages_ms: stages,
    semantic_action_graph_evaluations: 2,
    judge_routes: {
      tool: routes >= 1,
      memory: routes >= 2,
      ambiguous: routes >= 3,
      total: 999,
    },
    graph_projection: { nodes: 12, edges: 18, truncated: false },
    decision,
    deterministic_disposition: decision === "deny" ? "deny" : "allow",
  };
}

describe("tool-call performance metrics", () => {
  it("keeps a bounded rolling window and reports stage percentiles", () => {
    const tracker = new ToolCallPerformanceTracker(2);
    tracker.record(sample(10, "allow", 0));
    tracker.record(sample(20, "ask", 1));
    tracker.record(sample(30, "deny", 3));

    const snapshot = tracker.snapshot();
    expect(snapshot).toMatchObject({
      ok: true,
      sample_count: 2,
      window_limit: 2,
      judge_routed_samples: 2,
      judge_route_rate: 1,
      judge_routes_total: 4,
      semantic_action_graph_evaluations: 4,
      decisions: { allow: 0, ask: 1, deny: 1 },
    });
    expect(snapshot.stages.total_until_audit).toEqual({
      count: 2,
      avg_ms: 25,
      p50_ms: 20,
      p95_ms: 30,
      p99_ms: 30,
      max_ms: 30,
    });
  });

  it("normalizes invalid values and resets to an empty snapshot", () => {
    const tracker = new ToolCallPerformanceTracker(1);
    const invalid = sample(Number.NaN, "allow", 1);
    invalid.recorded_at = "invalid";
    invalid.semantic_action_graph_evaluations = 99;
    invalid.graph_projection.nodes = -1;
    tracker.record(invalid);
    expect(tracker.snapshot()).toMatchObject({
      sample_count: 1,
      semantic_action_graph_evaluations: 8,
      judge_routes_total: 1,
      stages: { total_until_audit: { avg_ms: 0 } },
    });
    tracker.reset();
    expect(tracker.snapshot()).toMatchObject({ sample_count: 0, recorded_from: null, recorded_to: null });
    expect(roundDurationMs(-1)).toBe(0);
    expect(roundDurationMs(1.23456)).toBe(1.235);
  });
});
