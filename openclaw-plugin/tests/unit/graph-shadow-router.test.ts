import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { GraphShadowRouter } from "../../core/graph-learning/shadow-router.ts";
import { buildProductionGraphInput } from "../../core/graph-learning/production-graph.ts";
import { createSemanticActionGraph } from "../../core/semantic-action-graph.ts";

function graphInput() {
  const graph = createSemanticActionGraph();
  graph.nodes.push({ id: "action-1", kind: "action", sequence: 1, label: "read_file", tool: "read_file", status: "proposed" });
  return buildProductionGraphInput({ graph, currentActionNodeId: "action-1" });
}

describe("online graph shadow router", () => {
  it("is a no-op when disabled", async () => {
    const config = new PluginConfig();
    const router = new GraphShadowRouter(config);
    expect(await router.score(graphInput())).toBeNull();
    expect(router.status()).toMatchObject({ enabled: false, configured: false, state: "disabled", requests: 1 });
    await router.close();
  });

  it("scores through the JSONL sidecar without exposing a decision override", async () => {
    const config = new PluginConfig();
    config.graphLearning.enabled = true;
    config.graphLearning.pythonPath = process.execPath;
    config.graphLearning.scriptPath = join(process.cwd(), "tests", "fixtures", "graph-shadow-sidecar-fixture.mjs");
    config.graphLearning.checkpointPath = "fixture.pth";
    config.graphLearning.timeoutMs = 500;
    const router = new GraphShadowRouter(config);
    const result = await router.score(graphInput());
    expect(result).toMatchObject({
      schema_version: "production-gat-online-score-v1",
      model_version: "fixture-v1",
      graph_probability: 0.82,
      route: "shadow_review",
    });
    expect(router.status()).toMatchObject({ state: "ready", requests: 1, successes: 1, fallbacks: 0 });
    await router.close();
  });

  it("returns an explicit unavailable route when configuration is incomplete", async () => {
    const config = new PluginConfig();
    config.graphLearning.enabled = true;
    const router = new GraphShadowRouter(config);
    expect(await router.score(graphInput())).toMatchObject({ route: "unavailable", model_version: "unavailable" });
    expect(router.status()).toMatchObject({ state: "unavailable", fallbacks: 1 });
    await router.close();
  });
});
