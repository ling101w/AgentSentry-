import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

type StoryStep = {
  label: string;
  primary: string;
  detail: string;
};

const screenSource = readFileSync(new URL("../../public/security-screen.html", import.meta.url), "utf8");
const helperNames = [
  "actionClass",
  "causalRiskLabel",
  "causalNodeTitle",
  "causalCapabilityLabel",
  "compactCausalSequence",
  "causalAuthorizationActorLabel",
  "causalGraphStory",
];

function extractFunction(name: string): string {
  const marker = `    function ${name}(`;
  const start = screenSource.indexOf(marker);
  expect(start, `${name} should exist in security-screen.html`).toBeGreaterThanOrEqual(0);
  const next = screenSource.indexOf("\n    function ", start + marker.length);
  return screenSource.slice(start, next < 0 ? screenSource.length : next);
}

const storyHarness = helperNames.map(extractFunction).join("\n");

function causalStory(graph: Record<string, unknown>, alert: Record<string, unknown>): StoryStep[] {
  return runInNewContext(`${storyHarness}\ncausalGraphStory(graph, alert);`, { graph, alert }) as StoryStep[];
}

describe("security screen causal story", () => {
  it("binds authorization to the final sink action instead of an earlier authorized read", () => {
    const graph = {
      trace_kind: "attack",
      risk: "secret_to_external_sink",
      verdict: "review",
      path_node_ids: ["read", "data", "send", "sink"],
      nodes: [
        { id: "cap-read", kind: "capability", label: "read:file:read_only", source: "user", authorization_actor: "user", authorized: true, authorization_reason: "explicit_user_capability" },
        { id: "read", kind: "action", tool: "read_file", authorized: true },
        { id: "data", kind: "data", path: "$.token", confidentiality: "secret" },
        { id: "send", kind: "action", tool: "send_email", authorized: false },
        { id: "sink", kind: "sink", sink: "send_email", effect: "external" },
      ],
      edges: [
        { id: "authorize-read", from: "cap-read", to: "read", kind: "authorizes" },
        { id: "read-data", from: "read", to: "data", kind: "produces" },
        { id: "data-send", from: "data", to: "send", kind: "consumes" },
        { id: "send-sink", from: "send", to: "sink", kind: "targets" },
      ],
    };

    const story = causalStory(graph, { action: "BLOCK" });

    expect(story.map((step) => step.label)).toEqual(["授权主体", "授权结论", "数据字段", "经过工具", "最终去向", "最终裁决"]);
    expect(story[0]?.primary).toBe("未记录授权主体");
    expect(story[1]?.primary).toBe("当前任务未授权");
    expect(story[5]?.primary).toBe("BLOCK · 已阻断");
    expect(story[5]?.detail).toContain("图路径：人工复核");
  });

  it("shows an explicit user capability when it authorizes the final sink action", () => {
    const graph = {
      trace_kind: "authorized",
      risk: "authorized_tool_execution",
      verdict: "allow",
      path_node_ids: ["cap-send", "send", "sink"],
      nodes: [
        { id: "cap-send", kind: "capability", label: "send:email:external_side_effect", source: "user", authorization_actor: "user", authorized: true, authorization_reason: "explicit_user_capability" },
        { id: "send", kind: "action", tool: "send_email", authorized: true },
        { id: "sink", kind: "sink", sink: "send_email", effect: "external" },
      ],
      edges: [
        { id: "authorize-send", from: "cap-send", to: "send", kind: "authorizes" },
        { id: "send-sink", from: "send", to: "sink", kind: "targets" },
      ],
    };

    const story = causalStory(graph, { action: "ALLOW" });

    expect(story[0]?.primary).toBe("当前用户");
    expect(story[1]?.primary).toBe("TaskSpec 精确授权");
    expect(story[4]?.primary).toBe("send_email");
    expect(story[5]?.primary).toBe("ALLOW · 正常放行");
  });
});
