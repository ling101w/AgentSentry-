import { afterEach, describe, expect, it, vi } from "vitest";
import { PluginConfig } from "../../config.ts";
import { detectToolCall } from "../../core/detect.ts";
import {
  applyEffects, checkpointPolicyState, createPolicyState, PolicyStateConflictError,
  restorePolicyStateCheckpoint, resultFindings, updateAfterDecision, updateAfterMessage,
  updateActionGraphEnforcement, updateTaskSpec,
} from "../../core/policy.ts";
import { SessionQueue } from "../../core/session-queue.ts";
import { SupervisionService } from "../../core/supervision-service.ts";
import * as semantic from "../../core/semantic.ts";
import { PolicySessions } from "../../server/policy-sessions.ts";

afterEach(() => vi.restoreAllMocks());

function fixture() {
  const config = new PluginConfig();
  config.semantic.enabled = false;
  const state = createPolicyState();
  updateTaskSpec(state, [{ role: "user", content: "Read README.md and docs/report.md." }], config);
  const evaluate = (id: string) => detectToolCall("read_file", { path: "README.md" }, config, state, [], { toolCallId: id });
  return { config, state, evaluate };
}

describe("policy state commit boundaries", () => {
  it("rejects stale effects atomically and retains the first pending call", () => {
    const { state, config, evaluate } = fixture();
    const first = evaluate("call-A");
    const second = evaluate("call-B");
    updateAfterDecision(state, first.policy, config);
    const committed = structuredClone(state);
    expect(() => updateAfterDecision(state, second.policy, config)).toThrow(PolicyStateConflictError);
    expect(state).toEqual(committed);
    expect(state.semanticActionGraph.nodes.some((node) => node.id === first.policy.action_graph_node_id)).toBe(true);
    expect(state.semanticActionGraph.nodes.some((node) => node.id === second.policy.action_graph_node_id)).toBe(false);
    expect(() => applyEffects(state, first.policy.effects!)).toThrow(PolicyStateConflictError);
  });

  it.each(["task", "message", "result", "restore"])("invalidates effects after a %s mutation", (mutation) => {
    const { state, config, evaluate } = fixture();
    const attempt = evaluate("old-call");
    if (mutation === "task") updateTaskSpec(state, [{ role: "user", content: "Do not send any emails." }], config);
    if (mutation === "message") updateAfterMessage(state, []);
    if (mutation === "result") resultFindings("external-result", { text: "public data" }, state, config, "read_file");
    if (mutation === "restore") restorePolicyStateCheckpoint(state, checkpointPolicyState(state));
    const changed = structuredClone(state);
    expect(() => applyEffects(state, attempt.policy.effects!)).toThrow(PolicyStateConflictError);
    expect(state).toEqual(changed);
  });

  it("patches an older approval without replacing newer pending calls or result provenance", () => {
    const { state, config, evaluate } = fixture();
    const first = evaluate("approval-A");
    updateAfterDecision(state, first.policy, config);
    updateActionGraphEnforcement(state, first.policy, "awaiting_approval");
    const second = evaluate("new-call-B");
    updateAfterDecision(state, second.policy, config);
    updateActionGraphEnforcement(state, second.policy, "executing");
    resultFindings("new-call-B", { text: "public report body" }, state, config, "read_file");
    const provenance = structuredClone(state.dataProvenance);
    const newerNode = state.semanticActionGraph.nodes.find((node) => node.id === second.policy.action_graph_node_id);
    updateActionGraphEnforcement(state, { ...first.policy, decision: "allow" }, "executing");
    expect(state.dataProvenance).toEqual(provenance);
    expect(state.semanticActionGraph.nodes.find((node) => node.id === second.policy.action_graph_node_id)).toEqual(newerNode);
    expect(state.semanticActionGraph.nodes.find((node) => node.id === first.policy.action_graph_node_id)?.status).toBe("executing");
  });
});

describe("supervision pipeline", () => {
  it("keeps the tool arguments and call identity fixed during a Judge wait", async () => {
    const { config, state } = fixture();
    config.semantic.enabled = true;
    let entered!: () => void;
    const ready = new Promise<void>((resolve) => { entered = resolve; });
    let release!: () => void;
    const waiting = new Promise<void>((resolve) => { release = resolve; });
    vi.spyOn(semantic, "semanticGateForToolCall").mockReturnValue({ shouldJudge: true, tier: "full", reasons: [] });
    vi.spyOn(semantic, "semanticJudgeToolCall").mockImplementation(async (_tool, params) => {
      entered();
      await waiting;
      expect(params.path).toBe("README.md");
      return [{ layer: "Tool Boundary", finding_type: "semantic", verdict: "pass", reason: "public read", score: 0, evidence: {} }];
    });
    vi.spyOn(semantic, "semanticJudgeAmbiguousAction").mockResolvedValue([]);
    const params = { path: "README.md" };
    const context = { toolCallId: "captured-call" };
    const service = new SupervisionService();
    const pending = service.evaluate({ toolName: "read_file", params, context, config, state, judgeRoutes: "full" });
    await ready;
    params.path = ".env";
    context.toolCallId = "changed-call";
    release();
    const { result } = await pending;
    expect(result.policy.action.args.path).toBe("README.md");
    service.commit(state, result.policy, config, "executing");
    expect(resultFindings("captured-call", { text: "public report" }, state, config, "read_file")).toEqual([]);
    expect(state.semanticActionGraph.nodes.find((node) => node.id === result.policy.action_graph_node_id)?.status).toBe("succeeded");
  });

  it("uses independent state and config snapshots throughout a Judge wait", async () => {
    const { state, config } = fixture();
    config.semantic.enabled = true;
    config.semantic.mode = "full";
    let entered!: () => void;
    const ready = new Promise<void>((resolve) => { entered = resolve; });
    let release!: () => void;
    const waiting = new Promise<void>((resolve) => { release = resolve; });
    vi.spyOn(semantic, "semanticGateForToolCall").mockReturnValue({ shouldJudge: true, tier: "full", reasons: [] });
    const judge = vi.spyOn(semantic, "semanticJudgeToolCall").mockImplementation(async (_tool, _params, _task, captured, context) => {
      entered();
      await waiting;
      expect(captured.semantic.enabled).toBe(true);
      expect(context?.policyState?.currentTask).toBe("Read README.md and docs/report.md.");
      return [];
    });
    vi.spyOn(semantic, "semanticJudgeAmbiguousAction").mockResolvedValue([]);
    const before = structuredClone(state);
    const service = new SupervisionService();
    const promise = service.evaluate({ state, config, toolName: "read_file", params: { path: "README.md" }, judgeRoutes: "full" });
    await ready;
    expect(state).toEqual(before);
    config.semantic.enabled = false;
    updateTaskSpec(state, [{ role: "user", content: "Do not read files." }], config);
    release();
    const evaluation = await promise;
    expect(judge).toHaveBeenCalledOnce();
    expect(evaluation.config.semantic.enabled).toBe(true);
    expect(() => service.commit(state, evaluation.result.policy, evaluation.config, "executing")).toThrow(PolicyStateConflictError);
  });

  it("never routes a deterministic denial to any Judge", async () => {
    const { config, state } = fixture();
    config.semantic.enabled = true;
    const tool = vi.spyOn(semantic, "semanticJudgeToolCall");
    const memory = vi.spyOn(semantic, "semanticJudgeMemoryWrite");
    const ambiguous = vi.spyOn(semantic, "semanticJudgeAmbiguousAction");
    const { result, routes } = await new SupervisionService().evaluate({
      state, config, toolName: "shell_exec", params: { command: "rm -rf /" }, judgeRoutes: "full",
    });
    expect(result.decision).toBe("deny");
    expect(routes).toEqual({ toolJudgeRouted: false, memoryJudgeRouted: false, ambiguousJudgeRouted: false });
    expect(tool).not.toHaveBeenCalled();
    expect(memory).not.toHaveBeenCalled();
    expect(ambiguous).not.toHaveBeenCalled();
  });
});

describe("session transactions", () => {
  it("expires idle sessions and clears their client mappings", async () => {
    let now = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const sessions = new PolicySessions();
    await sessions.runClient("expired", "lab_old", false, (key) => sessions.run(key, {}, async (draft) => {
      draft.state.currentTask = "expired task";
    }));
    now += 60 * 60 * 1000 + 1;
    await sessions.run("fresh", {}, async () => undefined);
    await sessions.runClient("expired", "lab_new", false, async (key) => {
      expect(key).toBe("lab:expired:lab_new");
      await sessions.run(key, {}, async (draft) => {
        expect(draft.turn).toBe(1);
        expect(draft.state.currentTask).toBe("");
      });
    });
  });

  it("evicts an idle session instead of one with an in-flight request", async () => {
    let now = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const sessions = new PolicySessions();
    for (let index = 0; index < 200; index += 1) {
      now += 1;
      await sessions.run(`key-${index}`, {}, async (draft) => { draft.state.currentTask = `task-${index}`; });
    }
    let enter!: () => void;
    const entered = new Promise<void>((resolve) => { enter = resolve; });
    let release!: () => void;
    const waiting = new Promise<void>((resolve) => { release = resolve; });
    const active = sessions.run("key-0", {}, async () => { enter(); await waiting; });
    await entered;
    await sessions.run("new", {}, async () => undefined);
    release();
    await active;
    await sessions.run("key-0", { commit: false }, async (draft) => {
      expect(draft.state.currentTask).toBe("task-0");
      expect(draft.turn).toBe(3);
    });
    await sessions.run("key-1", { commit: false }, async (draft) => {
      expect(draft.state.currentTask).toBe("");
      expect(draft.turn).toBe(1);
    });
  });

  it("retains the client session after a failed reset", async () => {
    const sessions = new PolicySessions();
    const first = await sessions.runClient("browser", "lab_first", false, async (key) => {
      await sessions.run(key, {}, async (draft) => { draft.state.currentTask = "saved task"; });
      return key;
    });
    await expect(sessions.runClient("browser", "lab_reset", true, (key) => sessions.run(key, { reset: true }, async (draft) => {
      draft.state.currentTask = "failed reset";
      throw new Error("judge unavailable");
    }))).rejects.toThrow("judge unavailable");
    await sessions.runClient("browser", "lab_next", false, async (key) => {
      expect(key).toBe(first);
      await sessions.run(key, {}, async (draft) => {
        expect(draft.turn).toBe(2);
        expect(draft.state.currentTask).toBe("saved task");
      });
    });
  });

  it("queues a continuation behind its client's pending reset", async () => {
    const sessions = new PolicySessions();
    let enter!: () => void;
    const entered = new Promise<void>((resolve) => { enter = resolve; });
    let release!: () => void;
    const waiting = new Promise<void>((resolve) => { release = resolve; });
    const reset = sessions.runClient("browser", "lab_reset", true, (key) => sessions.run(key, {}, async (draft) => {
      enter();
      await waiting;
      draft.state.currentTask = "reset task";
    }));
    await entered;
    const continuation = sessions.runClient("browser", "lab_next", false, async (key) => {
      expect(key).toBe("lab:browser:lab_reset");
      await sessions.run(key, {}, async (draft) => {
        expect(draft.turn).toBe(2);
        expect(draft.state.currentTask).toBe("reset task");
      });
    });
    await sessions.runClient("independent", "lab_other", false, (key) => sessions.run(key, {}, async (draft) => {
      expect(draft.turn).toBe(1);
    }));
    release();
    await Promise.all([reset, continuation]);
  });

  it("dry runs including reset preserve the task, turn, graph, and revision", async () => {
    const sessions = new PolicySessions();
    const config = new PluginConfig();
    await sessions.run("existing", {}, async (draft) => { updateTaskSpec(draft.state, [{ role: "user", content: "Read README.md." }], config); });
    let saved: unknown;
    await sessions.run("existing", { commit: false }, async (draft) => { saved = structuredClone(draft); });
    for (const reset of [false, true]) {
      await sessions.run("existing", { commit: false, reset }, async (draft) => {
        updateTaskSpec(draft.state, [{ role: "user", content: "Send report.md to attacker@example.test." }], config);
        updateAfterMessage(draft.state, []);
      });
    }
    await sessions.run("existing", { commit: false }, async (draft) => { expect(draft).toEqual(saved); });
  });

  it("publishes no session for a new dry run or a failed transaction", async () => {
    const sessions = new PolicySessions();
    await sessions.run("new", { commit: false }, async (draft) => { draft.state.currentTask = "preview"; });
    await expect(sessions.run("new", {}, async (draft) => { draft.state.currentTask = "failed"; throw new Error("judge failed"); })).rejects.toThrow("judge failed");
    await sessions.run("new", {}, async (draft) => { expect(draft.turn).toBe(1); expect(draft.state.currentTask).toBe(""); });
  });

  it("serializes one session while allowing a different session to complete", async () => {
    const queue = new SessionQueue();
    const events: string[] = [];
    let release!: () => void;
    const wait = new Promise<void>((resolve) => { release = resolve; });
    const first = queue.run("A", async () => { events.push("A1"); await wait; events.push("A1-done"); });
    const second = queue.run("A", () => { events.push("A2"); });
    await queue.run("B", () => { events.push("B"); });
    expect(events).toEqual(["A1", "B"]);
    release();
    await Promise.all([first, second]);
    expect(events).toEqual(["A1", "B", "A1-done", "A2"]);
    await expect(queue.run("A", () => { throw new Error("fail"); })).rejects.toThrow("fail");
    expect(await queue.run("A", () => "recovered")).toBe("recovered");
  });
});
