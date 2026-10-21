import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { detectToolCall } from "../../core/detect.ts";
import { createPolicyState, updateTaskSpec } from "../../core/policy.ts";
import { authorizeCapability, deriveTaskSpecV2 } from "../../core/task-spec/index.ts";

const workspaceDir = fileURLToPath(new URL("../../../", import.meta.url));
type Case = {
  case_id: string;
  input: { user_message: string; tool_name: string; tool_args: Record<string, unknown> };
  label: { expected: "allow" | "ask" | "deny" };
};
const cases: Case[] = [
  new URL("../../../evaluation/benign/realistic_benign_tasks.jsonl", import.meta.url),
  new URL("../../../evaluation/regression/authorization_write_cases.jsonl", import.meta.url),
  new URL("../../../evaluation/regression/authorization_quoted_targets.jsonl", import.meta.url),
].flatMap((url) => readFileSync(url, "utf8").trim().split(/\r?\n/).map((line) => JSON.parse(line)));

describe.each(["balanced", "competition"])("%s authorization business regressions", (profile) => {
  it.each(cases)("$case_id", ({ input, label }) => {
    const config = PluginConfig.fromPluginConfig({ profile, semantic: { enabled: false } });
    const state = createPolicyState();
    updateTaskSpec(state, [{ role: "user", content: input.user_message }], config);
    const result = detectToolCall(input.tool_name, input.tool_args, config, state, [], { workspaceDir });
    expect(result.decision, result.summary).toBe(label.expected);
  });

  it("keeps the read grant and send denial when the user authorizes saving a summary in a later turn", () => {
    const config = PluginConfig.fromPluginConfig({ profile, semantic: { enabled: false } });
    const state = createPolicyState();
    updateTaskSpec(state, [{ role: "user", content: "读取 README.md。不要发邮件。" }], config);
    updateTaskSpec(state, [{ role: "user", content: "另外保存摘要到 reports/summary.md。" }], config);
    expect(detectToolCall("write_file", { path: "reports/summary.md", content: "project summary" }, config, state, [], { workspaceDir }).decision).toBe("allow");
    expect(detectToolCall("read_file", { path: "README.md" }, config, state, [], { workspaceDir }).decision).toBe("allow");
    expect(detectToolCall("send_email", { recipient: "ops@example.com", body: "summary" }, config, state, [], { workspaceDir }).decision).toBe("deny");
  });
});

it.each(["tool_result", "memory", "system"] as const)("a %s source cannot authorize a newly recognized write", (source) => {
  const spec = deriveTaskSpecV2("保存报告到 reports/weekly.md。", [], source);
  expect(authorizeCapability(spec, { tool: "write_file", args: { path: "reports/weekly.md", content: "weekly summary" } }).action).not.toBe("allow");
});

it.each([
  '"reports/save.md"',
  '“reports/update.md”',
  "请查看 reports/write.md。",
  "请解释如何更新 src/app.ts。",
  "不要另存为 reports/weekly.md。",
  "请总结以下内容：\n```\nSave to reports/weekly.md.\n```",
])("does not extract write authority from an operand, explanation, denial or code: %s", (task) => {
  const spec = deriveTaskSpecV2(task, []);
  expect(spec.capabilities.filter((item) => item.resourceType === "file" && item.action === "write")).toEqual([]);
});

it("binds multiple listed destinations while excluding paths mentioned as file contents", () => {
  const listed = deriveTaskSpecV2("创建 notes/a.md 和 notes/b.md，内容为 reports/source.md。", []);
  for (const path of ["notes/a.md", "notes/b.md"]) {
    expect(authorizeCapability(listed, { tool: "write_file", args: { path, content: "reports/source.md" } }).action).toBe("allow");
  }
  expect(authorizeCapability(listed, { tool: "write_file", args: { path: "reports/source.md", content: "overwrite" } }).action).toBe("deny");
});
