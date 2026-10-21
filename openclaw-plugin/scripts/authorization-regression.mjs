import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { PluginConfig } from "../dist/config.js";
import { detectToolCall } from "../dist/core/detect.js";
import { createPolicyState, updateTaskSpec } from "../dist/core/policy.js";

// Development regressions only: no tool execution, model calls, or task-utility estimate.
const workspaceDir = fileURLToPath(new URL("../../", import.meta.url));
const datasets = [
  new URL("../../evaluation/benign/realistic_benign_tasks.jsonl", import.meta.url),
  new URL("../../evaluation/regression/authorization_write_cases.jsonl", import.meta.url),
  new URL("../../evaluation/regression/authorization_quoted_targets.jsonl", import.meta.url),
].map((url) => ({ url, source: readFileSync(url, "utf8") }));
const cases = datasets.flatMap(({ source }) => source.trim().split(/\r?\n/).map((line) => JSON.parse(line)));
const aggregates = [];
for (const profile of ["balanced", "competition"]) {
  const decisions = cases.map(({ case_id, input, label }) => {
    const config = PluginConfig.fromPluginConfig({ profile, semantic: { enabled: false } });
    const state = createPolicyState();
    updateTaskSpec(state, [{ role: "user", content: input.user_message }], config);
    const result = detectToolCall(input.tool_name, input.tool_args, config, state, [], { workspaceDir });
    return {
      case_id, expected: label.expected, is_boundary: label.is_attack,
      decision: result.decision,
      reasons: result.findings.filter((finding) => finding.verdict !== "pass").map((finding) => finding.reason),
    };
  });
  const benign = decisions.filter((item) => !item.is_boundary);
  const boundaries = decisions.filter((item) => item.is_boundary);
  const counts = { allow: 0, ask: 0, deny: 0 };
  for (const item of benign) counts[item.decision] += 1;
  const mismatches = decisions.filter((item) => item.decision !== item.expected);
  aggregates.push({
    profile, intervention_mode: "risk-based", semantic_judge: false,
    benign_cases: benign.length, benign_decisions: counts,
    benign_deny_rate: counts.deny / benign.length,
    benign_intervention_rate: (counts.ask + counts.deny) / benign.length,
    boundary_cases: boundaries.length,
    boundary_allows: boundaries.filter((item) => item.decision === "allow").length,
    mismatches,
  });
}
const report = {
  evidence_level: "development_regression",
  evaluated_at: new Date().toISOString(),
  commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: workspaceDir, encoding: "utf8" }).trim(),
  working_tree_dirty: Boolean(execFileSync("git", ["status", "--porcelain"], { cwd: workspaceDir, encoding: "utf8" }).trim()),
  cases_sha256: createHash("sha256").update(datasets.map(({ source }) => source).join("\n")).digest("hex"),
  limitations: "Curated, known development fixtures with Judge disabled. Decisions only; no tools execute and no production FPR, task Utility or attack-success rate is estimated.",
  results: aggregates,
};
const outputIndex = process.argv.indexOf("--output");
if (outputIndex !== -1) {
  const output = process.argv[outputIndex + 1];
  if (!output || output.startsWith("--")) throw new Error("--output requires a JSON file path");
  writeFileSync(resolve(output), JSON.stringify(report, null, 2) + "\n");
}
for (const row of aggregates) {
  console.log(`${row.profile}: benign=${row.benign_cases} allow=${row.benign_decisions.allow} ask=${row.benign_decisions.ask} deny=${row.benign_decisions.deny}; boundary allows=${row.boundary_allows}/${row.boundary_cases}; mismatches=${row.mismatches.length}`);
  if (row.mismatches.length) console.log(row.mismatches.map((item) => `  ${item.case_id}: expected ${item.expected}, received ${item.decision}`).join("\n"));
}
process.exitCode = aggregates.some((row) => row.mismatches.length) ? 1 : 0;
