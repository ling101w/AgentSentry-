import { readFileSync, writeFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { PluginConfig } from "../dist/config.js";
import { supervisionService } from "../dist/core/supervision-service.js";
import { createPolicyState, updateTaskSpec, updateAfterMessage, resultFindings } from "../dist/core/policy.js";
import { detectMessageContent } from "../dist/core/detect.js";
import { labActionsFromCommand } from "../dist/server/lab/scenarios.js";
import { clearCustomToolManifests, registerToolManifest } from "../dist/core/tool-manifest.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const fields = ["session_history", "tool_args", "tool_name", "tool_result", "user_message"];
const option = (name) => { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; };

if (process.argv.includes("--materialize")) {
  const rows = JSON.parse(readFileSync(0, "utf8"));
  for (const row of rows) {
    const actions = row.actions || labActionsFromCommand(row.command, "manual", { tool: row.tool, target: row.target, params: row.params });
    row.steps = actions.map((action) => {
      const args = { ...action.params };
      if (typeof args.reason === "string" && /benchmark|benign baseline|public MCP/i.test(args.reason)) delete args.reason;
      return { user_message: row.command, tool_name: action.toolName, tool_args: args, tool_result: null, session_history: [] };
    });
    delete row.actions; delete row.command; delete row.tool; delete row.params; delete row.target;
  }
  process.stdout.write(JSON.stringify(rows));
} else {
  const path = option("--cases");
  const output = option("--output");
  if (!path || !output) throw new Error("--cases and --output are required");
  const source = readFileSync(path, "utf8");
  const cases = source.trim().split(/\r?\n/).map((line) => JSON.parse(line));
  const profiles = (option("--profiles") || "balanced,competition").split(",");
  const rows = [];
  for (const profile of profiles) {
    for (const entry of cases) {
      clearCustomToolManifests();
      if (entry.adapter === "agentdojo-workspace") {
        const document = JSON.parse(readFileSync(new URL("../manifests/agentdojo-workspace-v1.2.2.json", import.meta.url), "utf8"));
        for (const manifest of document.manifests) registerToolManifest(manifest, { version: document.mapping_version });
      }
      const config = PluginConfig.fromPluginConfig({ profile, semantic: { enabled: false } });
      const state = createPolicyState();
      const steps = [];
      let error = "";
      try {
        for (const payload of entry.steps) {
          if (JSON.stringify(Object.keys(payload).sort()) !== JSON.stringify(fields)) throw new Error("Invalid detector envelope");
          if (payload.session_history.length) throw new Error("History replay requires an explicit adapter");
          if (state.currentTask !== payload.user_message) {
            updateTaskSpec(state, [{ role: "user", content: payload.user_message }], config);
            updateAfterMessage(state, detectMessageContent(payload.user_message, config));
          }
          const toolCallId = randomUUID();
          const evaluation = await supervisionService.evaluate({ toolName: payload.tool_name, params: payload.tool_args, config, state, context: { workspaceDir: ROOT, toolCallId } });
          const result = evaluation.result;
          supervisionService.commit(state, result.policy, config, result.decision === "allow" ? "executing" : result.decision === "ask" ? "awaiting_approval" : "blocked");
          steps.push({ tool: payload.tool_name, normalized_tool: result.policy.action.tool, decision: result.decision, risk_score: result.risk_score,
            findings: result.findings.filter((finding) => finding.verdict !== "pass").map((finding) => ({ layer: finding.layer, reason: finding.reason, verdict: finding.verdict })),
            violations: result.policy.violations });
          if (result.decision !== "allow") break;
          if (payload.tool_result !== null) updateAfterMessage(state, resultFindings(toolCallId, payload.tool_result, state, config, payload.tool_name));
        }
      } catch (failure) { error = failure instanceof Error ? failure.message : String(failure); }
      const decision = steps.find((step) => step.decision !== "allow")?.decision || "allow";
      const groups = [...new Set(steps.flatMap((step) => step.findings.map((finding) => reasonGroup(finding.reason))))];
      rows.push({ profile, case_id: entry.case_id, input_sha256: entry.input_sha256, source: entry.provenance[0].source, expected: entry.label.expected,
        decision, evaluated_steps: steps.length, proposed_steps: entry.steps.length, steps, reason_groups: groups, harness_error: error });
    }
  }
  clearCustomToolManifests();
  writeFileSync(output, JSON.stringify({ evidence_level: "source_labeled_development_policy_replay", cases_sha256: createHash("sha256").update(source).digest("hex"), tools_executed: false,
    mode: "stop_on_first_intervention", task_utility: null, rows }, null, 2) + "\n");
  for (const profile of profiles) {
    const group = rows.filter((row) => row.profile === profile);
    const normal = group.filter((row) => row.expected === "allow");
    const controls = group.filter((row) => row.expected !== "allow");
    const counts = (items) => Object.fromEntries(["allow", "ask", "deny"].map((decision) => [decision, items.filter((row) => row.decision === decision).length]));
    console.log(JSON.stringify({ profile, workflows: group.length, normal_workflows: normal.length, normal_decisions: counts(normal), review_controls: controls.length,
      control_decisions: counts(controls), harness_errors: group.filter((row) => row.harness_error).length }));
  }
}

function reasonGroup(reason) {
  if (/sensitive|secret|credential|私钥|密钥/i.test(reason)) return "sensitive_data_boundary";
  if (/path|workspace|路径|目录/i.test(reason)) return "filesystem_scope";
  if (/loopback|private|metadata|allowed_targets|host|URL|network|origin/i.test(reason)) return "network_scope";
  if (/taint|provenance|污染|untrusted|injection|poison|hijack/i.test(reason)) return "taint_or_content";
  if (/authorization|授权|capability|intent|task family|task mode|side-effect tools/i.test(reason)) return "authorization_or_intent";
  if (/shell|command|execution|执行|命令/i.test(reason)) return "execution_boundary";
  return "other";
}
