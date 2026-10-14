import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { assertProductionGraphInput } from "../dist/core/graph-learning/production-graph.js";

const options = parseArgs(process.argv.slice(2));
if (!options.input) fail("usage: --input <graph-training.jsonl> [--report <report.json>]");

const inputPath = resolve(options.input);
const lines = readFileSync(inputPath, "utf8").split(/\r?\n/).filter(Boolean);
const rows = [];
let invalidRows = 0;
let forbiddenMatches = 0;
for (const line of lines) {
  try {
    const row = JSON.parse(line);
    assertProductionGraphInput(row.input);
    if (!row.label || row.label.source !== "policy_weak_label") throw new Error("missing independent label envelope");
    rows.push(row);
    forbiddenMatches += countForbidden(JSON.stringify(row.input));
  } catch {
    invalidRows += 1;
  }
}

const nodes = rows.map((row) => row.input.graph.nodes.length);
const edges = rows.map((row) => row.input.graph.edges.length);
const truncated = rows.filter((row) => row.input.graph.projection_truncated).length;
const report = {
  schema_version: "graph-learning-pilot-report-v1",
  generated_at: new Date().toISOString(),
  source: inputPath,
  rows_read: lines.length,
  rows_exported: rows.length,
  invalid_rows: invalidRows,
  node_count: summarize(nodes),
  edge_count: summarize(edges),
  projection_truncated: truncated,
  truncation_rate: ratio(truncated, rows.length),
  weak_label_distribution: {
    allow: rows.filter((row) => row.label.policy_outcome === "allow").length,
    review: rows.filter((row) => row.label.policy_outcome === "review").length,
    block: rows.filter((row) => row.label.policy_outcome === "block").length,
  },
  input_forbidden_key_matches: forbiddenMatches,
  quality_gate: rows.length > 0 && invalidRows === 0 && forbiddenMatches === 0 ? "pass" : "fail",
};
if (options.report) writeFileSync(resolve(options.report), `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (report.quality_gate !== "pass") process.exitCode = 1;

function parseArgs(args) {
  const result = { input: "", report: "" };
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--input") result.input = args[++index] || "";
    else if (args[index] === "--report") result.report = args[++index] || "";
    else fail(`unknown argument: ${args[index]}`);
  }
  return result;
}

function summarize(values) {
  if (!values.length) return { min: null, mean: 0, max: null };
  return {
    min: Math.min(...values),
    mean: Math.round((values.reduce((sum, value) => sum + value, 0) / values.length) * 100) / 100,
    max: Math.max(...values),
  };
}

function ratio(numerator, denominator) {
  return denominator ? Math.round((numerator / denominator) * 10_000) / 10_000 : 0;
}

function countForbidden(serialized) {
  return (serialized.match(/"(?:decision|status|verdict|label|findings|risk_score|sentry_score|judge_output)"/g) || []).length;
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}
