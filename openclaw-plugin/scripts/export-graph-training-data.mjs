import { createReadStream, createWriteStream, existsSync, mkdirSync, renameSync, rmSync } from "node:fs";
import { once } from "node:events";
import { dirname, resolve } from "node:path";
import { createInterface } from "node:readline";
import { graphTrainingRowFromRecord } from "../dist/core/graph-learning/training-export.js";

const options = parseArgs(process.argv.slice(2));
if (!options.input || !options.output) fail("usage: --input <records.jsonl> --output <graph-training.jsonl> [--force]");

const inputPath = resolve(options.input);
const outputPath = resolve(options.output);
if (!existsSync(inputPath)) fail(`input does not exist: ${inputPath}`);
if (inputPath === outputPath) fail("input and output must be different files");
if (existsSync(outputPath) && !options.force) fail(`output exists; pass --force to replace it: ${outputPath}`);

mkdirSync(dirname(outputPath), { recursive: true });
const temporaryPath = `${outputPath}.tmp-${process.pid}`;
const output = createWriteStream(temporaryPath, { encoding: "utf8", flags: "wx", mode: 0o600 });
let read = 0;
let exported = 0;
let invalid = 0;

try {
  const lines = createInterface({ input: createReadStream(inputPath, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    read += 1;
    try {
      const row = graphTrainingRowFromRecord(JSON.parse(line));
      if (!row) continue;
      if (!output.write(`${JSON.stringify(row)}\n`)) await once(output, "drain");
      exported += 1;
    } catch {
      invalid += 1;
    }
  }
  output.end();
  await once(output, "close");
  if (existsSync(outputPath)) rmSync(outputPath, { force: true });
  renameSync(temporaryPath, outputPath);
} catch (error) {
  output.destroy();
  rmSync(temporaryPath, { force: true });
  throw error;
}

process.stdout.write(`${JSON.stringify({ input: inputPath, output: outputPath, records_read: read, rows_exported: exported, invalid_rows: invalid })}\n`);

function parseArgs(args) {
  const parsed = { input: "", output: "", force: false };
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (value === "--force") parsed.force = true;
    else if (value === "--input") parsed.input = args[++index] || "";
    else if (value === "--output") parsed.output = args[++index] || "";
    else fail(`unknown argument: ${value}`);
  }
  return parsed;
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}
