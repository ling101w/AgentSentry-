import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { detectToolCall } from "../../core/detect.ts";
import { createPolicyState, updateTaskSpec } from "../../core/policy.ts";
import { matchWorkspaceReadPath, pathInsideCanonicalRoot } from "../../core/path-security.ts";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): { workspace: string; outside: string } {
  const root = mkdtempSync(join(tmpdir(), "agentsentry-path-"));
  roots.push(root);
  const workspace = join(root, "workspace");
  const outside = join(root, "outside");
  mkdirSync(join(workspace, "docs"), { recursive: true });
  mkdirSync(outside, { recursive: true });
  writeFileSync(join(workspace, "docs", "report.md"), "report");
  writeFileSync(join(outside, "secret.txt"), "secret");
  return { workspace, outside };
}

describe("canonical filesystem boundaries", () => {
  it("allows reads inside the real workspace and rejects traversal and absolute escapes", () => {
    const { workspace, outside } = fixture();
    expect(matchWorkspaceReadPath("docs/report.md", workspace).allowed).toBe(true);
    expect(matchWorkspaceReadPath("../outside/secret.txt", workspace).allowed).toBe(false);
    expect(matchWorkspaceReadPath(join(outside, "secret.txt"), workspace).allowed).toBe(false);
  });

  it("rejects UNC reads before filesystem canonicalization", () => {
    const { workspace } = fixture();
    expect(matchWorkspaceReadPath("//github.com/octocat/Hello-World'", workspace)).toMatchObject({
      allowed: false,
      reason: expect.stringContaining("UNC or network path"),
    });
  });

  it("rejects a workspace symlink or junction that resolves outside", () => {
    const { workspace, outside } = fixture();
    const link = join(workspace, "linked-outside");
    symlinkSync(outside, link, process.platform === "win32" ? "junction" : "dir");
    expect(matchWorkspaceReadPath(join("linked-outside", "secret.txt"), workspace)).toMatchObject({ allowed: false });
  });

  it("denies read and write aliases whose canonical target is a sensitive file", () => {
    const { workspace } = fixture();
    const output = join(workspace, "output");
    mkdirSync(output);
    let readAlias = "public.txt";
    let writeAlias = "output/public.txt";
    if (process.platform === "win32") {
      const readTarget = join(workspace, ".env.local");
      const writeTarget = join(output, ".env.local");
      mkdirSync(readTarget);
      mkdirSync(writeTarget);
      writeFileSync(join(readTarget, "secret.txt"), "SECRET=read-target");
      writeFileSync(join(writeTarget, "secret.txt"), "SECRET=write-target");
      symlinkSync(readTarget, join(workspace, "public"), "junction");
      symlinkSync(writeTarget, join(output, "public"), "junction");
      readAlias = "public/secret.txt";
      writeAlias = "output/public/secret.txt";
    } else {
      writeFileSync(join(workspace, ".env"), "SECRET=read-target");
      writeFileSync(join(output, ".env"), "SECRET=write-target");
      symlinkSync(join(workspace, ".env"), join(workspace, readAlias), "file");
      symlinkSync(join(output, ".env"), join(workspace, writeAlias), "file");
    }

    const readConfig = new PluginConfig();
    const readState = createPolicyState();
    updateTaskSpec(readState, [{ role: "user", content: `Read ${readAlias}` }], readConfig);
    const read = detectToolCall("read_file", { path: readAlias }, readConfig, readState, [], { workspaceDir: workspace });
    expect(read.decision).toBe("deny");
    expect(read.policy.violations).toContain("read path references sensitive asset");

    const writeConfig = new PluginConfig();
    writeConfig.policy.restrictWritesToAllowedRoots = true;
    writeConfig.policy.allowedWriteRoots = ["output"];
    const writeState = createPolicyState();
    updateTaskSpec(writeState, [{ role: "user", content: `Write hello to ${writeAlias}` }], writeConfig);
    const write = detectToolCall("write_file", { path: writeAlias, content: "hello" }, writeConfig, writeState, [], { workspaceDir: workspace });
    expect(write.decision).toBe("deny");
    expect(write.policy.violations).toContain("write path references sensitive asset");

    writeConfig.policy.restrictWritesToAllowedRoots = false;
    const unrestrictedWrite = detectToolCall("write_file", { path: writeAlias, content: "hello" }, writeConfig, writeState, [], { workspaceDir: workspace });
    expect(unrestrictedWrite.decision).toBe("deny");
    expect(unrestrictedWrite.policy.violations).toContain("write path references sensitive asset");
  });

  it("handles Windows drive and UNC containment without prefix confusion", () => {
    expect(pathInsideCanonicalRoot(String.raw`C:\safe\root\file.txt`, String.raw`C:\safe\root`, "win32")).toBe(true);
    expect(pathInsideCanonicalRoot(String.raw`D:\safe\root\file.txt`, String.raw`C:\safe\root`, "win32")).toBe(false);
    expect(pathInsideCanonicalRoot(String.raw`\\server\share\root\file.txt`, String.raw`\\server\share\root`, "win32")).toBe(true);
    expect(pathInsideCanonicalRoot(String.raw`\\server\other\root\file.txt`, String.raw`\\server\share\root`, "win32")).toBe(false);
  });

  it("resolves relative write roots from the supplied workspace rather than process cwd", () => {
    const { workspace } = fixture();
    mkdirSync(join(workspace, "output"));
    const config = new PluginConfig();
    config.policy.restrictWritesToAllowedRoots = true;
    config.policy.allowedWriteRoots = ["output"];
    const state = createPolicyState();
    updateTaskSpec(state, [{ role: "user", content: "Write the result to output/result.txt" }], config);

    const inside = detectToolCall("write_file", { path: "output/result.txt", content: "ok" }, config, state, [], { workspaceDir: workspace });
    const escaped = detectToolCall("write_file", { path: "../outside/result.txt", content: "no" }, config, state, [], { workspaceDir: workspace });
    const missingWorkspace = detectToolCall("write_file", { path: "output/result.txt", content: "no" }, config, state, [], { workspaceDir: "" });
    expect(inside.policy.violations.some((item) => item.includes("write path escapes"))).toBe(false);
    expect(escaped.policy.violations.some((item) => item.includes("write path escapes"))).toBe(true);
    expect(missingWorkspace.policy.violations).toContain("write path cannot be authorized without a workspace root");
  });
});
