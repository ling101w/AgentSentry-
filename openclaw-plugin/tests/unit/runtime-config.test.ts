import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const fsControl = vi.hoisted(() => ({ failRename: false }));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    renameSync: (oldPath: string, newPath: string): void => {
      if (fsControl.failRename) {
        throw Object.assign(new Error("simulated rename failure"), { code: "EACCES" });
      }
      actual.renameSync(oldPath, newPath);
    },
  };
});

import { PluginConfig } from "../../config.ts";
import {
  deleteRuntimeConfig,
  loadRuntimeConfig,
  runtimeConfigPath,
  saveRuntimeConfig,
} from "../../core/runtime-config.ts";

const tempRoots: string[] = [];
let originalStateDir: string | undefined;
let originalApiKey: string | undefined;

function tempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "agentsentry-runtime-config-"));
  tempRoots.push(root);
  return root;
}

function configAt(root = tempRoot()): PluginConfig {
  const config = new PluginConfig();
  config.storage.stateDir = root;
  return config;
}

function writeRuntimeFile(config: PluginConfig, value: unknown): void {
  const path = runtimeConfigPath(config);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value), "utf8");
}

beforeEach(() => {
  originalStateDir = process.env.OPENCLAW_STATE_DIR;
  originalApiKey = process.env.AGENTSENTRY_API_KEY;
  fsControl.failRename = false;
});

afterEach(() => {
  fsControl.failRename = false;
  if (originalStateDir === undefined) delete process.env.OPENCLAW_STATE_DIR;
  else process.env.OPENCLAW_STATE_DIR = originalStateDir;
  if (originalApiKey === undefined) delete process.env.AGENTSENTRY_API_KEY;
  else process.env.AGENTSENTRY_API_KEY = originalApiKey;
  for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("runtime config path", () => {
  it("prefers an explicit state directory and trims environment fallback", () => {
    const explicitRoot = tempRoot();
    const environmentRoot = tempRoot();
    process.env.OPENCLAW_STATE_DIR = `  ${environmentRoot}  `;

    const config = new PluginConfig();
    config.storage.stateDir = explicitRoot;
    expect(runtimeConfigPath(config)).toBe(join(explicitRoot, "agentsentry", "runtime-config.json"));

    config.storage.stateDir = "   ";
    expect(runtimeConfigPath(config)).toBe(join(environmentRoot, "agentsentry", "runtime-config.json"));
  });
});

describe("runtime config loading", () => {
  it("returns the same explicit config unchanged when no runtime file exists", () => {
    const base = configAt();
    base.dashboard.port = 9123;
    base.enforcement.mode = "block";

    const loaded = loadRuntimeConfig(base);
    expect(loaded).toBe(base);
    expect(loaded.dashboard.port).toBe(9123);
    expect(loaded.enforcement.mode).toBe("block");
  });

  it("merges only present known leaves and normalizes string arrays", () => {
    const base = configAt();
    base.dashboard.port = 9123;
    base.capture.previewChars = 777;
    (base.semantic as unknown as Record<string, unknown>).apiKey = "existing-private-value";
    writeRuntimeFile(base, {
      detection: { enabled: false },
      semantic: { apiKey: "attacker-controlled-value" },
      policy: { allowlistedRecipients: [" alice@example.test ", "alice@example.test", "bob@example.test"] },
      unknownSection: { enabled: true },
    });

    const loaded = loadRuntimeConfig(base);
    expect(loaded).toBe(base);
    expect(loaded.dashboard.port).toBe(9123);
    expect(loaded.capture.previewChars).toBe(777);
    expect(loaded.detection.enabled).toBe(false);
    expect(loaded.policy.allowlistedRecipients).toEqual(["alice@example.test", "bob@example.test"]);
    expect(loaded.semantic).toHaveProperty("apiKey", "existing-private-value");
    expect(loaded).not.toHaveProperty("unknownSection");
  });

  it("ignores malformed JSON, JSON primitives, arrays, and oversized files", () => {
    const base = configAt();
    base.dashboard.port = 9123;

    for (const contents of ["{not-json", "null", "42", "[]", `{"padding":"${"x".repeat(1024 * 1024)}"}`]) {
      writeRuntimeFile(base, contents);
      expect(loadRuntimeConfig(base).dashboard.port).toBe(9123);
    }
  });

  it("rejects type-compatible invalid enums and numbers while applying valid fields", () => {
    const base = configAt();
    base.profile = "balanced";
    base.enforcement.mode = "approval";
    base.semantic.mode = "risk-tiered";
    base.storage.maxRecords = 500;
    writeRuntimeFile(base, {
      profile: "unrestricted",
      enforcement: { mode: "permit", approvalTimeoutMs: -1 },
      semantic: { enabled: true, mode: "unsafe", timeoutMs: 100.9 },
      runtimeIsolation: { unavailableAction: "allow" },
      notifications: { minSeverity: "info" },
      storage: { maxRecords: 0 },
      detection: { askThreshold: 90, denyThreshold: 80 },
      policy: { allowlistedApiHosts: ["valid.test", 7] },
    });

    const loaded = loadRuntimeConfig(base);
    expect(loaded.profile).toBe("balanced");
    expect(loaded.enforcement.mode).toBe("approval");
    expect(loaded.enforcement.approvalTimeoutMs).toBe(300_000);
    expect(loaded.semantic.enabled).toBe(true);
    expect(loaded.semantic.mode).toBe("risk-tiered");
    expect(loaded.semantic.timeoutMs).toBe(100);
    expect(loaded.runtimeIsolation.unavailableAction).toBe("require_approval");
    expect(loaded.notifications.minSeverity).toBe("danger");
    expect(loaded.storage.maxRecords).toBe(500);
    expect(loaded.detection.askThreshold).toBe(70);
    expect(loaded.detection.denyThreshold).toBe(80);
    expect(loaded.policy.allowlistedApiHosts).toEqual([]);
  });

  it("applies a valid profile before explicit runtime overrides", () => {
    const base = configAt();
    writeRuntimeFile(base, {
      profile: " competition ",
      responseCover: { enabled: false },
    });

    const loaded = loadRuntimeConfig(base);
    expect(loaded.profile).toBe("competition");
    expect(loaded.enforcement.mode).toBe("approval");
    expect(loaded.semantic.enabled).toBe(true);
    expect(loaded.policy.restrictWritesToAllowedRoots).toBe(true);
    expect(loaded.responseCover.enabled).toBe(false);
  });
});

describe("runtime config persistence", () => {
  it("saves known settings without persisting dynamic secrets or unknown fields", () => {
    const config = configAt();
    const secret = "runtime-secret-value-that-must-not-be-written";
    config.enforcement.mode = "block";
    config.policy.allowlistedApiHosts = ["api.example.test"];
    process.env[config.semantic.apiKeyEnv] = secret;
    (config as unknown as Record<string, unknown>).token = secret;
    (config.semantic as unknown as Record<string, unknown>).apiKey = secret;

    saveRuntimeConfig(config);

    const contents = readFileSync(runtimeConfigPath(config), "utf8");
    const saved = JSON.parse(contents) as Record<string, unknown>;
    expect(contents.endsWith("\n")).toBe(true);
    expect(contents).not.toContain(secret);
    expect(saved).not.toHaveProperty("token");
    expect(saved).not.toHaveProperty("semantic.apiKey");
    expect(saved).toHaveProperty("semantic.apiKeyEnv", config.semantic.apiKeyEnv);
    expect(saved).toHaveProperty("enforcement.mode", "block");
    expect(saved).toHaveProperty("policy.allowlistedApiHosts", ["api.example.test"]);
  });

  it("atomically replaces an existing config and removes temporary files", () => {
    const config = configAt();
    config.dashboard.port = 9001;
    saveRuntimeConfig(config);
    config.dashboard.port = 9002;
    saveRuntimeConfig(config);

    expect(JSON.parse(readFileSync(runtimeConfigPath(config), "utf8"))).toHaveProperty("dashboard.port", 9002);
    expect(readdirSync(dirname(runtimeConfigPath(config))).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });

  it("preserves the previous config and cleans up when the atomic rename fails", () => {
    const config = configAt();
    config.dashboard.port = 9001;
    saveRuntimeConfig(config);
    const previous = readFileSync(runtimeConfigPath(config), "utf8");

    config.dashboard.port = 9002;
    fsControl.failRename = true;
    expect(() => saveRuntimeConfig(config)).toThrow("simulated rename failure");

    expect(readFileSync(runtimeConfigPath(config), "utf8")).toBe(previous);
    expect(readdirSync(dirname(runtimeConfigPath(config))).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });

  it("propagates directory/write failures without creating a runtime file", () => {
    const root = tempRoot();
    const config = new PluginConfig();
    config.storage.stateDir = join(root, "state");
    mkdirSync(config.storage.stateDir);
    writeFileSync(join(config.storage.stateDir, "agentsentry"), "not a directory", "utf8");

    expect(() => saveRuntimeConfig(config)).toThrow();
    expect(existsSync(runtimeConfigPath(config))).toBe(false);
  });

  it("uses owner-only permissions where POSIX file modes are available", () => {
    if (process.platform === "win32") return;
    const config = configAt();
    saveRuntimeConfig(config);
    expect(statSync(runtimeConfigPath(config)).mode & 0o777).toBe(0o600);
  });

  it("deletes persisted state idempotently", () => {
    const config = configAt();
    saveRuntimeConfig(config);
    expect(existsSync(runtimeConfigPath(config))).toBe(true);

    deleteRuntimeConfig(config);
    deleteRuntimeConfig(config);
    expect(existsSync(runtimeConfigPath(config))).toBe(false);
  });
});
