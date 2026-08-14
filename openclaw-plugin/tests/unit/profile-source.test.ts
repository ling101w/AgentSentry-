import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  loadSecurityProfileDefinition,
  PluginConfig,
  type SecurityProfileName,
} from "../../config.ts";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

describe("security profile source files", () => {
  it("keeps the default config synchronized with observe.json", () => {
    expect(new PluginConfig()).toMatchObject(loadSecurityProfileDefinition("observe"));
  });

  it("loads every named posture from the source profile directory", () => {
    const profiles: SecurityProfileName[] = ["observe", "balanced", "competition", "evidence-gated", "high-security"];

    for (const profile of profiles) {
      const definition = loadSecurityProfileDefinition(profile);
      expect(definition.profile).toBe(profile);
      expect(definition.policy.deterministic).toBe(true);
      expect(definition.semantic.mode).toBe("risk-tiered");
      expect(definition.intervention.preserveSafetyBoundaries).toBe(true);
    }
    expect(loadSecurityProfileDefinition("evidence-gated").intervention.mode).toBe("evidence-gated");
  });

  it("publishes the evidence-gated profile and intervention settings in the plugin schema", () => {
    const manifestUrl = new URL("../../openclaw.plugin.json", import.meta.url);
    const manifest = JSON.parse(readFileSync(manifestUrl, "utf8")) as Record<string, any>;

    expect(manifest.configSchema.properties.profile.enum).toContain("evidence-gated");
    expect(manifest.configSchema.properties.intervention.properties.mode.enum).toEqual(["risk-based", "evidence-gated"]);
    expect(manifest.configSchema.properties.intervention.properties.preserveSafetyBoundaries.type).toBe("boolean");
    expect(manifest.configSchema.properties.semantic.properties.timeoutMs.description).toContain("500-90000");
    expect(manifest.uiHints).toHaveProperty("intervention.mode");
    expect(manifest.uiHints).toHaveProperty("intervention.preserveSafetyBoundaries");
  });

  it("applies profile defaults before explicit nested user configuration", () => {
    const config = PluginConfig.fromPluginConfig({
      profile: "competition",
      enforcement: { mode: "observe" },
      semantic: { enabled: false, judgeProvenance: false },
      policy: { allowedWriteRoots: ["custom-output"] },
      notifications: { minSeverity: "danger" },
    });

    expect(config).toMatchObject({
      profile: "competition",
      enforcement: { mode: "observe" },
      semantic: { enabled: false, judgeProvenance: false },
      policy: { allowedWriteRoots: ["custom-output"] },
      notifications: { minSeverity: "danger" },
    });
  });

  it("reports an unreadable profile without silently using defaults", () => {
    const directory = createProfileDirectory();

    expect(() => loadSecurityProfileDefinition("competition", directory.url)).toThrow(
      /security profile "competition".*could not be read/i,
    );
  });

  it("reports invalid JSON with the profile name and failure stage", () => {
    const directory = createProfileDirectory();
    writeFileSync(join(directory.path, "competition.json"), "{ not-json", "utf8");

    expect(() => loadSecurityProfileDefinition("competition", directory.url)).toThrow(
      /security profile "competition".*contains invalid JSON/i,
    );
  });

  it.each([
    ["wrong field type", (profile: Record<string, any>) => { profile.semantic.enabled = "true"; }, /semantic\.enabled must be a boolean/i],
    ["unknown field", (profile: Record<string, any>) => { profile.policy.typo = true; }, /policy contains unknown field\(s\): typo/i],
    ["missing field", (profile: Record<string, any>) => { delete profile.runtimeIsolation.auditAfterExecution; }, /runtimeIsolation is missing required field\(s\): auditAfterExecution/i],
    ["invalid intervention mode", (profile: Record<string, any>) => { profile.intervention.mode = "threshold-only"; }, /intervention\.mode must be one of: risk-based, evidence-gated/i],
    ["missing intervention boundary flag", (profile: Record<string, any>) => { delete profile.intervention.preserveSafetyBoundaries; }, /intervention is missing required field\(s\): preserveSafetyBoundaries/i],
    ["profile name mismatch", (profile: Record<string, any>) => { profile.profile = "balanced"; }, /profile\.profile must be "competition"/i],
  ])("rejects a structurally invalid definition: %s", (_label, mutate, expectedError) => {
    const directory = createProfileDirectory();
    const profile = readCompetitionProfile();
    mutate(profile);
    writeFileSync(join(directory.path, "competition.json"), JSON.stringify(profile), "utf8");

    expect(() => loadSecurityProfileDefinition("competition", directory.url)).toThrow(expectedError);
  });
});

function createProfileDirectory(): { path: string; url: URL } {
  const path = mkdtempSync(join(tmpdir(), "agentsentry-profiles-"));
  temporaryDirectories.push(path);
  return { path, url: pathToFileURL(`${path}${sep}`) };
}

function readCompetitionProfile(): Record<string, any> {
  const profileUrl = new URL("../../profiles/competition.json", import.meta.url);
  return JSON.parse(readFileSync(profileUrl, "utf8")) as Record<string, any>;
}
