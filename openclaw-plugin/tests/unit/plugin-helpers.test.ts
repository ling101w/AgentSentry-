import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  notificationRoute,
  provenanceRootsFor,
  severityForDecision,
  severityForVerdict,
  shouldCoverAssistantResponse,
  shouldNotify,
  shouldReturnJudgeAnalysis,
} from "../../core/plugin-helpers.ts";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("plugin lifecycle helpers", () => {
  it("shows Judge analysis only when semantic evidence is materially risky", () => {
    const semantic = { finding_type: "semantic", verdict: "pass", score: 10, evidence: { semanticRisk: "low" } };
    expect(shouldReturnJudgeAnalysis([], 100, "deny")).toBe(false);
    expect(shouldReturnJudgeAnalysis([semantic], 20, "allow")).toBe(false);
    expect(shouldReturnJudgeAnalysis([semantic], 55, "allow")).toBe(true);
    expect(shouldReturnJudgeAnalysis([semantic], 10, "deny")).toBe(true);
    expect(shouldReturnJudgeAnalysis([{ ...semantic, verdict: "block" }], 10, "allow")).toBe(true);
  });

  it("maps policy outcomes to stable record severities", () => {
    expect(severityForDecision("deny")).toBe("danger");
    expect(severityForDecision("ask")).toBe("warning");
    expect(severityForDecision("allow")).toBe("success");
    expect(severityForVerdict("block")).toBe("danger");
    expect(severityForVerdict("require_approval")).toBe("warning");
    expect(severityForVerdict("pass")).toBe("info");
  });

  it("covers only contaminated assistant responses when both controls are enabled", () => {
    const enabled = { enabled: true, coverAssistantAfterContamination: true };
    expect(shouldCoverAssistantResponse(enabled, true, "assistant")).toBe(true);
    expect(shouldCoverAssistantResponse(enabled, false, "assistant")).toBe(false);
    expect(shouldCoverAssistantResponse(enabled, true, "user")).toBe(false);
    expect(shouldCoverAssistantResponse({ ...enabled, enabled: false }, true, "assistant")).toBe(false);
  });

  it("honors notification thresholds and supported routes", () => {
    expect(shouldNotify({ enableProactiveNotifications: false, minSeverity: "warning" }, "danger")).toBe(false);
    expect(shouldNotify({ enableProactiveNotifications: true, minSeverity: "danger" }, "warning")).toBe(false);
    expect(shouldNotify({ enableProactiveNotifications: true, minSeverity: "danger" }, "danger")).toBe(true);
    expect(shouldNotify({ enableProactiveNotifications: true, minSeverity: "warning" }, "warning")).toBe(true);
    expect(notificationRoute({ messageProvider: "FeiShu", sessionKey: "agent:user-42" })).toEqual({ channel: "feishu", target: "user-42" });
    expect(notificationRoute({ messageProvider: "qqbot", sessionKey: "user-7" })).toEqual({ channel: "qqbot", target: "user-7" });
    expect(notificationRoute({ messageProvider: "email", sessionKey: "user-7" })).toBeNull();
    expect(notificationRoute({ messageProvider: "feishu", sessionKey: "" })).toBeNull();
  });

  it("uses the platform path delimiter and removes nested provenance roots", () => {
    const root = makeDirectory("agentsentry-plugin-roots-");
    const workspace = mkdir(join(root, "workspace"));
    const home = mkdir(join(root, "home"));
    const pluginSkills = mkdir(join(home, ".openclaw", "plugin-skills"));
    const userSkills = mkdir(join(home, ".openclaw", "skills"));
    const externalA = mkdir(join(root, "external-a"));
    const externalB = mkdir(join(root, "external-b"));

    expect(provenanceRootsFor(workspace, {
      homeDir: home,
      skillsPathList: [externalA, externalB].join(delimiter),
    })).toEqual([workspace, pluginSkills, userSkills, externalA, externalB].map((item) => resolve(item)));

    const openclawWorkspace = resolve(home, ".openclaw");
    expect(provenanceRootsFor(openclawWorkspace, { homeDir: home, skillsPathList: "" })).toEqual([openclawWorkspace]);
  });
});

function makeDirectory(prefix: string): string {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

function mkdir(path: string): string {
  mkdirSync(path, { recursive: true });
  return path;
}
