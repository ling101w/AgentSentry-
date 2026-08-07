import { describe, expect, it } from "vitest";
import { annotateActiveSkills } from "../../core/skill-context.ts";
import type { InitializationScanResult } from "../../core/init-defense.ts";

const SCAN: InitializationScanResult = {
  roots: ["/workspace"],
  scanned_at: "2026-08-06T00:00:00.000Z",
  blocked: false,
  findings: [],
  components: [
    {
      id: "cmp-weather",
      kind: "skill",
      path: "skills/weather/SKILL.md",
      root: "/workspace",
      sha256: "a".repeat(64),
      size: 120,
      risk: 20,
      trust: "trusted",
      admission: "allow_limited",
      admissionReason: "本地低风险 Skill",
      manifest: {
        present: false,
        path: "",
        signed: false,
        declaredCapabilities: ["network_read"],
      },
    },
    {
      id: "cmp-risky",
      kind: "skill",
      path: "skills/risky/SKILL.md",
      root: "/workspace",
      sha256: "b".repeat(64),
      size: 120,
      risk: 90,
      trust: "blocked",
      admission: "quarantine",
      admissionReason: "高危组合",
      manifest: {
        present: false,
        path: "",
        signed: false,
        declaredCapabilities: ["network_write", "sensitive_read"],
      },
    },
  ],
};

describe("active Skill context annotation", () => {
  it("adds a low-risk Skill annotation only when the user explicitly references that Skill", () => {
    const annotations = annotateActiveSkills(SCAN, {}, {}, "请使用 /weather Skill 查询杭州天气。");
    expect(annotations).toHaveLength(1);
    expect(annotations[0]).toMatchObject({ skillName: "weather", admission: "allow_limited" });
    expect(annotations[0].text).toContain("作者未提供完整能力清单");
    expect(annotations[0].text).toContain("不授予额外权限");
  });

  it("does not add unrelated Skill inventory entries to normal prompts", () => {
    expect(annotateActiveSkills(SCAN, {}, {}, "整理今天的会议纪要。"))
      .toEqual([]);
  });

  it("uses OpenClaw-provided active Skill metadata when available", () => {
    const annotations = annotateActiveSkills(SCAN, { activeSkills: ["weather"] }, {}, "查询杭州天气。");
    expect(annotations.map((item) => item.skillName)).toEqual(["weather"]);
  });
});
