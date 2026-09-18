import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const demoHtml = readFileSync(new URL("../../public/demo/selected-cases/index.html", import.meta.url), "utf8");
const demoJs = readFileSync(new URL("../../public/demo/selected-cases/demo.js", import.meta.url), "utf8");
const demoCases = readFileSync(new URL("../../public/demo/selected-cases/demo-cases.js", import.meta.url), "utf8");
const dashboardTs = readFileSync(new URL("../../server/dashboard.ts", import.meta.url), "utf8");
const commandLabHtml = readFileSync(new URL("../../public/command-lab.html", import.meta.url), "utf8");
const commandLabJs = readFileSync(new URL("../../public/command-lab.js", import.meta.url), "utf8");

describe("governance process demo", () => {
  it("exposes a recorded three-case playback page", () => {
    expect(demoHtml).toContain("真实治理过程演示");
    expect(demoHtml).toContain("./demo-cases.js");
    expect(demoHtml).toContain("./demo.js");
    expect(demoJs).toContain("XUANJIAN_DEMO_CASES");
    expect(commandLabHtml).toContain('href="/demo"');
    expect(commandLabHtml).toContain("workspace_injection_12_11");
    expect(commandLabHtml).toContain("deeptrap_r3_t05");
    expect(commandLabHtml).toContain("deeptrap_r2_t07");
    expect(commandLabHtml).toContain(">测评<");
    expect(commandLabHtml).toContain(">正常请求<");
    expect(commandLabHtml).not.toContain(">交互实验<");
    expect(commandLabHtml).not.toContain(">公开样例<");
    expect(commandLabHtml).not.toContain(">真实 Agent<");
    expect(commandLabHtml).toContain("interventionSelect");
    expect(commandLabHtml).toContain("证据门控");
  });

  it("covers injection, tool hijack, and memory poison from existing benchmark logs", () => {
    expect(demoCases).toContain('id: "injection"');
    expect(demoCases).toContain('id: "tool"');
    expect(demoCases).toContain('id: "memory"');
    expect(demoCases).toContain("agentdojo:workspace:UserTask7:InjectionTask0");
    expect(demoCases).toContain("agentdefense:toolpoisoning-backdoor-042-conditional");
    expect(demoCases).toContain("memorygraft-poison:exp_poison_010");
    expect(demoCases).toContain("~/.ssh/id_ed25519");
    expect(demoCases).toContain("~/.aws/credentials");
    expect(demoCases).toContain("report_delivery_profile");
  });

  it("routes /demo to the selected-cases page and allows embedding", () => {
    expect(dashboardTs).toContain('Location: `/demo/selected-cases/index.html${url.search}`');
    expect(dashboardTs).toContain("function isPublicDemoPath");
    expect(dashboardTs).toContain("function resolvePublicRequestPath");
    expect(dashboardTs).toContain('res.setHeader("Content-Security-Policy", "frame-ancestors *")');
    expect(dashboardTs).toContain('pathname === "/command-lab") return "/command-lab.html"');
  });

  it("adds labeled malicious and benign featured public samples", () => {
    expect(commandLabJs).toContain("const FEATURED_BENCHMARKS");
    expect(commandLabJs).toContain("恶意 · 应拦截");
    expect(commandLabJs).toContain("正常 · 应放行");
    expect(commandLabJs).toContain("agentdojo:workspace:UserTask7:InjectionTask0");
    expect(commandLabJs).toContain("redteamcua:adversary_task.raw_own_owncloud_setup_project:3");
    expect(commandLabJs).toContain("memorygraft-poison:exp_poison_010");
    expect(commandLabJs).toContain("agentdojo-benign:workspace:UserTask6");
    expect(commandLabJs).toContain("agentdefense-benign:benign-normal-058");
    expect(commandLabJs).toContain("agentdefense-benign:benign-normal-005");
    expect(commandLabJs).toContain("隐藏邮件改约");
    expect(commandLabJs).toContain("约午餐（无注入）");
    expect(commandLabJs).toContain("普通业务通知邮件");
  });
});
