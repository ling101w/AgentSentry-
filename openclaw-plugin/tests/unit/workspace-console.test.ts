import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const indexHtml = readFileSync(new URL("../../public/index.html", import.meta.url), "utf8");
const workspaceHtml = readFileSync(new URL("../../public/workspace.html", import.meta.url), "utf8");
const workspaceJs = readFileSync(new URL("../../public/workspace.js", import.meta.url), "utf8");
const appJs = readFileSync(new URL("../../public/app.js", import.meta.url), "utf8");
const themeJs = readFileSync(new URL("../../public/theme.js", import.meta.url), "utf8");
const themesCss = readFileSync(new URL("../../public/themes.css", import.meta.url), "utf8");
const dashboardTs = readFileSync(new URL("../../server/dashboard.ts", import.meta.url), "utf8");

describe("玄鉴 operations workspace", () => {
  it("exposes every operations view through the shared shell", () => {
    for (const path of ["/overview", "/agents", "/policies", "/tools", "/alerts", "/audit", "/settings"]) {
      expect(workspaceHtml).toContain(`href="${path}"`);
      expect(workspaceHtml).toContain(`data-nav="${path.slice(1)}"`);
    }
    expect(workspaceHtml).toContain('href="/" data-nav="monitor"');
    expect(dashboardTs).toContain('"/workspace.html"');
    expect(dashboardTs).toContain('["/overview", "/agents", "/policies", "/tools", "/alerts", "/audit", "/settings"]');
  });

  it("uses the live dashboard contracts for each workspace surface", () => {
    for (const endpoint of [
      "/api/security/overview",
      "/api/policy/config",
      "/api/tools/manifests",
      "/api/security/alerts",
      "/api/records",
      "/api/stats",
      "/api/health",
      "/api/checkpoints",
    ]) {
      expect(workspaceJs).toContain(endpoint);
    }
    for (const endpoint of [
      "/api/policy/config",
      "/api/settings/enforcement",
      "/api/tools/manifests/register",
      "/api/tools/manifests/revoke",
      "/api/tools/manifests/restore",
      "/api/checkpoints/restore",
    ]) {
      expect(workspaceJs).toContain(endpoint);
    }
  });

  it("prioritizes current posture and keeps tool attributes visually restrained", () => {
    for (const label of ["当前安全状态", "主要风险", "需要处理", "最近运行事件"]) {
      expect(workspaceJs).toContain(label);
    }
    expect(workspaceJs).toContain('class="overview-command-center"');
    expect(workspaceJs).toContain('const secondaryMetrics = ["total", "tools", "taint", "drift"]');
    expect(workspaceJs).not.toContain('metric.en || "REALTIME"');
    expect(workspaceJs).toContain("plainBoolean(manifest.acceptsSensitiveData)");
    expect(workspaceJs).toContain("plainAttribute(trustLabel(manifest.defaultTrust))");
  });

  it("keeps drawer actions delegated and allows a requested session to open", () => {
    expect(workspaceJs).toContain('$("drawerBody").addEventListener("click", handleContentClick)');
    expect(workspaceJs).toContain('data-action="revoke-tool"');
    expect(workspaceJs).toContain('data-action="restore-tool"');
    expect(appJs).toContain('new URLSearchParams(window.location.search).get("session")');
  });

  it("exposes a persistent theme switch on both investigation shells", () => {
    expect(workspaceHtml).toContain("data-theme-toggle");
    expect(workspaceHtml).toContain('/themes.css?v=20260809-2');
    expect(workspaceHtml).toContain('/theme.js?v=20260809-2');
    expect(indexHtml).toContain("data-theme-toggle");
    expect(themeJs).toContain("agentsentry-console-theme");
    expect(themeJs).toContain("localStorage.setItem");
    expect(themesCss).toContain('html[data-theme="graphite"]');
  });
});
