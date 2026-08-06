import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const screenSource = readFileSync(new URL("../../public/security-screen.html", import.meta.url), "utf8");

function occurrences(value: string): number {
  return screenSource.split(value).length - 1;
}

describe("security screen overview console", () => {
  it("uses one accessible four-tab console without duplicating live data targets", () => {
    expect(occurrences("data-overview-pane=")).toBe(4);
    expect(occurrences("data-overview-panel=")).toBe(4);
    expect(occurrences('id="protectionIndex"')).toBe(1);
    expect(occurrences('id="lifecycleBars"')).toBe(1);
    expect(occurrences('id="modeList"')).toBe(1);
    expect(occurrences('id="attackStages"')).toBe(1);
    expect(screenSource).toContain('role="tablist" aria-label="态势模块"');
    expect(screenSource).toContain("function setOverviewPane");
    expect(screenSource).toContain('event.key === "ArrowLeft"');
    expect(screenSource).toContain('event.key === "ArrowRight"');
  });

  it("moves the attack chain into the side console and leaves a two-panel bottom row", () => {
    const leftColumnStart = screenSource.indexOf('<aside class="left-col">');
    const leftColumnEnd = screenSource.indexOf("</aside>", leftColumnStart);
    const attackStages = screenSource.indexOf('id="attackStages"');
    const bottomGrid = screenSource.indexOf('<section class="bottom-grid">');

    expect(leftColumnStart).toBeGreaterThanOrEqual(0);
    expect(attackStages).toBeGreaterThan(leftColumnStart);
    expect(attackStages).toBeLessThan(leftColumnEnd);
    expect(bottomGrid).toBeGreaterThan(leftColumnEnd);
    expect(screenSource).toContain("grid-template-columns: minmax(0, 0.92fr) minmax(0, 1.58fr) !important");
    expect(screenSource).not.toContain("A. 当前防护态势");
    expect(screenSource).not.toContain("A. 攻击链阶段分布");
    expect(screenSource).not.toContain("B. 策略命中排行");
    expect(screenSource).not.toContain("C. 最近事件时间线");
  });

  it("uses the Xuanjian-ready banner copy", () => {
    expect(screenSource).toContain("玄鉴已启动 · 全域戒备");
    expect(screenSource).toContain("玄鉴在线 · 风险巡弋中");
    expect(screenSource).toContain("重防线已列阵");
    expect(screenSource).not.toContain("比赛防护链路已就绪");
  });
});
