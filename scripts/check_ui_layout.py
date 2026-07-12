from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from playwright.sync_api import sync_playwright

from playwright_browser import launch_chromium


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "reports" / "ui-screenshots"
BASE_URL = "http://127.0.0.1:8000"

VIEWPORTS = [
    ("dashboard-1440x900", "/", 1440, 900),
    ("dashboard-390x844", "/", 390, 844),
    ("screen-1920x1080", "/security-screen", 1920, 1080),
    ("screen-1366x768", "/security-screen", 1366, 768),
    ("screen-1180x760", "/security-screen", 1180, 760),
]


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    all_issues: list[dict] = []
    matrix_checks: list[dict] = []
    wait_for_server()
    with sync_playwright() as p:
        browser = launch_chromium(p)
        for name, path, width, height in VIEWPORTS:
            page = browser.new_page(viewport={"width": width, "height": height}, device_scale_factor=1)
            page.goto(f"{BASE_URL}{path}", wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(1400)
            screenshot = OUT_DIR / f"{name}.png"
            page.screenshot(path=str(screenshot), full_page=True)
            issues = page.evaluate(LAYOUT_CHECK_JS)
            all_issues.extend({"viewport": name, **issue} for issue in issues)
            if path == "/":
                matrix_check = page.evaluate(MATRIX_CHECK_JS)
                matrix_checks.append({"viewport": name, **matrix_check})
                if not matrix_check.get("ok"):
                    all_issues.append({"viewport": name, "type": "matrix-structure", **matrix_check})
            page.close()
        browser.close()

    report = {
        "screenshots": [str((OUT_DIR / f"{name}.png").relative_to(ROOT)) for name, *_ in VIEWPORTS],
        "matrix_checks": matrix_checks,
        "issue_count": len(all_issues),
        "issues": all_issues[:200],
    }
    report_path = OUT_DIR / "layout-check.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if all_issues else 0


MATRIX_CHECK_JS = r"""
() => {
  const grid = document.querySelector(".matrix-grid");
  if (!grid) return { ok: false, reason: "matrix-grid missing" };
  const headerLabels = Array.from(grid.querySelectorAll(".matrix-head strong"))
    .map((el) => String(el.textContent || "").trim());
  const templateColumns = getComputedStyle(grid).gridTemplateColumns
    .split(/\s+/)
    .filter(Boolean);
  const cellCount = grid.querySelectorAll(".matrix-cell").length;
  const requiredLabels = ["行为基线", "语义复核"];
  const visibleRequiredLabels = requiredLabels.every((label) => {
    const element = Array.from(grid.querySelectorAll(".matrix-head strong"))
      .find((el) => String(el.textContent || "").trim() === label);
    if (!element) return false;
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  });
  let learnedMapsToBehavioral = false;
  if (typeof renderDefenseMatrix === "function") {
    const probe = document.createElement("div");
    probe.innerHTML = renderDefenseMatrix([{ layer: "Foundation", finding_type: "learned" }]);
    const behavioralCell = probe.querySelector(".matrix-cell.behavioral.active strong");
    learnedMapsToBehavioral = String(behavioralCell?.textContent || "").trim() === "1";
  }
  return {
    ok: templateColumns.length === 5 && cellCount % 5 === 0 && visibleRequiredLabels && learnedMapsToBehavioral,
    columnCount: templateColumns.length,
    cellCount,
    headerLabels,
    visibleRequiredLabels,
    learnedMapsToBehavioral
  };
}
"""


def wait_for_server(timeout: float = 45.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(f"{BASE_URL}/api/health", timeout=2) as response:
                if response.status < 500:
                    return
        except (OSError, URLError) as exc:
            last_error = exc
        time.sleep(1)
    raise RuntimeError(f"AgentSentry server did not become ready at {BASE_URL}: {last_error}")


LAYOUT_CHECK_JS = r"""
() => {
  const issues = [];
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const visible = Array.from(document.querySelectorAll("body *")).filter((el) => {
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) return false;
    const rect = visibleRect(el);
    return rect.width > 2 && rect.height > 2;
  });
  const selectorOf = (el) => {
    if (el.id) return `#${el.id}`;
    const cls = String(el.className || "").trim().split(/\s+/).filter(Boolean).slice(0, 3).join(".");
    return `${el.tagName.toLowerCase()}${cls ? "." + cls : ""}`;
  };
  for (const el of visible) {
    const rect = clipToAncestors(el);
    const viewportRect = visibleRect(el);
    const style = getComputedStyle(el);
    const selector = selectorOf(el);
    if (rect.right > vw + 2 || rect.left < -2) {
      issues.push({ type: "viewport-x-overflow", selector, rect: roundRect(rect), text: textPreview(el) });
    }
    if (rect.bottom > vh + 2 && style.position === "fixed") {
      issues.push({ type: "fixed-y-overflow", selector, rect: roundRect(rect), text: textPreview(el) });
    }
    if (el.scrollWidth > el.clientWidth + 3 && style.overflowX === "visible" && viewportRect.width > 3) {
      issues.push({ type: "content-x-overflow", selector, rect: roundRect(viewportRect), scrollWidth: el.scrollWidth, clientWidth: el.clientWidth, text: textPreview(el) });
    }
    if (el.scrollHeight > el.clientHeight + 8 && style.overflowY === "visible" && viewportRect.height > 8) {
      issues.push({ type: "content-y-overflow", selector, rect: roundRect(viewportRect), scrollHeight: el.scrollHeight, clientHeight: el.clientHeight, text: textPreview(el) });
    }
  }

  const important = visible.filter((el) => {
    const selector = selectorOf(el);
    return /panel|kpi|alert|three-label|mesh-meta-line|header|topbar|event|mini-card|stage|rule/.test(selector);
  });
  for (let i = 0; i < important.length; i += 1) {
    const a = important[i];
    const ar = visibleRect(a);
    if (ar.width < 12 || ar.height < 12) continue;
    for (let j = i + 1; j < important.length; j += 1) {
      const b = important[j];
      if (a.contains(b) || b.contains(a)) continue;
      const br = visibleRect(b);
      if (br.width < 12 || br.height < 12) continue;
      const x = Math.max(0, Math.min(ar.right, br.right) - Math.max(ar.left, br.left));
      const y = Math.max(0, Math.min(ar.bottom, br.bottom) - Math.max(ar.top, br.top));
      const area = x * y;
      const minArea = Math.min(ar.width * ar.height, br.width * br.height);
      if (area > 120 && area / minArea > 0.18) {
        issues.push({ type: "sibling-overlap", a: selectorOf(a), b: selectorOf(b), overlap: Math.round(area), aText: textPreview(a), bText: textPreview(b) });
      }
    }
  }
  return issues.slice(0, 80);

  function clipToAncestors(el) {
    let rect = rectObj(el.getBoundingClientRect());
    let parent = el.parentElement;
    while (parent && parent !== document.body) {
      const style = getComputedStyle(parent);
      if (clips(style.overflowX) || clips(style.overflowY)) {
        rect = intersect(rect, rectObj(parent.getBoundingClientRect()));
      }
      parent = parent.parentElement;
    }
    return rect;
  }
  function visibleRect(el) {
    return intersect(clipToAncestors(el), { left: 0, top: 0, right: vw, bottom: vh, width: vw, height: vh, x: 0, y: 0 });
  }
  function clips(value) {
    return value === "hidden" || value === "clip" || value === "auto" || value === "scroll";
  }
  function rectObj(rect) {
    return { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom, width: rect.width, height: rect.height, x: rect.x, y: rect.y };
  }
  function intersect(a, b) {
    const left = Math.max(a.left, b.left);
    const top = Math.max(a.top, b.top);
    const right = Math.min(a.right, b.right);
    const bottom = Math.min(a.bottom, b.bottom);
    return {
      left,
      top,
      right,
      bottom,
      x: left,
      y: top,
      width: Math.max(0, right - left),
      height: Math.max(0, bottom - top)
    };
  }
  function roundRect(rect) {
    return {
      x: Math.round(rect.x),
      y: Math.round(rect.y),
      width: Math.round(rect.width),
      height: Math.round(rect.height),
      right: Math.round(rect.right),
      bottom: Math.round(rect.bottom)
    };
  }
  function textPreview(el) {
    return String(el.innerText || el.textContent || "").replace(/\s+/g, " ").trim().slice(0, 100);
  }
}
"""


if __name__ == "__main__":
    sys.exit(main())
