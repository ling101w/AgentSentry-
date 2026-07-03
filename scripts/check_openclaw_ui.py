from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "reports" / "ui-screenshots-8765"
BASE_URL = "http://127.0.0.1:8765"
KEEP_SCREENSHOTS = os.environ.get("AGENTSENTRY_KEEP_SCREENSHOTS") == "1"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    wait_for_server()
    report: dict[str, object] = {"checks": [], "layout_issues": [], "screenshots": []}

    lab = post_json(
        "/api/lab/command",
        {
            "command": "请阅读这封客户邮件，整理项目风险、预算变化和交付日期。",
            "scenario": "external_email_hidden",
            "clientId": "openclaw-ui-check",
            "resetSession": True,
        },
    )
    decisions = lab.get("decisions") if isinstance(lab.get("decisions"), list) else []
    command_id = (lab.get("record") or {}).get("id")
    add_check(
        report,
        "lab_policy_enforcement",
        bool(lab.get("ok")) and any(item.get("decision") == "deny" for item in decisions if isinstance(item, dict)),
        {"record": (lab.get("record") or {}).get("id"), "decisions": decisions},
    )

    recent_records = get_json("/api/records?limit=200").get("records", [])
    command_records = [
        item for item in recent_records
        if isinstance(item, dict)
        and (
            item.get("id") == command_id
            or ((item.get("payload") or {}) if isinstance(item.get("payload"), dict) else {}).get("command_id") == command_id
        )
    ]
    add_check(
        report,
        "lab_records_materialized",
        bool(command_id)
        and any(item.get("type") == "tool_decision" for item in command_records)
        and any(item.get("type") in {"tool_result", "alert"} for item in command_records),
        {"command_id": command_id, "types": [item.get("type") for item in command_records]},
    )
    mode_settings = get_json("/api/settings/enforcement")
    add_check(
        report,
        "enforcement_settings_api",
        mode_settings.get("ok") is True
        and mode_settings.get("mode") in {"observe", "approval", "block"}
        and len(mode_settings.get("modes", [])) == 3,
        {
            "mode": mode_settings.get("mode"),
            "modes": [item.get("value") for item in mode_settings.get("modes", []) if isinstance(item, dict)],
        },
    )

    with sync_playwright() as p:
        browser = p.chromium.launch()
        console_errors: list[str] = []

        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.goto(f"{BASE_URL}/", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(900)
        save_screenshot(page, report, "home-1440x900.png")
        add_check(
            report,
            "home_links",
            page.locator('a[href="/security-screen"]').count() >= 1 and page.locator('a[href="/command-lab"]').count() >= 1,
            {"title": page.title()},
        )
        add_check(
            report,
            "home_enforcement_mode_control",
            page.locator("#modeSelect").count() == 1
            and page.locator("#modeStatus").inner_text().startswith("当前：")
            and page.locator("#modeHelpText").inner_text().strip() != "",
            {
                "mode": page.locator("#modeSelect").input_value() if page.locator("#modeSelect").count() else "",
                "status": page.locator("#modeStatus").inner_text() if page.locator("#modeStatus").count() else "",
                "help": page.locator("#modeHelpText").inner_text()[:120] if page.locator("#modeHelpText").count() else "",
            },
        )
        page.close()

        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.goto(f"{BASE_URL}/command-lab", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_selector("#commandInput", timeout=15000)
        page.wait_for_selector("#modeSelect", timeout=15000)
        page.wait_for_timeout(900)
        add_check(
            report,
            "command_lab_enforcement_mode_control",
            page.locator("#modeSelect").count() == 1
            and page.locator("#modeStatus").inner_text().startswith("当前：")
            and page.locator("#modeHelpText").inner_text().strip() != "",
            {
                "mode": page.locator("#modeSelect").input_value(),
                "status": page.locator("#modeStatus").inner_text(),
                "help": page.locator("#modeHelpText").inner_text()[:120],
            },
        )
        page.locator("#commandInput").fill("请阅读这封客户邮件，整理项目风险、预算变化和交付日期。")
        page.locator("#scenarioSelect").select_option("external_email_hidden")
        page.locator("#markOnlyBtn").click()
        page.wait_for_function(
            "() => !['记录中', '标记中'].includes((document.querySelector('#commandState')?.innerText || '').trim())",
            timeout=45000,
        )
        page.wait_for_timeout(900)
        state_text = page.locator("#commandState").inner_text()
        stream_text = page.locator("#streamList").inner_text()
        latest_records = get_json("/api/records?limit=300").get("records", [])
        ui_session_records = [
            item for item in latest_records
            if isinstance(item, dict)
            and str(item.get("session_key", "")).startswith("lab:browser_")
            and item.get("type") in {"lab_command", "tool_decision", "tool_result", "alert"}
        ]
        ui_has_decision = any(item.get("type") == "tool_decision" for item in ui_session_records)
        ui_has_alert = any(item.get("type") == "alert" for item in ui_session_records)
        save_screenshot(page, report, "command-lab-1440x900.png")
        add_check(
            report,
            "command_lab_submit",
            ("阻断" in state_text or "确认" in state_text) and ui_has_decision and ui_has_alert,
            {
                "state": state_text,
                "streamPreview": stream_text[:240],
                "recentSessionTypes": [item.get("type") for item in ui_session_records[:24]],
            },
        )
        report["layout_issues"].extend({"viewport": "command-lab-1440x900", **issue} for issue in page.evaluate(LAYOUT_CHECK_JS))
        page.close()

        for name, width, height in [
            ("screen-1920x1080", 1920, 1080),
            ("screen-1366x768", 1366, 768),
            ("screen-1180x760", 1180, 760),
        ]:
            page = browser.new_page(viewport={"width": width, "height": height}, device_scale_factor=1)
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            page.goto(f"{BASE_URL}/security-screen", wait_until="domcontentloaded", timeout=30000)
            wait_for_kpis(page)
            api = page.evaluate("fetch('/api/security/overview').then((res) => res.json())")
            stats = page.evaluate("fetch('/api/stats?limit=5000').then((res) => res.json())")
            source = api.get("source", {})
            source_mode = source.get("mode") if isinstance(source, dict) else str(source)
            metric_total = next((item.get("num") for item in api.get("metrics", []) if item.get("key") == "total"), None)
            kpi_count = page.locator("#kpiStrip .kpi-num").count()
            first_kpi = int(page.locator("#kpiStrip .kpi-num").first.inner_text().replace(",", "")) if kpi_count else -1
            stats_total = int(stats.get("total", -1))
            metric_total_int = int(metric_total or -2)
            total_delta = max(abs(first_kpi - stats_total), abs(first_kpi - metric_total_int), abs(stats_total - metric_total_int))
            save_screenshot(page, report, f"{name}.png")
            add_check(
                report,
                f"{name}_real_openclaw_data",
                source_mode == "openclaw"
                and kpi_count >= 8
                and total_delta <= 25
                and page.locator("#runtimeMode").inner_text() != "NO API",
                {
                    "runtime": page.locator("#runtimeMode").inner_text(),
                    "kpiCount": kpi_count,
                    "firstKpi": first_kpi,
                    "statsTotal": stats_total,
                    "metricTotal": metric_total,
                    "totalDelta": total_delta,
                    "source": source,
                    "protectionIndex": page.locator("#protectionIndex").inner_text(),
                },
            )
            if name == "screen-1920x1080":
                pause_button = page.locator("#pauseBtn")
                if pause_button.count() > 0 and pause_button.inner_text() == "暂停":
                    pause_button.click()
                    page.wait_for_timeout(400)
                alert_button = page.locator("#openAlertModal")
                alert_button_visible = alert_button.count() > 0 and alert_button.first.is_visible()
                if alert_button_visible:
                    alert_button.first.click(force=True)
                    page.wait_for_selector("#alertModal.open", timeout=8000)
                    page.wait_for_selector("#alertModalBody .modal-alert", timeout=12000)
                    first_page_count = page.locator("#alertModalBody .modal-alert").count()
                    next_button = page.locator('#alertModalBody [data-pagination="alerts"] [data-page]').last
                    has_next = next_button.count() > 0 and next_button.is_enabled()
                    if has_next:
                        next_button.click()
                        page.wait_for_function(
                            "() => /26\\s*-\\s*50\\s*\\//.test(document.querySelector('#alertModalBody')?.innerText || '')",
                            timeout=12000,
                        )
                    second_page_count = page.locator("#alertModalBody .modal-alert").count()
                    modal_text = page.locator("#alertModalBody").inner_text()
                    save_screenshot(page, report, "screen-alert-modal-1920x1080.png")
                    add_check(
                        report,
                        "alert_modal_server_pagination",
                        first_page_count > 0 and second_page_count > 0 and "/" in modal_text,
                        {
                            "firstPageCount": first_page_count,
                            "secondPageCount": second_page_count,
                            "hasNext": has_next,
                            "textPreview": modal_text[:220],
                        },
                    )
                    page.locator("#alertModalClose").click()
                else:
                    add_check(report, "alert_modal_server_pagination", False, {"reason": "openAlertModal button not visible"})
            report["layout_issues"].extend({"viewport": name, **issue} for issue in page.evaluate(LAYOUT_CHECK_JS))
            page.close()

        add_check(report, "browser_console_errors", not console_errors, {"errors": console_errors[:20]})
        browser.close()

    report["issue_count"] = len(report["layout_issues"])
    report_path = OUT_DIR / "browser-functional-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if any(not item["ok"] for item in report["checks"]) or report["layout_issues"] else 0


def save_screenshot(page, report: dict[str, object], filename: str) -> None:
    if not KEEP_SCREENSHOTS:
        return
    screenshot = OUT_DIR / filename
    page.screenshot(path=str(screenshot), full_page=True)
    screenshots = report.get("screenshots")
    if isinstance(screenshots, list):
        screenshots.append(str(screenshot.relative_to(ROOT)))


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
    raise RuntimeError(f"OpenClaw AgentSentry dashboard did not become ready at {BASE_URL}: {last_error}")


def get_json(path: str) -> dict:
    with urlopen(f"{BASE_URL}{path}", timeout=15) as response:
        value = json.loads(response.read().decode("utf-8"))
    return value if isinstance(value, dict) else {}


def post_json(path: str, payload: dict) -> dict:
    req = Request(
        f"{BASE_URL}{path}",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urlopen(req, timeout=15) as response:
        value = json.loads(response.read().decode("utf-8"))
    return value if isinstance(value, dict) else {}


def add_check(report: dict[str, object], name: str, ok: bool, detail: dict) -> None:
    checks = report.setdefault("checks", [])
    assert isinstance(checks, list)
    checks.append({"name": name, "ok": bool(ok), "detail": detail})
    print(f"{name}: {'PASS' if ok else 'FAIL'}")


def wait_for_kpis(page) -> None:
    for attempt in range(2):
        try:
            page.wait_for_function(
                "document.querySelectorAll('#kpiStrip .kpi-num').length >= 8",
                timeout=25000,
            )
            page.wait_for_timeout(2600)
            return
        except Exception:
            if attempt == 0:
                page.reload(wait_until="domcontentloaded", timeout=30000)
                continue
            page.wait_for_timeout(1000)


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

  const important = visible.filter((el) => /panel|kpi|alert|three-label|mesh-meta-line|header|topbar|event|mini-card|stage|rule|gauge|stat-card|flow-node|stream-row/.test(selectorOf(el)));
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

  const gauge = document.querySelector(".gauge");
  const gaugeValue = document.querySelector(".gauge .value");
  if (gauge && gaugeValue) {
    const g = gauge.getBoundingClientRect();
    const v = gaugeValue.getBoundingClientRect();
    if (v.left < g.left - 1 || v.right > g.right + 1 || v.top < g.top - 1 || v.bottom > g.bottom + 1) {
      issues.push({ type: "gauge-value-overflow", rect: roundRect(v), gauge: roundRect(g), text: textPreview(gaugeValue) });
    }
  }
  return issues.slice(0, 120);

  function clipToAncestors(el) {
    let rect = rectObj(el.getBoundingClientRect());
    let parent = el.parentElement;
    while (parent && parent !== document.body) {
      const style = getComputedStyle(parent);
      if (clips(style.overflowX) || clips(style.overflowY)) rect = intersect(rect, rectObj(parent.getBoundingClientRect()));
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
    return { left, top, right, bottom, x: left, y: top, width: Math.max(0, right - left), height: Math.max(0, bottom - top) };
  }
  function roundRect(rect) {
    return { x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height), right: Math.round(rect.right), bottom: Math.round(rect.bottom) };
  }
  function textPreview(el) {
    return String(el.innerText || el.textContent || "").replace(/\s+/g, " ").trim().slice(0, 120);
  }
}
"""


if __name__ == "__main__":
    sys.exit(main())
