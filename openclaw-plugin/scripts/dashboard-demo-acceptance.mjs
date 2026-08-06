import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { chromium } from "playwright-core";

const accessUrl = process.env.AGENTSENTRY_DASHBOARD_ACCESS_URL || "";
const outputDir = resolve(process.env.AGENTSENTRY_DEMO_OUTPUT_DIR || ".tmp/dashboard-demo");
const executablePath = process.env.AGENTSENTRY_BROWSER_EXECUTABLE || "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
assert(accessUrl, "AGENTSENTRY_DASHBOARD_ACCESS_URL is required");

mkdirSync(outputDir, { recursive: true });
const parsed = new URL(accessUrl);
const baseUrl = parsed.origin;
const browser = await chromium.launch({ executablePath, headless: true });

try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();

  const bare = await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });
  assert.equal(bare?.status(), 401, "fresh browser must not open the bare dashboard URL");
  assert.equal((await context.cookies()).length, 0, "fresh browser unexpectedly had dashboard cookies");

  const bootstrap = await page.goto(accessUrl, { waitUntil: "networkidle" });
  assert.equal(bootstrap?.status(), 200, "dashboard bootstrap did not reach the authenticated page");
  assert.equal(page.url(), `${baseUrl}/`, "bootstrap token was not removed from the browser URL");
  assert(!page.url().includes("access_token"), "dashboard token remains visible in the address bar");
  const authenticatedDashboardUrl = page.url();
  const cookies = await context.cookies();
  const session = cookies.find((item) => item.name === "agentsentry_session");
  assert(session?.httpOnly, "dashboard session cookie is not HttpOnly");
  assert.equal(session?.sameSite, "Strict", "dashboard session cookie must use SameSite=Strict");
  const resetStatus = await page.evaluate(async () => (await fetch("/api/reset", { method: "POST" })).status);
  assert.equal(resetStatus, 200, "could not reset the isolated demo records");
  await page.reload({ waitUntil: "networkidle" });
  await page.screenshot({ path: resolve(outputDir, "01-authenticated-dashboard.png"), fullPage: true });

  await page.goto(`${baseUrl}/command-lab`, { waitUntil: "networkidle" });
  await page.locator("#connectionState").filter({ hasText: "已连接" }).waitFor({ state: "visible", timeout: 15_000 });
  await page.locator("#markOnlyBtn").click();
  await page.locator("#commandState").filter({ hasText: "已阻断" }).waitFor({ state: "visible", timeout: 15_000 });
  const commandState = (await page.locator("#commandState").innerText()).trim();
  const flowSummary = (await page.locator("#flowDecisionSummary").innerText()).trim();
  assert.match(commandState, /已阻断/);
  assert.match(flowSummary, /阻断|拒绝/);
  await page.screenshot({ path: resolve(outputDir, "02-attack-blocked.png"), fullPage: true });

  const records = await page.evaluate(async () => {
    const response = await fetch("/api/records?limit=200");
    return await response.json();
  });
  const decisions = Array.isArray(records.records)
    ? records.records.filter((item) => item?.type === "tool_decision").map((item) => item?.payload?.decision)
    : [];
  assert(decisions.includes("deny"), "attack demo produced no deny tool decision");

  const evidence = {
    fresh_bare_status: bare?.status(),
    bootstrap_final_url: authenticatedDashboardUrl,
    token_removed_from_url: !authenticatedDashboardUrl.includes("access_token"),
    session_cookie: { httpOnly: session.httpOnly, sameSite: session.sameSite, secure: session.secure },
    command_state: commandState,
    flow_summary: flowSummary,
    decisions,
  };
  writeFileSync(resolve(outputDir, "acceptance.json"), `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  console.log(JSON.stringify(evidence));
} finally {
  await browser.close();
}
