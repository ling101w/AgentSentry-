import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync, statSync, symlinkSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PluginConfig } from "../dist/config.js";
import { memoryGuardScanRead, memoryGuardScanWrite } from "../dist/core/memory-guard.js";
import { matchAllowedWritePath, pathInsideCanonicalRoot } from "../dist/core/path-security.js";
import { RecordStore } from "../dist/core/records.js";
import { isForbiddenIpAddress, safeHttpGet } from "../dist/core/ssrf-http.js";
import { stateSecretPath } from "../dist/core/state-secret.js";
import { targetMatches } from "../dist/core/policy.js";
import { startDashboard } from "../dist/server/dashboard.js";

const testDir = join(tmpdir(), `agentsentry-security-${process.pid}-${Date.now()}`);
let dashboard;

try {
  mkdirSync(testDir, { recursive: true });
  testTargetRules();
  testPathBoundaries();
  testMemoryGuardSecret();
  await testSsrfAddressChecks();
  await testEventWriter();
  dashboard = await testDashboardBoundary();
} finally {
  if (dashboard) await dashboard.close();
  rmSync(testDir, { recursive: true, force: true });
}

console.log("AgentSentry security smoke passed.");

function testTargetRules() {
  assert.equal(targetMatches("http://127.0.0.1:8765/foo", "http://127.0.0.1:8765/foo"), true);
  assert.equal(targetMatches("http://127.0.0.1:9999/foo", "http://127.0.0.1:8765/foo"), false);
  assert.equal(targetMatches("http://example.com:80/foo", "http://example.com/foo"), true);
  assert.equal(targetMatches("https://example.com/foo/", "https://example.com/foo"), false);
  assert.equal(targetMatches("https://example.com/foo/bar", "https://example.com/foo"), false);
  assert.equal(targetMatches("https://example.com/foo/bar", "prefix:https://example.com/foo"), true);
  assert.equal(targetMatches("https://example.com:444/foo/bar", "prefix:https://example.com/foo"), false);
  assert.equal(targetMatches("https://example.com/foo?scope=write", "https://example.com/foo?scope=read"), false);
}

function testPathBoundaries() {
  const root = join(testDir, "allowed-root");
  const outside = join(testDir, "outside-root");
  mkdirSync(root, { recursive: true });
  mkdirSync(outside, { recursive: true });

  assert.equal(matchAllowedWritePath(join(root, "new", "file.txt"), [root]).allowed, true);
  assert.equal(matchAllowedWritePath(join(root, "..", "outside-root", "file.txt"), [root]).allowed, false);
  assert.equal(matchAllowedWritePath(join(testDir, "allowed-root-sibling", "file.txt"), [root]).allowed, false);
  assert.equal(matchAllowedWritePath(join(root, "file.txt"), ["relative-root"]).allowed, false);

  const link = join(root, "outside-link");
  symlinkSync(outside, link, process.platform === "win32" ? "junction" : "dir");
  assert.equal(matchAllowedWritePath(join(link, "escaped.txt"), [root]).allowed, false);

  assert.equal(pathInsideCanonicalRoot(String.raw`C:\safe\root\file.txt`, String.raw`C:\safe\root`, "win32"), true);
  assert.equal(pathInsideCanonicalRoot(String.raw`C:\safe\rooted\file.txt`, String.raw`C:\safe\root`, "win32"), false);
  assert.equal(pathInsideCanonicalRoot(String.raw`\\server\share\root\file.txt`, String.raw`\\server\share\root`, "win32"), true);
  assert.equal(pathInsideCanonicalRoot(String.raw`\\server\other\root\file.txt`, String.raw`\\server\share\root`, "win32"), false);
}

function testMemoryGuardSecret() {
  const config = new PluginConfig();
  config.storage.stateDir = join(testDir, "memory-state");
  process.env.AGENTSENTRY_API_KEY = "api-key-must-not-sign-memory";
  const written = memoryGuardScanWrite({
    key: "report_language",
    content: "Use Chinese for report summaries.",
    context: "The user requested a report-language preference.",
    sourceClass: "user_directive",
    config,
  });
  const secretPath = stateSecretPath(config, "memory-guard");
  const encodedSecret = readFileSync(secretPath, "utf8").trim();
  assert.match(encodedSecret, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(encodedSecret, process.env.AGENTSENTRY_API_KEY);
  if (process.platform !== "win32") assert.equal(statSync(secretPath).mode & 0o777, 0o600);

  process.env.AGENTSENTRY_API_KEY = "changed-api-key";
  const envelope = { updated_at: written.passport.updated_at, value: written.sanitizedContent, passport: written.passport };
  assert.equal(memoryGuardScanRead({ key: "report_language", envelope, context: "read", config }).integrity_ok, true);
  const tampered = {
    ...envelope,
    passport: { ...envelope.passport, signature: `${envelope.passport.signature[0] === "0" ? "1" : "0"}${envelope.passport.signature.slice(1)}` },
  };
  assert.equal(memoryGuardScanRead({ key: "report_language", envelope: tampered, context: "read", config }).integrity_ok, false);
  delete process.env.AGENTSENTRY_API_KEY;
}

async function testSsrfAddressChecks() {
  for (const address of ["127.0.0.1", "10.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1"]) {
    assert.equal(isForbiddenIpAddress(address), true, address);
  }
  assert.equal(isForbiddenIpAddress("8.8.8.8"), false);
  assert.equal(isForbiddenIpAddress("2606:4700:4700::1111"), false);
  await assert.rejects(() => safeHttpGet("http://169.254.169.254/latest/meta-data/"), /SSRF protection blocked/);
  await assert.rejects(() => safeHttpGet("http://127.0.0.1/", { allowedHosts: ["127.0.0.1"] }), /SSRF protection blocked/);
  await assert.rejects(() => safeHttpGet("https://example.com/", { allowedHosts: ["api.example.com"] }), /not allowlisted/);
}

async function testDashboardBoundary() {
  const remoteDenied = new PluginConfig();
  remoteDenied.dashboard.host = "0.0.0.0";
  assert.throws(() => startDashboard(remoteDenied, {}, { info() {} }), /allowRemote/);
  remoteDenied.dashboard.allowRemote = true;
  assert.throws(() => startDashboard(remoteDenied, {}, { info() {} }), /authToken/);

  const config = new PluginConfig();
  config.storage.stateDir = join(testDir, "dashboard-state");
  config.dashboard.port = 0;
  const store = new RecordStore(config);
  const server = await startDashboard(config, store, { info() {} });
  const access = new URL(server.accessUrl);
  const token = access.searchParams.get("access_token");
  assert(token && token.length >= 32);
  assert.equal(statSync(stateSecretPath(config, "dashboard-session")).isFile(), true);

  assert.equal((await request(server.url)).status, 401);
  assert.equal((await request(`${server.url}/api/health`, { headers: { Authorization: `Bearer ${token}` } })).status, 200);
  assert.equal((await request(`${server.url}/api/health`, { headers: { Authorization: `Bearer ${token}`, Host: `evil.example:${access.port}` } })).status, 421);

  const bootstrap = await request(server.accessUrl);
  assert.equal(bootstrap.status, 303);
  const cookie = String(bootstrap.headers["set-cookie"]?.[0] || "").split(";")[0];
  assert(cookie.startsWith("agentsentry_session="));
  assert.equal((await request(`${server.url}/api/health`, { headers: { Cookie: cookie } })).status, 200);
  assert.equal((await request(`${server.url}/api/reset`, { method: "POST", headers: { Cookie: cookie, Origin: "http://evil.example" } })).status, 403);
  assert.equal((await request(`${server.url}/api/reset`, { method: "POST", headers: { Authorization: `Bearer ${token}` } })).status, 200);
  await store.close();
  return server;
}

async function testEventWriter() {
  const config = new PluginConfig();
  config.storage.stateDir = join(testDir, "writer-state");
  const store = new RecordStore(config);
  const record = store.add({
    run_id: "run_writer",
    session_key: "session_writer",
    type: "test",
    layer: "Evidence Feedback",
    severity: "warning",
    title: "queued event",
    summary: "writer test",
    payload: {},
  });
  assert.equal(store.get(record.id)?.id, record.id);
  assert.equal(store.list(1)[0]?.id, record.id);
  assert.equal(store.count(), 1);
  assert(!readFileSync(store.recordsPath, "utf8").includes(record.id));
  await store.flush();
  assert(readFileSync(store.recordsPath, "utf8").includes(record.id));
  await store.close();
}

function request(url, options = {}) {
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: parsed.hostname,
      port: parsed.port,
      path: `${parsed.pathname}${parsed.search}`,
      method: options.method || "GET",
      headers: options.headers || {},
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}
