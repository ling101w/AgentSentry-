import { createReadStream, existsSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import type { PluginConfig } from "../config.ts";
import type { AgentSentryRecord, RecordStore } from "../core/records.ts";

export type DashboardServer = {
  url: string;
  close: () => Promise<void>;
};

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
};

export function startDashboard(config: PluginConfig, store: RecordStore, logger: LoggerLike): Promise<DashboardServer> {
  const publicDir = join(fileURLToPath(new URL(".", import.meta.url)), "..", "public");
  const host = config.dashboard.host;
  const port = config.dashboard.port;

  const server = createServer((req, res) => {
    void handleRequest(req, res, publicDir, store);
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      const address = server.address();
      const actualPort = typeof address === "object" && address ? address.port : port;
      const url = `http://${host}:${actualPort}`;
      logger.info(`[AgentSentry] dashboard listening at ${url}`);
      resolve({
        url,
        close: () => closeServer(server),
      });
    });
  });
}

async function handleRequest(req: IncomingMessage, res: ServerResponse, publicDir: string, store: RecordStore): Promise<void> {
  const url = new URL(req.url || "/", "http://agentsentry.local");

  if (req.method === "GET" && url.pathname === "/api/health") {
    sendJson(res, { ok: true, recordsPath: store.recordsPath, capabilities: ["lab_command"] });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/records") {
    const limit = clampInt(url.searchParams.get("limit"), 1, 5000, 500);
    sendJson(res, { records: store.list(limit) });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/stats") {
    sendJson(res, store.stats());
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/lab/command") {
    try {
      const body = await readJsonBody(req, 32768);
      const command = String(body.command || "").trim();
      if (!command) {
        sendJson(res, { ok: false, error: "command is required" }, 400);
        return;
      }
      const clientId = String(body.clientId || "browser").replace(/[^\w:.-]/g, "_").slice(0, 80);
      const scenario = String(body.scenario || "manual").slice(0, 80);
      const copied = Boolean(body.copied);
      const record = store.add({
        run_id: `lab_${Date.now().toString(36)}`,
        session_key: `lab:${clientId}`,
        type: "lab_command",
        layer: "Runtime",
        severity: "info",
        title: "OpenClaw lab command",
        summary: command.slice(0, 240),
        payload: {
          command,
          scenario,
          copied,
          source: "command-lab",
        },
      });
      sendJson(res, { ok: true, record });
    } catch (error) {
      sendJson(res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/export") {
    const limit = clampInt(url.searchParams.get("limit"), 1, 50000, 5000);
    const format = (url.searchParams.get("format") || "json").toLowerCase();
    const records = store.list(limit);
    if (format === "csv") {
      sendDownload(res, "text/csv; charset=utf-8", `agentsentry-records-${dateStamp()}.csv`, recordsToCsv(records));
      return;
    }
    sendDownload(
      res,
      "application/json; charset=utf-8",
      `agentsentry-records-${dateStamp()}.json`,
      JSON.stringify({ exported_at: new Date().toISOString(), count: records.length, records }, null, 2),
    );
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/reset") {
    store.reset();
    sendJson(res, { ok: true });
    return;
  }

  if (req.method !== "GET") {
    sendText(res, 405, "Method not allowed");
    return;
  }

  const requested = url.pathname === "/"
    ? "/index.html"
    : url.pathname === "/screen" || url.pathname === "/security-screen"
      ? "/security-screen.html"
      : url.pathname === "/lab" || url.pathname === "/command-lab"
        ? "/command-lab.html"
        : url.pathname;
  const filePath = normalize(join(publicDir, requested));
  if (!filePath.startsWith(normalize(publicDir)) || !existsSync(filePath)) {
    sendText(res, 404, "Not found");
    return;
  }

  res.writeHead(200, { "Content-Type": MIME_TYPES[extname(filePath)] || "application/octet-stream" });
  createReadStream(filePath).pipe(res);
}

function sendJson(res: ServerResponse, body: unknown, status = 200): void {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(body));
}

function readJsonBody(req: IncomingMessage, maxBytes: number): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("error", reject);
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8").trim();
      if (!text) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(text) as Record<string, unknown>);
      } catch {
        reject(new Error("invalid JSON body"));
      }
    });
  });
}

function sendDownload(res: ServerResponse, contentType: string, filename: string, body: string): void {
  res.writeHead(200, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Content-Disposition": `attachment; filename="${filename}"`,
  });
  res.end(body);
}

function sendText(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(body);
}

function clampInt(value: string | null, min: number, max: number, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function recordsToCsv(records: AgentSentryRecord[]): string {
  const headers = ["id", "created_at", "severity", "type", "layer", "title", "summary", "run_id", "session_key", "payload"];
  const rows = records.map((record) => [
    record.id,
    record.created_at,
    record.severity,
    record.type,
    record.layer,
    record.title,
    record.summary,
    record.run_id,
    record.session_key,
    JSON.stringify(record.payload),
  ]);
  return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n") + "\n";
}

function csvCell(value: unknown): string {
  const text = String(value ?? "");
  return `"${text.replace(/"/g, '""')}"`;
}

function dateStamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

type LoggerLike = {
  info: (message: string) => void;
};
