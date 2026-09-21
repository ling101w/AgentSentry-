import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";

export type SafeHttpResponse = {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
  bytes: number;
  truncated: boolean;
  finalUrl: string;
  redirects: number;
};

export type SafeHttpOptions = {
  allowedHosts?: string[];
  maxBytes?: number;
  maxRedirects?: number;
  timeoutMs?: number;
};

type ResolvedAddress = { address: string; family: 4 | 6 };

const DEFAULT_MAX_BYTES = 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_TIMEOUT_MS = 5000;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export async function safeHttpGet(input: URL | string, options: SafeHttpOptions = {}): Promise<SafeHttpResponse> {
  const maxBytes = positiveInt(options.maxBytes, DEFAULT_MAX_BYTES);
  const maxRedirects = positiveInt(options.maxRedirects, DEFAULT_MAX_REDIRECTS);
  const timeoutMs = positiveInt(options.timeoutMs, DEFAULT_TIMEOUT_MS);
  const deadline = Date.now() + timeoutMs;
  let current = typeof input === "string" ? new URL(input) : new URL(input.toString());

  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    const allowedHosts = options.allowedHosts || [];
    validateHttpUrl(current, allowedHosts);
    const resolved = await resolvePublicAddress(current.hostname, isHostAllowlisted(current, allowedHosts));
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) throw new Error("HTTP request timed out");
    const response = await requestPinned(current, resolved, maxBytes, remainingMs);
    const location = firstHeader(response.headers.location);
    if (!REDIRECT_STATUSES.has(response.status) || !location) {
      return { ...response, finalUrl: current.toString(), redirects };
    }
    if (redirects === maxRedirects) throw new Error(`HTTP redirect limit exceeded (${maxRedirects})`);
    current = new URL(location, current);
  }
  throw new Error("HTTP redirect limit exceeded");
}

export async function safeHttpPost(input: URL | string, body: unknown, options: SafeHttpOptions = {}): Promise<SafeHttpResponse> {
  const maxBytes = positiveInt(options.maxBytes, DEFAULT_MAX_BYTES);
  const timeoutMs = positiveInt(options.timeoutMs, DEFAULT_TIMEOUT_MS);
  const url = typeof input === "string" ? new URL(input) : new URL(input.toString());
  const allowedHosts = options.allowedHosts || [];
  validateHttpUrl(url, allowedHosts);
  const resolved = await resolvePublicAddress(url.hostname, isHostAllowlisted(url, allowedHosts));
  const requestBody = typeof body === "string" ? body : JSON.stringify(body);
  const response = await requestPinned(url, resolved, maxBytes, timeoutMs, "POST", requestBody);
  return { ...response, finalUrl: url.toString(), redirects: 0 };
}

export function isForbiddenIpAddress(address: string): boolean {
  const family = isIP(stripIpv6Brackets(address));
  if (family === 4) return forbiddenIpv4(stripIpv6Brackets(address));
  if (family !== 6) return true;
  const bytes = ipv6Bytes(stripIpv6Brackets(address));
  if (!bytes) return true;
  if (bytes.every((value) => value === 0)) return true;
  if (bytes.slice(0, 15).every((value) => value === 0) && bytes[15] === 1) return true;
  if ((bytes[0] & 0xfe) === 0xfc) return true;
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true;
  if (bytes[0] === 0xff) return true;
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x0d && bytes[3] === 0xb8) return true;

  const mappedV4 = bytes.slice(0, 10).every((value) => value === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  const compatibleV4 = bytes.slice(0, 12).every((value) => value === 0);
  const nat64V4 = bytes.slice(0, 12).every((value, index) => value === [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0][index]);
  if (mappedV4 || compatibleV4 || nat64V4) return forbiddenIpv4(bytes.slice(12).join("."));
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return forbiddenIpv4(`${bytes[2]}.${bytes[3]}.${bytes[4]}.${bytes[5]}`);
  return false;
}

async function resolvePublicAddress(hostname: string, allowPrivate = false): Promise<ResolvedAddress> {
  const host = stripIpv6Brackets(hostname);
  const literalFamily = isIP(host);
  const results = literalFamily
    ? [{ address: host, family: literalFamily }]
    : await dnsLookup(host, { all: true, verbatim: true });
  if (!results.length) throw new Error(`DNS returned no addresses for ${host}`);
  const forbidden = allowPrivate ? null : results.find((item) => isForbiddenIpAddress(item.address));
  if (forbidden) throw new Error(`SSRF protection blocked non-public address ${forbidden.address} for ${host}`);
  const selected = results[0];
  if (selected.family !== 4 && selected.family !== 6) throw new Error(`unsupported address family for ${host}`);
  return { address: selected.address, family: selected.family };
}

export function validateHttpUrl(url: URL, allowedHosts: string[]): void {
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error(`unsupported URL protocol ${url.protocol}`);
  if (url.username || url.password) throw new Error("URLs containing credentials are not allowed");
  if (!url.hostname) throw new Error("URL hostname is required");
  if (allowedHosts.length) {
    const hostname = stripIpv6Brackets(url.hostname).toLowerCase();
    if (!isHostAllowlisted(url, allowedHosts)) throw new Error(`HTTP host ${hostname} is not allowlisted`);
  }
}

function isHostAllowlisted(url: URL, allowedHosts: string[]): boolean {
  if (!allowedHosts.length) return false;
  const hostname = stripIpv6Brackets(url.hostname).toLowerCase();
  return allowedHosts.some((item) => normalizeAllowedHost(item) === hostname);
}

function requestPinned(
  url: URL,
  resolved: ResolvedAddress,
  maxBytes: number,
  timeoutMs: number,
  method: "GET" | "POST" = "GET",
  requestBody = "",
): Promise<Omit<SafeHttpResponse, "finalUrl" | "redirects">> {
  return new Promise((resolve, reject) => {
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)({
      protocol: url.protocol,
      hostname: resolved.address,
      family: resolved.family,
      port: url.port ? Number(url.port) : undefined,
      path: `${url.pathname}${url.search}`,
      method,
      headers: {
        Accept: "application/json, text/plain;q=0.9, */*;q=0.8",
        Host: url.host,
        "User-Agent": "AgentSentry-BusinessTool/1.0",
        ...(method === "POST" ? {
          "Content-Type": "application/json; charset=utf-8",
          "Content-Length": String(Buffer.byteLength(requestBody)),
        } : {}),
      },
      servername: isIP(stripIpv6Brackets(url.hostname)) ? undefined : stripIpv6Brackets(url.hostname),
    }, (response) => {
      const status = response.statusCode || 0;
      const declaredLength = Number(firstHeader(response.headers["content-length"]) || "0");
      if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
        response.destroy();
        resolve({ status, headers: response.headers, body: "", bytes: 0, truncated: true });
        return;
      }

      const chunks: Buffer[] = [];
      let bytes = 0;
      let settled = false;
      const finish = (truncated: boolean) => {
        if (settled) return;
        settled = true;
        resolve({ status, headers: response.headers, body: Buffer.concat(chunks).toString("utf8"), bytes, truncated });
      };
      response.on("data", (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const remaining = maxBytes - bytes;
        if (remaining > 0) chunks.push(buffer.subarray(0, remaining));
        bytes += Math.min(buffer.length, Math.max(remaining, 0));
        if (buffer.length > remaining) {
          finish(true);
          response.destroy();
        }
      });
      response.on("end", () => finish(false));
      response.on("error", (error) => {
        if (!settled) reject(error);
      });
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("HTTP request timed out")));
    request.on("error", reject);
    if (method === "POST" && requestBody) request.write(requestBody);
    request.end();
  });
}

function forbiddenIpv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return true;
  const [a, b, c] = octets;
  return a === 0
    || a === 10
    || a === 127
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 0 && c === 0)
    || (a === 192 && b === 0 && c === 2)
    || (a === 192 && b === 168)
    || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113)
    || a >= 224;
}

function ipv6Bytes(address: string): number[] | null {
  const withoutZone = address.split("%")[0].toLowerCase();
  if ((withoutZone.match(/::/g) || []).length > 1) return null;
  const [leftText, rightText = ""] = withoutZone.split("::");
  const left = parseIpv6Parts(leftText);
  const right = parseIpv6Parts(rightText);
  if (!left || !right) return null;
  const omitted = 8 - left.length - right.length;
  if ((withoutZone.includes("::") && omitted < 1) || (!withoutZone.includes("::") && omitted !== 0)) return null;
  const parts = [...left, ...Array(Math.max(0, omitted)).fill(0), ...right];
  if (parts.length !== 8) return null;
  return parts.flatMap((part) => [(part >> 8) & 0xff, part & 0xff]);
}

function parseIpv6Parts(text: string): number[] | null {
  if (!text) return [];
  const raw = text.split(":");
  const parts: number[] = [];
  for (const item of raw) {
    if (item.includes(".")) {
      const octets = item.split(".").map(Number);
      if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return null;
      parts.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
      continue;
    }
    if (!/^[a-f0-9]{1,4}$/.test(item)) return null;
    parts.push(Number.parseInt(item, 16));
  }
  return parts;
}

function normalizeAllowedHost(value: string): string {
  const text = value.trim();
  if (!text) return "";
  try {
    return stripIpv6Brackets(new URL(text).hostname).toLowerCase();
  } catch {
    return stripIpv6Brackets(text).toLowerCase();
  }
}

function stripIpv6Brackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function firstHeader(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value[0] || "" : value || "";
}

function positiveInt(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.trunc(value) : fallback;
}
