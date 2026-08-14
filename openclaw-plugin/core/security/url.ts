export function targetAllowed(target: string, allowedTargets: string[]): boolean {
  if (!allowedTargets.length) return false;
  return allowedTargets.some((allowed) => targetMatches(target, allowed));
}

export function targetMatches(target: string, allowed: string): boolean {
  const rule = parseTargetRule(allowed);
  if (!rule || !target.trim()) return false;
  const targetUrl = normalizedUrl(target);
  const allowedUrl = normalizedUrl(rule.value);
  if (!targetUrl || !allowedUrl) return rule.kind === "exact" && target.trim() === rule.value;
  if (rule.kind === "exact" || targetUrl.protocol === "mock:") {
    return comparableUrl(targetUrl) === comparableUrl(allowedUrl);
  }
  if (targetUrl.origin !== allowedUrl.origin || allowedUrl.search || allowedUrl.hash) return false;
  const allowedPath = normalizedPathname(allowedUrl.pathname);
  const targetPath = normalizedPathname(targetUrl.pathname);
  return allowedPath === "/" || targetPath === allowedPath || targetPath.startsWith(`${allowedPath}/`);
}

export function hostFromUrl(value: string): string {
  try {
    return normalizedUrl(value)?.hostname.toLowerCase() || "";
  } catch {
    return "";
  }
}

export function originFromUrl(value: string): string {
  try {
    return new URL(value).origin.toLowerCase();
  } catch {
    return "";
  }
}

export function isLocalHost(host: string): boolean {
  const normalized = host.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1" || normalized.endsWith(".localhost");
}

export function extractUrlTargets(text: string): string[] {
  const matches = text.match(/\b(?:https?:\/\/\S+|mock:\/\/\S+)/g) || [];
  return matches.map((value) => value.replace(/[.,;:\])}>'"，。；：）】》”]+$/g, "")).filter(Boolean);
}

function parseTargetRule(value: string): { kind: "exact" | "prefix"; value: string } | null {
  const text = value.trim();
  if (!text) return null;
  if (text.startsWith("prefix:")) return { kind: "prefix", value: text.slice("prefix:".length).trim() };
  if (text.startsWith("exact:")) return { kind: "exact", value: text.slice("exact:".length).trim() };
  return { kind: "exact", value: text };
}

function normalizedUrl(value: string): URL | null {
  try {
    const text = value.trim();
    const candidate = /^[a-z0-9.-]+\.[a-z]{2,}(?:[/:?#]|$)/i.test(text) ? `https://${text}` : text;
    const parsed = new URL(candidate);
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    return parsed;
  } catch {
    return null;
  }
}

function comparableUrl(url: URL): string {
  const copy = new URL(url.toString());
  copy.hash = "";
  return copy.toString();
}

function normalizedPathname(pathname: string): string {
  return pathname.replace(/\/$/, "") || "/";
}
