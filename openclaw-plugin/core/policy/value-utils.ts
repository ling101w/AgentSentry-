import type { TrustLabel } from "../trust.ts";

export type LabeledValue = {
  value: unknown;
  label: {
    integrity: string;
    trust_label?: TrustLabel;
    [key: string]: unknown;
  };
};

export function flattenText(value: unknown): string {
  if (isLabeledValue(value)) return flattenText(value.value);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(flattenText).join(" ");
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (typeof obj.text === "string") return obj.text;
    if (typeof obj.content === "string") return obj.content;
    return Object.values(obj).map(flattenText).join(" ");
  }
  return value === undefined || value === null ? "" : String(value);
}

export function isLabeledValue(value: unknown): value is LabeledValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const obj = value as Record<string, unknown>;
  const label = obj.label as Record<string, unknown> | undefined;
  return obj.value !== undefined && Boolean(label && typeof label === "object" && typeof label.integrity === "string");
}

export function readFirstString(args: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string") {
      const normalized = value.trim();
      if (normalized) return normalized;
    }
    if (isLabeledValue(value)) {
      const unwrapped = flattenText(value.value).trim();
      if (unwrapped) return unwrapped;
    }
  }
  return "";
}

export function hostFromUrl(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) return "";
  const candidates = [trimmed];
  if (trimmed.startsWith("//")) {
    candidates.push(`http:${trimmed}`);
  } else if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) && !/^[/\\]/.test(trimmed)) {
    candidates.push(`http://${trimmed}`);
  }
  for (const candidate of candidates) {
    try {
      const parsed = new URL(candidate);
      if (parsed.hostname) return parsed.hostname.toLowerCase().replace(/\.$/, "");
    } catch {
      // Try a host-like value with an implicit HTTP scheme next.
    }
  }
  return "";
}

export function isLocalHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return normalized === "localhost"
    || /^127(?:\.\d{1,3}){3}$/.test(normalized)
    || normalized === "::1"
    || normalized === "0.0.0.0"
    || normalized === "::ffff:127.0.0.1"
    || normalized.endsWith(".localhost");
}

export function containsAny(value: string, markers: string[]): boolean {
  return markers.some((marker) => value.includes(marker.toLowerCase()));
}

export function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}
