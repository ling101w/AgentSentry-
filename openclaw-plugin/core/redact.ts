const SECRET_KEY_PATTERN = /(api[_-]?key|token|secret|password|credential|authorization|cookie|session)/i;
const SECRET_VALUE_PATTERN = /(sk-[a-z0-9_-]{8,}|xox[baprs]-[a-z0-9-]{8,}|gh[pousr]_[a-z0-9_]{12,}|bearer\s+[a-z0-9._-]{12,})/gi;
const SECRET_ASSIGNMENT_PATTERN = /((?:["']?(?:api[_-]?key|token|secret|password|credential|authorization|cookie|session)["']?)\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|(?!\[)[^\s,;}\]]{8,})/gi;
const PRIVATE_KEY_PATTERN = /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/g;
const AWS_ACCESS_KEY_PATTERN = /\bAKIA[0-9A-Z]{16}\b/g;

export function clampText(value: unknown, maxChars: number): string {
  const text = typeof value === "string" ? value : safeStringify(value);
  const redacted = redactSecrets(text);
  if (redacted.length <= maxChars) return redacted;
  if (maxChars <= 3) return ".".repeat(Math.max(0, maxChars));
  return `${redacted.slice(0, Math.max(0, maxChars - 3))}...`;
}

export function redactObject(value: unknown, maxChars: number): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return clampText(value, maxChars);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 40).map((item) => redactObject(item, maxChars));
  if (typeof value !== "object") return clampText(String(value), maxChars);

  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_KEY_PATTERN.test(key)) {
      out[key] = "[redacted]";
      continue;
    }
    out[key] = redactObject(item, maxChars);
  }
  return out;
}

export function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function redactSecrets(text: string): string {
  return text
    .replace(PRIVATE_KEY_PATTERN, "[redacted-private-key]")
    .replace(AWS_ACCESS_KEY_PATTERN, "[redacted]")
    .replace(SECRET_ASSIGNMENT_PATTERN, '$1"[redacted]"')
    .replace(SECRET_VALUE_PATTERN, "[redacted]");
}
