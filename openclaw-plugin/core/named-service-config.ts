export type NamedServiceBinding = {
  id: string;
  names: string[];
  purpose: "health_read";
  endpoint: string;
};

export function canonicalServiceEndpoint(value: string): string | undefined {
  if (!value.trim() || value.length > 2048 || /[\x00-\x20\\]/.test(value)) return undefined;
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) return undefined;
    return url.toString();
  } catch { return undefined; }
}

/** Configuration is the authority. Invalid lists never yield partial grants. */
export function parseNamedServiceBindings(value: unknown): NamedServiceBinding[] | undefined {
  if (!Array.isArray(value) || value.length > 32) return undefined;
  const result: NamedServiceBinding[] = [];
  const ids = new Set<string>();
  for (const entry of value) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return undefined;
    const item = entry as Record<string, unknown>;
    if (Object.keys(item).some((key) => !["id", "names", "purpose", "endpoint"].includes(key))
      || typeof item.id !== "string" || !/^[a-z][a-z0-9._-]{1,79}$/.test(item.id) || ids.has(item.id)
      || item.purpose !== "health_read" || typeof item.endpoint !== "string"
      || !Array.isArray(item.names) || !item.names.length || item.names.length > 16
      || item.names.some((name) => typeof name !== "string" || name.trim().length < 2 || name.length > 80 || /[\r\n\x00]/.test(name))) return undefined;
    const endpoint = canonicalServiceEndpoint(item.endpoint);
    if (!endpoint) return undefined;
    ids.add(item.id);
    result.push({ id: item.id, names: [...new Set(item.names.map((name: string) => name.normalize("NFKC").trim()))], purpose: "health_read", endpoint });
  }
  return result;
}
