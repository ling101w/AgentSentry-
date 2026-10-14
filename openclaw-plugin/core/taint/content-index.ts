import { createHash } from "node:crypto";

const WINDOW = 64;
const STRIDE = 32;
const MAX_INDEX_CHARS = 256 * 1024;
const BASE = 31;
const POWER = Array.from({ length: WINDOW - 1 }).reduce<number>((value) => Math.imul(value, BASE) >>> 0, 1);

export type ContentIndex = {
  normalizedHash: string;
  normalizedLength: number;
  windows: Record<string, string[]>;
  truncated: boolean;
};

export function normalizeIndexedText(text: string): string {
  return text.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
}

export function contentHash(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function scanWindows(text: string, visit: (offset: number, hash: number) => boolean): boolean {
  if (text.length < WINDOW) return false;
  let hash = 0;
  for (let index = 0; index < WINDOW; index++) hash = (Math.imul(hash, BASE) + text.charCodeAt(index)) >>> 0;
  for (let offset = 0; offset <= text.length - WINDOW; offset++) {
    if (visit(offset, hash)) return true;
    if (offset + WINDOW < text.length) {
      hash = (Math.imul((hash - Math.imul(text.charCodeAt(offset), POWER)) >>> 0, BASE) + text.charCodeAt(offset + WINDOW)) >>> 0;
    }
  }
  return false;
}

export function buildContentIndex(raw: string): ContentIndex {
  const text = normalizeIndexedText(raw);
  const windows: Record<string, string[]> = {};
  scanWindows(text.slice(0, MAX_INDEX_CHARS), (offset, hash) => {
    if (offset % STRIDE !== 0) return false;
    const key = String(hash);
    const digest = contentHash(text.slice(offset, offset + WINDOW));
    if (!windows[key]) windows[key] = [];
    if (!windows[key].includes(digest)) windows[key].push(digest);
    return false;
  });
  return { normalizedHash: contentHash(text), normalizedLength: text.length, windows, truncated: text.length > MAX_INDEX_CHARS };
}

export function matchesIndexedChunk(normalized: string, index: ContentIndex): boolean {
  return scanWindows(normalized.slice(0, MAX_INDEX_CHARS), (offset, hash) => {
    const candidates = index.windows[String(hash)];
    return Boolean(candidates?.includes(contentHash(normalized.slice(offset, offset + WINDOW))));
  });
}
