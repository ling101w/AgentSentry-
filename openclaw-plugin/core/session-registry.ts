export const DEFAULT_SESSION_IDLE_TTL_MS = 30 * 60 * 1000;
export const DEFAULT_MAX_SESSIONS = 256;

export class SessionRegistry<T extends { lastAccessedAt: number }> {
  private readonly entries = new Map<string, T>();
  private readonly idleTtlMs: number;
  private readonly maxSessions: number;

  constructor(options: { idleTtlMs?: number; maxSessions?: number } = {}) {
    this.idleTtlMs = options.idleTtlMs ?? DEFAULT_SESSION_IDLE_TTL_MS;
    this.maxSessions = options.maxSessions ?? DEFAULT_MAX_SESSIONS;
  }

  get size(): number {
    return this.entries.size;
  }

  get(key: string, now = Date.now()): T | undefined {
    this.evictExpired(now);
    const value = this.entries.get(key);
    if (!value) return undefined;
    value.lastAccessedAt = now;
    this.entries.delete(key);
    this.entries.set(key, value);
    return value;
  }

  set(key: string, value: T, now = Date.now()): void {
    this.evictExpired(now);
    value.lastAccessedAt = now;
    this.entries.delete(key);
    this.entries.set(key, value);
    while (this.entries.size > this.maxSessions) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }

  evictExpired(now = Date.now()): number {
    const cutoff = now - this.idleTtlMs;
    let removed = 0;
    for (const [key, value] of this.entries) {
      if (value.lastAccessedAt > cutoff) continue;
      this.entries.delete(key);
      removed += 1;
    }
    return removed;
  }

  clear(): void {
    this.entries.clear();
  }
}
