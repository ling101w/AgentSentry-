export const DEFAULT_SESSION_IDLE_TTL_MS = 30 * 60 * 1000;
export const DEFAULT_MAX_SESSIONS = 256;

export class SessionRegistry<T extends { lastAccessedAt: number }> {
  private readonly entries = new Map<string, T>();
  private readonly idleTtlMs: number;
  private readonly maxSessions: number;
  private readonly canEvict: (value: T) => boolean;

  constructor(options: { idleTtlMs?: number; maxSessions?: number; canEvict?: (value: T) => boolean } = {}) {
    this.idleTtlMs = options.idleTtlMs ?? DEFAULT_SESSION_IDLE_TTL_MS;
    this.maxSessions = options.maxSessions ?? DEFAULT_MAX_SESSIONS;
    this.canEvict = options.canEvict ?? (() => true);
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
    if (this.entries.has(key)) {
      this.entries.delete(key);
      this.entries.set(key, value);
      return;
    }
    while (this.entries.size >= this.maxSessions) {
      const oldest = [...this.entries.entries()].find(([, candidate]) => this.canEvict(candidate));
      if (!oldest) throw new Error("AgentSentry active session capacity reached with in-flight calls; refusing untracked session state");
      this.entries.delete(oldest[0]);
    }
    this.entries.set(key, value);
  }

  evictExpired(now = Date.now()): number {
    const cutoff = now - this.idleTtlMs;
    let removed = 0;
    for (const [key, value] of this.entries) {
      if (value.lastAccessedAt > cutoff) continue;
      if (!this.canEvict(value)) continue;
      this.entries.delete(key);
      removed += 1;
    }
    return removed;
  }

  clear(): void {
    this.entries.clear();
  }

  delete(key: string): boolean {
    return this.entries.delete(key);
  }

  values(): IterableIterator<T> {
    return this.entries.values();
  }

  entriesIterator(): IterableIterator<[string, T]> {
    return this.entries.entries();
  }

  [Symbol.iterator](): IterableIterator<[string, T]> {
    return this.entries[Symbol.iterator]();
  }
}
