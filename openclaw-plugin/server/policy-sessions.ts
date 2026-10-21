import { createPolicyState, type PolicyState } from "../core/policy.ts";
import type { RecordStore } from "../core/records.ts";
import { SessionQueue } from "../core/session-queue.ts";

export type PolicySession = { state: PolicyState; updatedAt: number; turn: number };

/** One runtime owns its sessions. Only successful committing requests publish their draft. */
export class PolicySessions {
  private readonly sessions = new Map<string, PolicySession>();
  private readonly clients = new Map<string, string>();
  private readonly queue = new SessionQueue();
  private readonly clientQueue = new SessionQueue();

  runClient<T>(clientId: string, runId: string, reset: boolean, work: (key: string) => Promise<T>): Promise<T> {
    const base = `lab:${clientId}`;
    return this.clientQueue.run(base, async () => {
      const existing = this.clients.get(base);
      const key = !reset && existing && this.sessions.has(existing) ? existing : `${base}:${runId}`;
      const result = await work(key);
      // A failed reset must not disconnect the client from its last committed session.
      for (const [client, session] of this.clients) {
        if (!this.sessions.has(session)) this.clients.delete(client);
      }
      if (this.sessions.has(key)) this.clients.set(base, key);
      return result;
    });
  }

  run<T>(key: string, options: { reset?: boolean; commit?: boolean }, work: (draft: PolicySession) => Promise<T>): Promise<T> {
    return this.queue.run(key, async () => {
      const now = Date.now();
      const existing = options.reset ? undefined : this.sessions.get(key);
      const fresh = existing && now - existing.updatedAt <= 60 * 60 * 1000 ? existing : undefined;
      const draft = {
        state: fresh ? structuredClone(fresh.state) : createPolicyState(),
        updatedAt: fresh?.updatedAt ?? now,
        turn: (fresh?.turn ?? 0) + 1,
      };
      const value = await work(draft);
      if (options.commit !== false) {
        for (const [candidate, session] of this.sessions) {
          if (!this.queue.has(candidate) && now - session.updatedAt > 60 * 60 * 1000) this.sessions.delete(candidate);
        }
        if (!this.sessions.has(key) && this.sessions.size >= 200) {
          const oldest = [...this.sessions].filter(([candidate]) => !this.queue.has(candidate))
            .sort((a, b) => a[1].updatedAt - b[1].updatedAt)[0];
          if (!oldest) throw new Error("Policy session capacity reached with in-flight requests");
          this.sessions.delete(oldest[0]);
        }
        draft.updatedAt = Date.now();
        this.sessions.set(key, draft);
      }
      return value;
    });
  }
}

const runtimes = new WeakMap<RecordStore, PolicySessions>();

export function policySessionsFor(store: RecordStore): PolicySessions {
  let sessions = runtimes.get(store);
  if (!sessions) {
    sessions = new PolicySessions();
    runtimes.set(store, sessions);
  }
  return sessions;
}
