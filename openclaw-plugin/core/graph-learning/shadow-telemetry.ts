import type { GraphShadowScore } from "./shadow-router.ts";

export class ShadowTelemetry {
  private pending = 0;
  private closed = false;
  private dropped = 0;

  constructor(private readonly maxPending = 32) {}

  submit(score: () => Promise<GraphShadowScore | null>, record: (result: GraphShadowScore) => void): boolean {
    if (this.closed || this.pending >= this.maxPending) { this.dropped++; return false; }
    this.pending++;
    void Promise.resolve().then(() => this.closed ? null : score()).then((result) => {
      if (!this.closed && result) record(result);
    }).catch(() => undefined).finally(() => { this.pending--; });
    return true;
  }

  status() { return { pending: this.pending, dropped: this.dropped, closed: this.closed }; }
  close(): void { this.closed = true; }
}
