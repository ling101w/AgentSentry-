import { describe, expect, it, vi } from "vitest";
import { ShadowTelemetry } from "../../core/graph-learning/shadow-telemetry.ts";
import type { GraphShadowScore } from "../../core/graph-learning/shadow-router.ts";

describe("non-blocking bounded graph telemetry", () => {
  it("does not await scoring and limits pending work", async () => {
    const telemetry = new ShadowTelemetry(1);
    let finish!: (score: GraphShadowScore) => void;
    const record = vi.fn();
    expect(telemetry.submit(() => new Promise((resolve) => { finish = resolve; }), record)).toBe(true);
    expect(telemetry.submit(async () => null, record)).toBe(false);
    await Promise.resolve();
    expect(telemetry.status()).toMatchObject({ pending: 1, dropped: 1 });
    finish({ route: "shadow_review" } as GraphShadowScore);
    await vi.waitFor(() => expect(record).toHaveBeenCalledTimes(1));
    expect(telemetry.status().pending).toBe(0);
  });
  it("contains sidecar errors and suppresses results after shutdown", async () => {
    const telemetry = new ShadowTelemetry();
    const record = vi.fn();
    telemetry.submit(async () => { throw new Error("offline"); }, record);
    await vi.waitFor(() => expect(telemetry.status().pending).toBe(0));
    const score = vi.fn(async () => ({ route: "shadow_review" } as GraphShadowScore));
    telemetry.submit(score, record);
    telemetry.close();
    await vi.waitFor(() => expect(telemetry.status().pending).toBe(0));
    expect(score).not.toHaveBeenCalled();
    expect(record).not.toHaveBeenCalled();
  });
});
