import { describe, expect, it } from "vitest";
import { PluginConfig } from "../../config.ts";
import { applyExposureTaint, createPolicyState, labelToolResult, normalizeAction } from "../../core/policy.ts";
import { buildContentIndex, matchesIndexedChunk, normalizeIndexedText } from "../../core/taint/content-index.ts";
import { extractFieldProvenance, publicProvenance } from "../../core/taint/provenance-graph.ts";

describe("preview-independent content provenance", () => {
  const tail = "classified customer export: account-349823; contact-725943; retention-552304; balance-843920;";
  it("indexes long content independently from preview and omits indexes from public nodes", () => {
    const field = extractFieldProvenance({ value: "prefix ".repeat(500) + tail, source: "tool_result", sourceId: "fixture", previewChars: 30 })[0];
    expect(field.value.length).toBe(30);
    expect(matchesIndexedChunk(normalizeIndexedText(tail), field.contentIndex)).toBe(true);
    expect(publicProvenance(field)).not.toHaveProperty("contentIndex");
    expect(JSON.stringify(field.contentIndex)).not.toContain("classified customer");
  });
  it("detects tail copying, offset snippets and split output beyond the displayed prefix", () => {
    const config = new PluginConfig();
    config.capture.previewChars = 30;
    const state = createPolicyState();
    const content = "token=fixtureAlphaCredential123456; " + "public introduction ".repeat(500) + tail.repeat(3);
    labelToolResult("long-file", { secret: content }, state, config, "read_file");
    for (const body of [tail, "summary: " + tail, content.slice(-180, -70) + " -- " + content.slice(-70)]) {
      const result = applyExposureTaint(normalizeAction("send_email", { body }), state, config);
      expect(result.findings).toEqual(expect.arrayContaining([expect.objectContaining({
        verdict: "require_approval", evidence: expect.objectContaining({ match: "fingerprint_chunk", evidence_basis: "conservative" }),
      })]));
    }
    const exact = applyExposureTaint(normalizeAction("send_email", { body: content }), state, config);
    expect(exact.findings).toEqual(expect.arrayContaining([expect.objectContaining({ verdict: "block", evidence: expect.objectContaining({ match: "exact" }) })]));
  });
  it("does not present a copied display prefix as full-content exact proof", () => {
    const config = new PluginConfig();
    config.capture.previewChars = 30;
    const state = createPolicyState();
    labelToolResult("long-file", { secret: "token=fixtureAlphaCredential123456; " + "public introduction ".repeat(500) + tail }, state, config, "read_file");
    const result = applyExposureTaint(normalizeAction("send_email", { body: state.exposures[0].text }), state, config);
    expect(result.findings.some((finding) => finding.verdict === "block")).toBe(false);
  });
  it("prioritizes older exact evidence over a newer same-topic inference", () => {
    const config = new PluginConfig();
    const state = createPolicyState();
    const label = { source: "fixture", integrity: "untrusted" as const, confidentiality: "secret" as const, tainted: true };
    const body = "this employee has high income and receives the annual performance bonus";
    state.exposures.push({ source: "old-exact", text: body, label });
    state.exposures.push({ source: "new-topic", text: "employee salary 230000 CNY", label, semanticClaims: [{ kind: "financial_band", value: "high", confidence: 0.78, confidentiality: "internal", tags: [] }] });
    const result = applyExposureTaint(normalizeAction("send_email", { body }), state, config);
    expect(result.findings[0]).toMatchObject({ verdict: "block", evidence: { match: "exact", source: "old-exact" } });
  });
  it("does not infer origin from unrelated financial or credential topics", () => {
    const config = new PluginConfig();
    const state = createPolicyState();
    labelToolResult("hr", { salary: "Alice has annual salary 230000 CNY", token: "token=fixtureAlphaCredential123456" }, state, config, "read_file");
    for (const body of ["A textbook explains high income demographics.", "password=unrelatedBetaCredential654321"]) {
      expect(applyExposureTaint(normalizeAction("send_email", { body }), state, config).findings).toEqual([]);
    }
  });
  it("bounds the index while preserving a full-content fingerprint", () => {
    const index = buildContentIndex("x".repeat(300000) + tail);
    expect(index.truncated).toBe(true);
    expect(index.normalizedLength).toBeGreaterThan(300000);
    expect(Object.values(index.windows).flat().length).toBeLessThanOrEqual(8192);
  });
});
