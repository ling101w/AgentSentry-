import { describe, expect, it } from "vitest";
import { normalizeAction } from "../../core/policy.ts";
import {
  clearCustomToolManifests,
  registerToolManifest,
  toolManifestDigest,
  toolManifestFindings,
  verifyToolManifest,
  type ToolManifestEnvelope,
  type ToolSecurityManifest,
} from "../../core/tool-manifest.ts";

const CRM_MANIFEST: ToolSecurityManifest = {
  toolId: "mcp.crm.create_ticket",
  aliases: ["crm_create_ticket"],
  dataOrigins: ["third_party_api"],
  sideEffects: ["network_write", "persistent_state"],
  acceptsSensitiveData: true,
  canExfiltrate: true,
  requiresExplicitAuthorization: true,
  defaultTrust: "external",
};

describe("Tool Security Manifest", () => {
  it("hashes canonical metadata and verifies the registered envelope", () => {
    const left = toolManifestDigest(CRM_MANIFEST, { schema: { b: 2, a: 1 }, endpoint: "https://crm.example/api", version: "1" });
    const right = toolManifestDigest(CRM_MANIFEST, { schema: { a: 1, b: 2 }, endpoint: "https://crm.example/api", version: "1" });
    expect(left).toBe(right);

    const envelope = registerToolManifest(CRM_MANIFEST, {
      schema: { input: "ticket" },
      endpoint: "https://crm.example/api",
      version: "1",
    });
    expect(verifyToolManifest(envelope)).toBe(true);
  });

  it("fails closed on a changed digest-pinned manifest", () => {
    const envelope = registerToolManifest(CRM_MANIFEST, { version: "1" });
    const tampered: ToolManifestEnvelope = {
      ...envelope,
      manifest: { ...envelope.manifest, sideEffects: ["network_write", "process_exec"] },
    };
    expect(verifyToolManifest(tampered)).toBe(false);
    const findings = toolManifestFindings("mcp.crm.create_ticket", "mcp.crm.create_ticket", {
      __toolSecurityManifest: tampered,
    });
    expect(findings).toEqual(expect.arrayContaining([expect.objectContaining({ verdict: "block", reason: "tool_manifest_integrity_mismatch" })]));

    const recomputed = {
      ...tampered,
      digest: toolManifestDigest(tampered.manifest, tampered),
    };
    expect(verifyToolManifest(recomputed)).toBe(true);
    expect(toolManifestFindings("mcp.crm.create_ticket", "mcp.crm.create_ticket", {
      __toolSecurityManifest: recomputed,
    })).toEqual(expect.arrayContaining([
      expect.objectContaining({ verdict: "block", reason: "tool_manifest_integrity_mismatch" }),
    ]));
  });

  it("requires approval for an unregistered tool regardless of a benign name", () => {
    const findings = toolManifestFindings("internal_search_v2", "internal_search_v2", { query: "quarterly report" });
    expect(findings).toEqual(expect.arrayContaining([expect.objectContaining({ verdict: "require_approval" })]));

    const misleading = toolManifestFindings("mcp.evil.fetch_report", "call_api", { url: "https://example.com" });
    expect(misleading).toEqual(expect.arrayContaining([expect.objectContaining({ verdict: "require_approval" })]));
  });

  it("accepts a registered manifest and rejects identity substitution", () => {
    const registered = registerToolManifest(CRM_MANIFEST, { version: "2" });
    expect(toolManifestFindings("crm_create_ticket", "crm_create_ticket", {})).toEqual([]);

    const other = registerToolManifest({ ...CRM_MANIFEST, toolId: "mcp.crm.other", aliases: [] }, { version: "2" });
    const findings = toolManifestFindings("mcp.crm.create_ticket", "mcp.crm.create_ticket", {
      toolSecurityManifest: other,
    });
    expect(findings).toEqual(expect.arrayContaining([expect.objectContaining({ verdict: "block", reason: expect.stringContaining("identity") })]));
    expect(verifyToolManifest(registered)).toBe(true);
  });

  it("rejects an unexpected digest at registration time", () => {
    expect(() => registerToolManifest(CRM_MANIFEST, { expectedDigest: "0".repeat(64) })).toThrow("tool_manifest_integrity_mismatch");
  });

  it("blocks malformed runtime manifests and reserved alias takeover", () => {
    expect(toolManifestFindings("send_email", "send_email", {
      __toolSecurityManifest: { manifest: { toolId: "send_email" }, digest: "bad" },
    })).toEqual(expect.arrayContaining([
      expect.objectContaining({ verdict: "block", reason: "tool_manifest_invalid" }),
    ]));

    expect(() => registerToolManifest({ ...CRM_MANIFEST, toolId: "mcp.crm.alias-takeover", aliases: ["send_email"] }))
      .toThrow("tool_manifest_alias_conflict");
  });

  it("uses a registered manifest identity before name heuristics", () => {
    try {
      registerToolManifest({
        toolId: "business_read",
        aliases: ["search_emails"],
        dataOrigins: ["email"],
        sideEffects: ["none"],
        acceptsSensitiveData: false,
        canExfiltrate: false,
        requiresExplicitAuthorization: false,
        defaultTrust: "external",
      });
      expect(normalizeAction("search_emails", { query: "quarterly" }).tool).toBe("business_read");
    } finally {
      clearCustomToolManifests();
    }
  });
});
