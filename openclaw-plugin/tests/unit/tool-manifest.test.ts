import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PluginConfig } from "../../config.ts";
import { normalizeAction } from "../../core/policy.ts";
import {
  clearCustomToolManifests,
  configureToolManifestSigning,
  listToolManifestRevocations,
  registerToolManifest,
  toolManifestDigest,
  toolManifestFindings,
  toolManifestSignature,
  verifyToolManifest,
  revokeToolManifest,
  restoreToolManifest,
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

  it("includes subject and purpose declarations in the signed contract", () => {
    const manifest: ToolSecurityManifest = {
      ...CRM_MANIFEST,
      toolId: "mcp.crm.subject-bound",
      aliases: [],
      dataClassification: "user_private" as const,
      dataSubjects: ["named_subject", "third_party"],
      purposeBinding: "task_bound" as const,
    };
    const registered = registerToolManifest(manifest, { version: "1" });
    expect(verifyToolManifest(registered)).toBe(true);
    expect(registered.manifest).toMatchObject({
      dataSubjects: ["named_subject", "third_party"],
      purposeBinding: "task_bound",
    });
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
    recomputed.signature = toolManifestSignature(recomputed.manifest, recomputed);
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

  it("blocks a tool immediately after its signed manifest is revoked and permits explicit restoration", () => {
    const registered = registerToolManifest({ ...CRM_MANIFEST, toolId: "mcp.crm.revocable", aliases: ["crm_revocable"] }, { version: "4" });
    const revoked = revokeToolManifest("crm_revocable", "供应商发现未声明的数据外发");
    expect(revoked.digest).toBe(registered.digest);
    expect(toolManifestFindings("crm_revocable", "crm_revocable", {})).toEqual(expect.arrayContaining([
      expect.objectContaining({ verdict: "block", reason: "tool_manifest_revoked" }),
    ]));
    expect(restoreToolManifest("mcp.crm.revocable")).toBe(true);
    expect(toolManifestFindings("crm_revocable", "crm_revocable", {})).toEqual([]);
  });

  it("persists administrator-signed registrations and revocations across registry reload", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "agentsentry-tool-registry-"));
    try {
      const config = new PluginConfig();
      config.storage.stateDir = stateDir;
      configureToolManifestSigning(config);
      registerToolManifest({ ...CRM_MANIFEST, toolId: "mcp.crm.persisted", aliases: ["crm_persisted"] }, { version: "1" });
      revokeToolManifest("crm_persisted", "供应链公告要求暂停使用");
      configureToolManifestSigning(config);
      expect(toolManifestFindings("crm_persisted", "crm_persisted", {})).toEqual(expect.arrayContaining([
        expect.objectContaining({ verdict: "block", reason: "tool_manifest_revoked" }),
      ]));
    } finally {
      clearCustomToolManifests();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("rejects malformed administrator manifests and describes inferred effects for unknown tools", () => {
    expect(() => registerToolManifest(null as unknown as ToolSecurityManifest)).toThrow("tool manifest must be an object");
    expect(() => registerToolManifest({ ...CRM_MANIFEST, toolId: "" })).toThrow("requires toolId");
    expect(() => registerToolManifest({ ...CRM_MANIFEST, toolId: "mcp.crm.bad-alias", aliases: [""] })).toThrow("aliases must be non-empty");
    expect(() => registerToolManifest({ ...CRM_MANIFEST, toolId: "mcp.crm.bad-origin", dataOrigins: ["unknown-origin" as never] })).toThrow("invalid data origin");
    expect(() => registerToolManifest({ ...CRM_MANIFEST, toolId: "mcp.crm.bad-effect", sideEffects: ["unknown-effect" as never] })).toThrow("invalid side effect");
    expect(() => registerToolManifest({ ...CRM_MANIFEST, toolId: "mcp.crm.bad-flags", canExfiltrate: "yes" as never })).toThrow("flags must be boolean");
    expect(() => revokeToolManifest("mcp.missing", "不存在")).toThrow("tool_manifest_not_registered");

    const findings = toolManifestFindings("mcp.unregistered.runner", "mcp.unregistered.runner", {
      command: "status",
      path: "/srv/report.txt",
      content: "completed",
    });
    expect(findings[0].evidence.inferred_effects).toEqual(expect.arrayContaining(["process_exec", "file_write"]));
  });

  it("keeps revocation records inspectable and ignores a malformed persisted registry", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "agentsentry-tool-registry-invalid-"));
    try {
      const config = new PluginConfig();
      config.storage.stateDir = stateDir;
      const registryDir = join(stateDir, "agentsentry");
      mkdirSync(registryDir, { recursive: true });
      writeFileSync(join(registryDir, "tool-manifest-registry.json"), "{not-json", "utf8");
      configureToolManifestSigning(config);
      expect(toolManifestFindings("send_email", "send_email", {})).toEqual([]);

      registerToolManifest({ ...CRM_MANIFEST, toolId: "mcp.crm.sort-one", aliases: ["crm_sort_one"] });
      registerToolManifest({ ...CRM_MANIFEST, toolId: "mcp.crm.sort-two", aliases: ["crm_sort_two"] });
      revokeToolManifest("crm_sort_one", "第一条");
      revokeToolManifest("crm_sort_two", "第二条");
      expect(listToolManifestRevocations()).toHaveLength(2);
    } finally {
      clearCustomToolManifests();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });
});
