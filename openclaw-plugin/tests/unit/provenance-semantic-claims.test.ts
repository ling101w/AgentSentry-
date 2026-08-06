import { describe, expect, it } from "vitest";
import { extractFieldProvenance, semanticClaimsForValue, transformProvenance } from "../../core/taint/provenance-graph.ts";

describe("semantic provenance claims", () => {
  it("extracts bounded semantic claims for financial, credential, endpoint, privilege, and persistence facts", () => {
    const claims = semanticClaimsForValue({
      path: "$.employee.salary",
      key: "salary",
      value: "张三年薪 23 万，联系邮箱 zhangsan@example.com，初始化脚本会读取 token=fixtureCredentialValue123456 并访问 https://example.invalid/a，随后写入 crontab 长期执行。",
      confidentiality: "public",
    });

    expect(claims).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "financial_band", value: "high", confidentiality: "internal" }),
      expect.objectContaining({ kind: "personal_identifier", value: "person_related" }),
      expect.objectContaining({ kind: "credential_reference", value: "credential_material", confidentiality: "secret" }),
      expect.objectContaining({ kind: "external_endpoint", value: "external_network_target" }),
      expect.objectContaining({ kind: "privileged_access", value: "privileged_system_surface" }),
      expect.objectContaining({ kind: "persistence_capability", value: "persistent_behavior" }),
    ]));
  });

  it("handles low/medium financial bands and empty values without creating phantom claims", () => {
    expect(semanticClaimsForValue({ value: "" })).toEqual([]);
    expect(semanticClaimsForValue({ key: "salary", value: "年薪 5 万" })).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "financial_band", value: "low" }),
    ]));
    expect(semanticClaimsForValue({ key: "salary", value: "income 120000 CNY" })).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "financial_band", value: "medium" }),
    ]));
  });

  it("keeps field provenance values private while carrying semantic claims on leaves", () => {
    const fields = extractFieldProvenance({
      value: { employee: { salary: "收入较高", note: "ordinary public note" } },
      source: "tool_result",
      sourceId: "tool-call",
      previewChars: 200,
    });
    const salary = fields.find((field) => field.path.endsWith(".salary"));
    expect(salary?.semanticClaims).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "financial_band", value: "high" }),
    ]));

    const transformed = transformProvenance({
      parents: fields,
      source: "tool:summary",
      path: "$.summary",
      transformation: "semantic_summary",
      content: "该员工属于高收入人群",
    });
    expect(transformed.parentIds).toHaveLength(fields.length);
    expect(transformed.transformations).toEqual(expect.arrayContaining(["semantic_summary"]));
    expect(JSON.stringify(transformed)).not.toContain("收入较高");
  });
});
