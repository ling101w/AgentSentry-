import { createHash } from "node:crypto";
import {
  analyzeTrustContent,
  type RiskVector,
  type TrustLabel,
  type TrustSource,
} from "../trust.ts";

export interface DataProvenance {
  id: string;
  parentIds: string[];
  source: string;
  path: string;
  confidentiality: "public" | "internal" | "secret";
  integrity: "trusted" | "untrusted" | "tainted";
  transformations: string[];
  contentFingerprint: string;
}

export type SemanticClaim = {
  kind:
    | "financial_band"
    | "personal_identifier"
    | "credential_reference"
    | "external_endpoint"
    | "privileged_access"
    | "persistence_capability";
  value: string;
  confidence: number;
  confidentiality: "public" | "internal" | "secret";
  tags: string[];
};

export interface FieldProvenance extends DataProvenance {
  value: string;
  trustLabel: TrustLabel;
  riskVector: RiskVector;
  tags: string[];
  semanticClaims: SemanticClaim[];
}

export function extractFieldProvenance(input: {
  value: unknown;
  source: TrustSource;
  sourceId: string;
  toolName?: string;
  previewChars: number;
  parentIds?: string[];
}): FieldProvenance[] {
  const leaves = collectLeaves(input.value);
  return leaves.map((leaf) => {
    const analysisValue = leaf.key ? { [leaf.key]: leaf.value } : leaf.value;
    const analysis = analyzeTrustContent(analysisValue, {
      source: input.source,
      sourceId: `${input.sourceId}:${leaf.path}`,
      toolName: input.toolName,
      path: leaf.path,
      previewChars: input.previewChars,
    });
    const value = stringifyLeaf(leaf.value);
    const contentFingerprint = fingerprint(value);
    return {
      id: `prov_${fingerprint(`${input.sourceId}\u0000${leaf.path}\u0000${contentFingerprint}`).slice(0, 24)}`,
      parentIds: [...(input.parentIds || [])],
      source: input.sourceId,
      path: leaf.path,
      confidentiality: analysis.label.confidentiality,
      integrity: provenanceIntegrity(analysis.label),
      transformations: [],
      contentFingerprint,
      value: value.slice(0, input.previewChars),
      trustLabel: analysis.label,
      riskVector: analysis.risk_vector,
      tags: analysis.tags,
      semanticClaims: semanticClaimsForValue({
        path: leaf.path,
        key: leaf.key,
        value,
        tags: analysis.tags,
        confidentiality: analysis.label.confidentiality,
      }),
    };
  });
}

export function transformProvenance(input: {
  parents: DataProvenance[];
  source: string;
  path: string;
  transformation: string;
  content: unknown;
}): DataProvenance {
  const content = stringifyLeaf(input.content);
  const contentFingerprint = fingerprint(content);
  const confidentiality = maxConfidentiality(input.parents.map((item) => item.confidentiality));
  const integrity = minIntegrity(input.parents.map((item) => item.integrity));
  const transformations = Array.from(new Set([
    ...input.parents.flatMap((item) => item.transformations),
    input.transformation,
  ])).slice(-12);
  return {
    id: `prov_${fingerprint(`${input.source}\u0000${input.path}\u0000${contentFingerprint}\u0000${input.parents.map((item) => item.id).join("|")}`).slice(0, 24)}`,
    parentIds: input.parents.map((item) => item.id),
    source: input.source,
    path: input.path,
    confidentiality,
    integrity,
    transformations,
    contentFingerprint,
  };
}

export function publicProvenance(node: DataProvenance): DataProvenance {
  return {
    id: node.id,
    parentIds: [...node.parentIds],
    source: node.source,
    path: node.path,
    confidentiality: node.confidentiality,
    integrity: node.integrity,
    transformations: [...node.transformations],
    contentFingerprint: node.contentFingerprint,
  };
}

export function semanticClaimsForValue(input: {
  path?: string;
  key?: string;
  value: unknown;
  tags?: string[];
  confidentiality?: "public" | "internal" | "secret";
}): SemanticClaim[] {
  const text = canonicalClaimText(stringifyLeaf(input.value)).slice(0, 4096);
  if (!text) return [];
  const context = canonicalClaimText(`${input.path || ""} ${input.key || ""} ${text}`);
  const claims: SemanticClaim[] = [];
  const baseConfidentiality = input.confidentiality || "public";

  const financialContext = /(salary|income|compensation|payroll|wage|bonus|年薪|薪资|薪酬|工资|收入|奖金)/iu.test(context);
  if (financialContext) {
    const band = incomeBandFromText(context);
    if (band) {
      claims.push({
        kind: "financial_band",
        value: band,
        confidence: band === "unknown" ? 0.56 : 0.78,
        confidentiality: strongerClaimConfidentiality(baseConfidentiality, "internal"),
        tags: ["financial_attribute", "semantic_derivation"],
      });
    }
  }

  if (/(高收入|高薪|high[-\s]?income|upper[-\s]?income|senior\s+compensation|收入较高|薪资较高)/iu.test(context)) {
    claims.push({
      kind: "financial_band",
      value: "high",
      confidence: 0.72,
      confidentiality: strongerClaimConfidentiality(baseConfidentiality, "internal"),
      tags: ["financial_attribute", "semantic_derivation"],
    });
  }

  if (/(?:[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|(?:\+?\d[\d\s().-]{7,}\d)|身份证|住址|手机号|邮箱|patient|employee|customer|客户|员工|患者)/iu.test(context)) {
    claims.push({
      kind: "personal_identifier",
      value: "person_related",
      confidence: 0.72,
      confidentiality: strongerClaimConfidentiality(baseConfidentiality, "internal"),
      tags: ["personal_data"],
    });
  }

  if (/(?:-----begin [\s\S]{0,40}private key-----|(?:api[_ -]?key|token|secret|credential|password)\s*[:=]\s*["']?[\w./_-]{8,}|private\s*key|openclaw\.json|(?:^|[^\w])\.env(?:[^\w]|$)|id_(?:rsa|ed25519|ecdsa|dsa)|密钥\s*[:=]|凭据\s*[:=]|令牌\s*[:=]|私钥)/iu.test(context)) {
    claims.push({
      kind: "credential_reference",
      value: "credential_material",
      confidence: 0.86,
      confidentiality: "secret",
      tags: ["credential_reference"],
    });
  }

  if (/https?:\/\/(?!localhost(?::|\/|$)|127\.0\.0\.1(?::|\/|$)|\[::1\](?::|\/|$))/iu.test(context)) {
    claims.push({
      kind: "external_endpoint",
      value: "external_network_target",
      confidence: 0.74,
      confidentiality: baseConfidentiality,
      tags: ["external_endpoint"],
    });
  }

  if (/(?:sudo|root|chmod|chown|systemctl|crontab|startup|systemd|\/etc\/|~\/\.ssh|管理员|提权|定时任务|启动项)/iu.test(context)) {
    claims.push({
      kind: "privileged_access",
      value: "privileged_system_surface",
      confidence: 0.78,
      confidentiality: strongerClaimConfidentiality(baseConfidentiality, "internal"),
      tags: ["privileged_surface"],
    });
  }

  if (/(?:remember|persist|future|from now on|always|memory|记住|长期|永久|以后|未来|默认|每次)/iu.test(context)) {
    claims.push({
      kind: "persistence_capability",
      value: "persistent_behavior",
      confidence: 0.68,
      confidentiality: baseConfidentiality,
      tags: ["persistence_context"],
    });
  }

  const byKey = new Map<string, SemanticClaim>();
  for (const claim of claims) {
    const key = `${claim.kind}:${claim.value}`;
    const current = byKey.get(key);
    if (!current || claim.confidence > current.confidence) byKey.set(key, claim);
  }
  return [...byKey.values()].slice(0, 12);
}

function collectLeaves(value: unknown, path = "$", key = ""): Array<{ path: string; key: string; value: unknown }> {
  if (Array.isArray(value)) {
    if (!value.length) return [{ path, key, value: [] }];
    return value.flatMap((item, index) => collectLeaves(item, `${path}[${index}]`, String(index)));
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (!entries.length) return [{ path, key, value: {} }];
    return entries.flatMap(([childKey, child]) => collectLeaves(child, `${path}.${escapePath(childKey)}`, childKey));
  }
  return [{ path, key, value }];
}

function provenanceIntegrity(label: TrustLabel): DataProvenance["integrity"] {
  if (label.tainted || label.integrity === "tainted") return "tainted";
  if (label.integrity === "external") return "untrusted";
  return "trusted";
}

function maxConfidentiality(values: DataProvenance["confidentiality"][]): DataProvenance["confidentiality"] {
  if (values.includes("secret")) return "secret";
  if (values.includes("internal")) return "internal";
  return "public";
}

function minIntegrity(values: DataProvenance["integrity"][]): DataProvenance["integrity"] {
  if (values.includes("tainted")) return "tainted";
  if (values.includes("untrusted")) return "untrusted";
  return "trusted";
}

function stringifyLeaf(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined) return "undefined";
  if (value === null) return "null";
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function canonicalClaimText(value: string): string {
  return value.normalize("NFKC").replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00ad]/g, "").toLowerCase();
}

function incomeBandFromText(text: string): "low" | "medium" | "high" | "unknown" | "" {
  const values: number[] = [];
  const numberMatches = text.matchAll(/(\d+(?:\.\d+)?)\s*(万|w|k|千|元|rmb|cny|usd|\$)?/giu);
  for (const match of numberMatches) {
    let amount = Number(match[1]);
    if (!Number.isFinite(amount)) continue;
    const unit = String(match[2] || "").toLowerCase();
    if (unit === "万" || unit === "w") amount *= 10_000;
    else if (unit === "k" || unit === "千") amount *= 1_000;
    if (amount >= 1_000) values.push(amount);
  }
  if (!values.length) return /高收入|高薪|high[-\s]?income|upper[-\s]?income|收入较高|薪资较高/iu.test(text) ? "high" : "";
  const max = Math.max(...values);
  if (max >= 200_000) return "high";
  if (max >= 80_000) return "medium";
  return "low";
}

function strongerClaimConfidentiality(
  left: SemanticClaim["confidentiality"],
  right: SemanticClaim["confidentiality"],
): SemanticClaim["confidentiality"] {
  const rank = { public: 0, internal: 1, secret: 2 } as const;
  return rank[left] >= rank[right] ? left : right;
}

function fingerprint(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function escapePath(value: string): string {
  return /^[A-Za-z_$][\w$]*$/.test(value) ? value : `[${JSON.stringify(value)}]`;
}
