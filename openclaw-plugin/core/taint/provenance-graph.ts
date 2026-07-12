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

export interface FieldProvenance extends DataProvenance {
  value: string;
  trustLabel: TrustLabel;
  riskVector: RiskVector;
  tags: string[];
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

function fingerprint(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function escapePath(value: string): string {
  return /^[A-Za-z_$][\w$]*$/.test(value) ? value : `[${JSON.stringify(value)}]`;
}
