import { PluginConfig } from "../../config.ts";
import type { DetectionFinding } from "../detect.ts";
import { isLabeledValue } from "./value-utils.ts";
import type { SemanticProvenanceLink } from "../semantic-action-graph.ts";
import { publicProvenance, transformProvenance, type DataProvenance } from "../taint/provenance-graph.ts";
import type { AgentSentryAction, Label, PolicyState } from "./contracts.ts";
import { flattenText, matchExposure, provenanceEvidenceForMatch, finding } from "./support.ts";

const HIGH_RISK_SINKS = new Set(["send_email", "call_api", "shell_exec", "memory_write", "calendar_write"]);

export function applyExposureTaint(action: AgentSentryAction, state: PolicyState, config: PluginConfig): {
  action: AgentSentryAction;
  findings: DetectionFinding[];
  links: SemanticProvenanceLink[];
  additions: DataProvenance[];
} {
  if (!config.detection.enabled || !config.policy.deterministic || !state.exposures.length) {
    return { action, findings: [], links: [], additions: [] };
  }

  const args = { ...action.args };
  const findings: DetectionFinding[] = [];
  const links: SemanticProvenanceLink[] = [];
  const additions: DataProvenance[] = [];
  const blocksTaintedInput = HIGH_RISK_SINKS.has(action.tool);
  let matchedAny = false;
  for (const [key, value] of Object.entries(args)) {
    if (isControlArg(key)) continue;
    if (isLabeledValue(value)) continue;
    const text = flattenText(value);
    if (!text.trim()) continue;
    const match = matchExposure(text, state.exposures);
    let exposure = match?.exposure || null;
    let mode = match?.mode || "";
    if (!exposure) continue;
    const matchEvidence = provenanceEvidenceForMatch(mode);
    matchedAny = true;
    const inheritedLabel: Label = {
      ...exposure.label,
      influence: mode === "run_exposure_default" ? "payload_default" : "matched",
    };
    args[key] = { value, label: inheritedLabel };
    const parent = exposure.provenanceId
      ? state.dataProvenance.find((item) => item.id === exposure.provenanceId)
      : null;
    const lineage = parent
      ? transformProvenance({
        parents: [parent],
        source: `tool:${action.originalTool || action.tool}`,
        path: provenanceArgPath(key),
        transformation: mode,
        content: value,
      })
      : null;
    if (lineage) {
      additions.push(publicProvenance(lineage));
      links.push({ provenanceId: lineage.id, argPath: provenanceArgPath(key), match: mode, ...matchEvidence });
    } else if (exposure.provenanceId) {
      links.push({ provenanceId: exposure.provenanceId, argPath: provenanceArgPath(key), match: mode, ...matchEvidence });
    }
    if (blocksTaintedInput) {
      const observed = matchEvidence.basis !== "conservative";
      findings.push(finding(
        "Tool Boundary",
        observed ? "deterministic" : "heuristic",
        observed ? "block" : "require_approval",
        observed
          ? "sink argument inherits malicious or secret taint"
          : "sink argument may inherit malicious or secret taint through an inferred match",
        observed ? 100 : 60,
        {
          tool: action.tool,
          arg: key,
          source: exposure.source,
          match: mode,
          evidence_basis: matchEvidence.basis,
          confidence: matchEvidence.confidence,
          semantic_claims: exposure.semanticClaims || [],
          provenance_id: lineage?.id || exposure.provenanceId || "",
          parent_ids: lineage?.parentIds || [],
          provenance_path: lineage?.path || "",
        },
      ));
    }
  }

  if (!matchedAny) return { action, findings, links, additions };
  return { action: { ...action, args }, findings, links, additions };
}

function isControlArg(name: string): boolean {
  return /^(timeout|timeoutms|max_?tokens?|limit|page|pagesize|offset|cursor|count|retries|retry|temperature|top_p|stream)$/i.test(String(name || ""));
}

function provenanceArgPath(key: string): string {
  return /^[A-Za-z_$][\w$]*$/.test(key) ? `$.args.${key}` : `$.args[${JSON.stringify(key)}]`;
}
