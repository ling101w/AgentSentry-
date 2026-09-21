import type { AgentSentryRecord } from "../records.ts";
import {
  GRAPH_TRAINING_ENVELOPE_VERSION,
  assertProductionGraphInput,
  type GraphTrainingEnvelope,
  type ProductionGraphInput,
} from "./production-graph.ts";

export type GraphTrainingRow = {
  input: ProductionGraphInput;
  label: {
    source: "policy_weak_label";
    policy_outcome: "allow" | "review" | "block";
    deterministic_block: boolean;
  };
  metadata: {
    sample_id: string;
    record_id: string;
    run_id: string;
    session_key: string;
    captured_at: string;
    recorded_at: string;
  };
};

export function graphTrainingRowFromRecord(record: AgentSentryRecord | Record<string, unknown>): GraphTrainingRow | null {
  if (!record || record.type !== "tool_decision") return null;
  const payload = plainRecord(record.payload);
  const envelope = plainRecord(payload.graph_learning) as Partial<GraphTrainingEnvelope>;
  if (envelope.schema_version !== GRAPH_TRAINING_ENVELOPE_VERSION || typeof envelope.sample_id !== "string") return null;
  assertProductionGraphInput(envelope.input);
  const decision = payload.decision;
  if (decision !== "allow" && decision !== "ask" && decision !== "deny") return null;
  return {
    input: structuredClone(envelope.input),
    label: {
      source: "policy_weak_label",
      policy_outcome: decision === "deny" ? "block" : decision === "ask" ? "review" : "allow",
      deterministic_block: payload.deterministic_block === true,
    },
    metadata: {
      sample_id: envelope.sample_id,
      record_id: typeof record.id === "string" ? record.id : "",
      run_id: typeof record.run_id === "string" ? record.run_id : "",
      session_key: typeof record.session_key === "string" ? record.session_key : "",
      captured_at: typeof envelope.captured_at === "string" ? envelope.captured_at : "",
      recorded_at: typeof record.created_at === "string" ? record.created_at : "",
    },
  };
}

function plainRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, any> : {};
}
