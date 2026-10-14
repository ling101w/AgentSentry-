import type { PolicyState, PolicyEffects, PolicyStateCheckpoint } from "./contracts.ts";
import { deriveTaskSpecV2, createAuthorizationState } from "../task-spec/index.ts";
import { createSemanticActionGraph, activateSemanticIntent, type SemanticActionGraphState } from "../semantic-action-graph.ts";
import { createRiskVector } from "../trust.ts";
import { createDynamicSecurityState } from "../dynamic-security.ts";
export function createPolicyState(): PolicyState {
  const taskSpec = deriveTaskSpecV2("", [], "user");
  const authorizationState = createAuthorizationState([]);
  const semanticActionGraph = createSemanticActionGraph();
  activateSemanticIntent(semanticActionGraph, taskSpec);

  return {
    sessionRevision: 0,
    currentTask: "",
    taskSpec,
    authorizationState: { ...authorizationState, taskSpec },
    contaminated: false,
    provenanceBlocked: false,
    provenanceFindings: [],
    history: [],
    toolResultLabels: new Map(),
    exposures: [],
    apiCallCounts: new Map(),
    behaviorProfiles: new Map(),
    runtimeProfiles: new Map(),
    trustLabels: [],
    aggregateRisk: createRiskVector(),
    taintedSources: [],
    taintFlows: [],
    dataProvenance: [],
    ifcBranches: [],
    persistentMemoryLabels: [],
    semanticActionGraph,
    dynamicSecurity: createDynamicSecurityState(),
  };
}

export function applyEffects(state: PolicyState, effects: PolicyEffects): void {
  if (effects.baseRevision !== state.sessionRevision) {
    throw new PolicyStateConflictError(effects.baseRevision, state.sessionRevision);
  }
  state.semanticActionGraph = structuredClone(effects.semanticActionGraph);
  state.apiCallCounts = new Map(effects.apiCallCounts);
  state.dataProvenance = structuredClone(effects.dataProvenance);
  state.taintFlows = structuredClone(effects.taintFlows);
  state.sessionRevision += 1;
}

export class PolicyStateConflictError extends Error {
  constructor(readonly expectedRevision: number, readonly actualRevision: number) {
    super(`Policy state changed during evaluation: expected revision ${expectedRevision}, received ${actualRevision}`);
    this.name = "PolicyStateConflictError";
  }
}

export function checkpointPolicyState(state: PolicyState): PolicyStateCheckpoint {
  return structuredClone({
    version: 1,
    created_at: new Date().toISOString(),
    currentTask: state.currentTask,
    taskSpec: state.taskSpec,
    authorizationState: state.authorizationState,
    contaminated: state.contaminated,
    provenanceBlocked: state.provenanceBlocked,
    provenanceFindings: state.provenanceFindings,
    history: state.history,
    toolResultLabels: [...state.toolResultLabels.entries()],
    exposures: state.exposures,
    apiCallCounts: [...state.apiCallCounts.entries()],
    behaviorProfiles: [...state.behaviorProfiles.entries()],
    runtimeProfiles: [...state.runtimeProfiles.entries()],
    trustLabels: state.trustLabels,
    aggregateRisk: state.aggregateRisk,
    taintedSources: state.taintedSources,
    taintFlows: state.taintFlows,
    dataProvenance: state.dataProvenance,
    ifcBranches: state.ifcBranches,
    persistentMemoryLabels: state.persistentMemoryLabels,
    semanticActionGraph: state.semanticActionGraph,
    dynamicSecurity: state.dynamicSecurity,
  } satisfies PolicyStateCheckpoint);
}

export function restorePolicyStateCheckpoint(state: PolicyState, checkpoint: PolicyStateCheckpoint | null | undefined): boolean {
  if (!checkpoint || checkpoint.version !== 1) return false;
  // A restore is a new mutation, never a rewind of the commit version.
  state.sessionRevision += 1;
  state.currentTask = checkpoint.currentTask;
  state.taskSpec = structuredClone(checkpoint.taskSpec);
  state.authorizationState = structuredClone(checkpoint.authorizationState);
  state.contaminated = checkpoint.contaminated;
  state.provenanceBlocked = checkpoint.provenanceBlocked;
  state.provenanceFindings = structuredClone(checkpoint.provenanceFindings);
  state.history = structuredClone(checkpoint.history);
  state.toolResultLabels = new Map(structuredClone(checkpoint.toolResultLabels));
  state.exposures = structuredClone(checkpoint.exposures);
  state.apiCallCounts = new Map(structuredClone(checkpoint.apiCallCounts));
  state.behaviorProfiles = new Map(structuredClone(checkpoint.behaviorProfiles));
  state.runtimeProfiles = new Map(structuredClone(checkpoint.runtimeProfiles));
  state.trustLabels = structuredClone(checkpoint.trustLabels);
  state.aggregateRisk = structuredClone(checkpoint.aggregateRisk);
  state.taintedSources = structuredClone(checkpoint.taintedSources);
  state.taintFlows = structuredClone(checkpoint.taintFlows);
  state.dataProvenance = structuredClone(checkpoint.dataProvenance);
  state.ifcBranches = structuredClone(checkpoint.ifcBranches);
  state.persistentMemoryLabels = structuredClone(checkpoint.persistentMemoryLabels);
  state.semanticActionGraph = restoreSemanticActionGraphMaps(structuredClone(checkpoint.semanticActionGraph));
  state.dynamicSecurity = structuredClone(checkpoint.dynamicSecurity);
  return true;
}

function restoreSemanticActionGraphMaps(graph: SemanticActionGraphState): SemanticActionGraphState {
  const pending = graph.pendingCalls instanceof Map
    ? graph.pendingCalls
    : new Map(Object.entries(graph.pendingCalls || {}) as Array<[string, string[]]>);
  const settled = graph.settledCalls instanceof Map
    ? graph.settledCalls
    : new Map(Object.entries(graph.settledCalls || {}) as Array<[string, string]>);
  return {
    ...graph,
    pendingCalls: pending,
    settledCalls: settled,
  };
}
