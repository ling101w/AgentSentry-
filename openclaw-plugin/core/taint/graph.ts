import type { PolicyEffect, PolicyState, ProvenanceEdge, ProvenanceGraph, ProvenanceNode, TaintFlow } from "../policy/types.ts";

export function createProvenanceGraph(): ProvenanceGraph {
  return { nodes: new Map(), edges: [] };
}

export function applyGraphEffect(state: PolicyState, effect: PolicyEffect): boolean {
  if (effect.type === "graph.node") {
    state.provenanceGraph.nodes.set(effect.node.id, effect.node);
    return true;
  }
  if (effect.type === "graph.edge") {
    rememberEdge(state.provenanceGraph, effect.edge);
    return true;
  }
  if (effect.type === "taint.flow") {
    rememberFlow(state, effect.flow);
    return true;
  }
  return false;
}

export function graphEffectsForFlow(input: {
  sourceNode: string;
  source: string;
  labelId: string;
  actionId: number;
  tool: string;
  arg: string;
  flow: TaintFlow;
}): PolicyEffect[] {
  const argNode = `tool_arg:${input.actionId}:${input.tool}:${input.arg}`;
  const sinkNode = `sink:${input.actionId}:${input.tool}`;
  const nodes: ProvenanceNode[] = [
    { id: input.sourceNode, kind: "tool_result", label_id: input.labelId, source: input.source },
    { id: argNode, kind: "tool_arg", label_id: input.labelId, source: input.source, tool: input.tool, arg: input.arg },
    { id: sinkNode, kind: "sink", tool: input.tool },
  ];
  const edges: ProvenanceEdge[] = [
    { from: input.sourceNode, to: argNode, relation: "used_in" },
    { from: argNode, to: sinkNode, relation: "reaches" },
  ];
  return [
    ...nodes.map((node): PolicyEffect => ({ type: "graph.node", node })),
    ...edges.map((edge): PolicyEffect => ({ type: "graph.edge", edge })),
    { type: "taint.flow", flow: { ...input.flow, path: [input.sourceNode, argNode, sinkNode] } },
  ];
}

function rememberEdge(graph: ProvenanceGraph, edge: ProvenanceEdge): void {
  const key = `${edge.from}:${edge.to}:${edge.relation}`;
  if (!graph.edges.some((item) => `${item.from}:${item.to}:${item.relation}` === key)) graph.edges.push(edge);
  if (graph.edges.length > 240) graph.edges = graph.edges.slice(-240);
}

function rememberFlow(state: PolicyState, flow: TaintFlow): void {
  const key = `${flow.label_id}:${flow.sink}:${flow.path.join(">")} `;
  if (!state.taintFlows.some((item) => `${item.label_id}:${item.sink}:${item.path.join(">")} ` === key)) state.taintFlows.push(flow);
  if (state.taintFlows.length > 80) state.taintFlows = state.taintFlows.slice(-80);
}
