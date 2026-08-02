import type { AuthorizationGraph, Capability } from "../policy/types.ts";

export function buildAuthorizationGraph(task: string, capabilities: Capability[]): AuthorizationGraph {
  const root = "task:current";
  const nodes: AuthorizationGraph["nodes"] = [{ id: root, kind: "task", value: task }];
  const edges: AuthorizationGraph["edges"] = [];
  capabilities.forEach((capability, index) => {
    const capabilityId = `capability:${index}:${capability.kind}`;
    nodes.push({ id: capabilityId, kind: "capability", value: capability.kind, capability_kind: capability.kind });
    edges.push({ from: root, to: capabilityId, relation: "grants" });
    capabilityScopes(capability).forEach((scope, scopeIndex) => {
      const scopeId = `scope:${index}:${scopeIndex}`;
      nodes.push({ id: scopeId, kind: "scope", value: scope, capability_kind: capability.kind });
      edges.push({ from: capabilityId, to: scopeId, relation: "scopes" });
    });
  });
  return { root, nodes, edges };
}

export function authorizationPath(graph: AuthorizationGraph, capabilityKind: Capability["kind"], scope = ""): string[] {
  const granted = graph.edges
    .filter((edge) => edge.from === graph.root && edge.relation === "grants")
    .map((edge) => graph.nodes.find((node) => node.id === edge.to))
    .find((node) => node?.capability_kind === capabilityKind);
  if (!granted) return [];
  const path = [graph.root, granted.id];
  if (!scope) return path;
  const scopeNode = graph.edges
    .filter((edge) => edge.from === granted.id && edge.relation === "scopes")
    .map((edge) => graph.nodes.find((node) => node.id === edge.to))
    .find((node) => node?.value === scope || node?.value === "*");
  if (scopeNode) path.push(scopeNode.id);
  return path;
}

function capabilityScopes(capability: Capability): string[] {
  if (capability.kind === "fs.read" || capability.kind === "fs.write") return capability.roots;
  if (capability.kind === "network.fetch") return capability.origins;
  if (capability.kind === "email.send") return capability.recipients || ["*"];
  if (capability.kind === "memory.read" || capability.kind === "memory.write") return [capability.namespace];
  return [];
}
