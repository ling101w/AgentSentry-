import { createHash } from "node:crypto";
import type { PluginConfig } from "../config.ts";
import { canonicalServiceEndpoint, parseNamedServiceBindings, type NamedServiceBinding } from "./named-service-config.ts";
import { analysisOnly, negatedAction, normalizeTaskText, splitClauses } from "./task-spec/extractor.ts";
import { conditionalFileInstruction } from "./task-spec/file-instructions.ts";
import type { CapabilityActionRequest, CapabilityAuthorization, TaskCapability, TaskSpec } from "./task-spec/types.ts";
import { resolveToolManifest } from "./tool-manifest.ts";

const URL_FIELDS = ["url", "uri", "href", "endpoint", "target"];
const METHOD_FIELDS = ["method", "httpMethod", "verb"];

export function trustedNamedServices(config: PluginConfig): NamedServiceBinding[] {
  const configured = parseNamedServiceBindings(config.policy.namedServices);
  if (!configured) return [];
  const host = config.dashboard.host.toLowerCase();
  const localHost = host === "localhost" ? "localhost" : ["127.0.0.1", "0.0.0.0"].includes(host) ? "127.0.0.1"
    : ["::1", "[::1]", "::", "[::]"].includes(host) ? "[::1]" : "";
  if (config.dashboard.enabled && localHost && Number.isInteger(config.dashboard.port) && config.dashboard.port > 0 && config.dashboard.port <= 65535) {
    const builtin: NamedServiceBinding = {
      id: "agentsentry-dashboard-health", purpose: "health_read",
      names: ["AgentSentry", "玄鉴", "本地 API", "本地API", "local API"],
      endpoint: `http://${localHost}:${config.dashboard.port}/api/health`,
    };
    if (configured.some((service) => service.id === builtin.id)) return [];
    return [builtin, ...configured];
  }
  return configured;
}

/** Request-local grants are absent from committed TaskSpec/checkpoints, so
 * revocation and endpoint changes take effect on the next evaluation. */
export function withNamedServiceCapabilities(spec: TaskSpec, config: PluginConfig, trustedUserTask: string): TaskSpec {
  if (!trustedUserTask || trustedUserTask !== spec.task || spec.denied_tools.includes("call_api")) return spec;
  const services = trustedNamedServices(config);
  const clauses = splitClauses(normalizeTaskText(trustedUserTask));
  const capabilities: TaskCapability[] = [];
  for (const clause of clauses) {
    const instruction = clause.text;
    if (clause.dataOnly || analysisOnly(instruction) || conditionalFileInstruction(instruction)
      || negatedAction(instruction, "read") || negatedAction(instruction, "request")
      || /(?:审批|批准|获批|\b(?:approval|approved|if|unless)\b)/i.test(instruction)
      || !/(?:健康检查|健康状态|服务正常|\bhealth\b)/i.test(instruction)
      || !/(?:调用|检查|查询|查看|请求|检测|确认|\b(?:check|get|fetch|read|query|verify|inspect|request|call)\b)/i.test(instruction)) continue;
    const matched = services.filter((service) => service.names.some((name) => mentionsName(instruction, name)));
    if (matched.length !== 1) continue;
    const service = matched[0];
    if (clauses.some((other) => !other.dataOnly && prohibitsService(other.text, service))) continue;
    const urls = instruction.match(/https?:\/\/[^\s，。；;,"'`]+/gi) || [];
    if (urls.some((url) => canonicalServiceEndpoint(url.replace(/[.!?]+$/, "")) !== service.endpoint)) continue;
    const binding = { id: service.id, endpoint: service.endpoint, purpose: service.purpose };
    capabilities.push({
      action: "read", resourceType: "api", effect: "read_only", targets: [service.endpoint],
      constraints: { allowedMethods: ["GET"], allowedHosts: [new URL(service.endpoint).hostname], namedService: binding },
      bound: { urls: [service.endpoint] }, capabilityId: `named-service:${hash(JSON.stringify({ service, instruction }))}`,
      evidence: { sourceMessageHash: hash(trustedUserTask), source: "user", explicitSpan: instruction.trim().slice(0, 320),
        explicitAuthorization: true, insideQuotation: false, negated: false, targetIsConcrete: true, confidence: 1 },
      expiresAfterTurn: 12,
    });
  }
  if (!capabilities.length) return spec;
  const tools = new Set([...spec.allowed_tools, "call_api", "read_webpage"].filter((tool) => !spec.denied_tools.includes(tool)));
  return { ...spec, capabilities: [...spec.capabilities, ...capabilities], allowed_tools: [...tools],
    forbidden_tools: spec.forbidden_tools.filter((tool) => !tools.has(tool)),
    allowed_targets: [...new Set([...spec.allowed_targets, ...capabilities.flatMap((capability) => capability.targets)])],
    ...(!spec.capabilities.length ? { task_family: "read_only" as const, task_confidence: 1 } : {}) };
}

export function authorizeNamedServiceArguments(capability: TaskCapability, request: CapabilityActionRequest): CapabilityAuthorization {
  const binding = capability.constraints.namedService;
  const deny = (reason: string): CapabilityAuthorization => ({ action: "deny", authorized: false, reason, capability });
  if (!binding || binding.purpose !== "health_read" || capability.effect !== "read_only"
    || !["call_api", "read_webpage"].includes(request.tool)) return deny("named_service_contract_mismatch");
  const envelope = resolveToolManifest(request.originalTool || request.tool);
  if (!envelope || envelope.issuer !== "builtin" || envelope.manifest.toolId !== request.tool) return deny("named_service_tool_contract_mismatch");
  const issue = namedServiceRequestError(binding.endpoint, request.args);
  if (issue) return deny(issue);
  if (capability.targets.length !== 1 || capability.targets[0] !== binding.endpoint
    || capability.constraints.allowedMethods?.length !== 1 || capability.constraints.allowedMethods[0] !== "GET"
    || !capability.bound?.urls?.includes(binding.endpoint)) return deny("named_service_contract_mismatch");
  return { action: "allow", authorized: true, reason: "explicit_named_service_binding_match", capability };
}

export function namedServiceRequestError(endpoint: string, args: Record<string, unknown>): string | undefined {
  if (Object.keys(args).some((key) => ![...URL_FIELDS, ...METHOD_FIELDS, "reason"].includes(key))
    || (args.reason !== undefined && typeof args.reason !== "string")) return "named_service_unrecognized_argument";
  const urls = URL_FIELDS.filter((key) => args[key] !== undefined).map((key) => args[key]);
  if (!urls.length || urls.some((url) => typeof url !== "string" || canonicalServiceEndpoint(url) !== endpoint)) return "named_service_target_mismatch";
  if (METHOD_FIELDS.some((key) => args[key] !== undefined && (typeof args[key] !== "string"
    || String(args[key]).trim().toUpperCase() !== "GET"))) return "named_service_method_mismatch";
  return undefined;
}

function mentionsName(instruction: string, name: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s*");
  return new RegExp(`(?<![A-Za-z0-9_])${escaped}(?![A-Za-z0-9_])`, "i").test(instruction);
}

function prohibitsService(instruction: string, service: NamedServiceBinding): boolean {
  const networkBan = /(?:不要|不得|禁止|不能).{0,30}(?:联网|网络请求|API|接口)|\b(?:do not|don't|never|no)\b.{0,35}\b(?:network|APIs?|HTTP)\b/i.test(instruction);
  return networkBan || (negatedAction(instruction, "read") || negatedAction(instruction, "request"))
    && service.names.some((name) => mentionsName(instruction, name));
}

function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
