# AgentSentry OpenClaw Plugin

This package embeds XuanJian/AgentSentry into OpenClaw as a local runtime supervision plugin:

- `openclaw.plugin.json` declares the plugin and config UI hints.
- `package.json` exposes `openclaw.extensions`.
- `dist/index.js` is built from the TypeScript source and loaded by OpenClaw.
- A local dashboard is served at `http://127.0.0.1:8765` by default.

## Install

PowerShell:

```powershell
cd E:\cslearn\AgentSentry\openclaw-plugin
.\setup.ps1 -Force
```

Bash:

```bash
cd /path/to/AgentSentry/openclaw-plugin
bash setup.sh --force
```

Then in OpenClaw:

```text
/agentsentry
```

The setup script uses `--dangerously-force-unsafe-install` because the plugin intentionally writes a local JSONL record file and starts a local HTTP dashboard. It also enables `plugins.entries.agent-sentry.hooks.allowConversationAccess` in `~/.openclaw/openclaw.json`, which is needed for TaskSpec inference and the dashboard timeline.

Runtime commands:

```text
/agentsentry status
/agentsentry profile competition
/agentsentry config get
/agentsentry config get enforcement.mode
/agentsentry config set enforcement.mode approval
/agentsentry config set enforcement.mode block
/agentsentry config set notifications.enableProactiveNotifications true
/agentsentry config set policy.allowlistedRecipients user@example.com,security@example.com
/agentsentry config set semantic.judgeProvenance true
/agentsentry config set responseCover.enabled true
/agentsentry approvals status
/agentsentry approvals reset
/agentsentry config reset
/agentsentry reset
```

Runtime config changes are persisted to:

```text
~/.openclaw/agentsentry/runtime-config.json
```

`/agentsentry config reset` removes that runtime override and returns to the OpenClaw/plugin startup config.

## What It Records

- prompt-build/session metadata
- LLM input events, without system prompt text by default
- user/assistant/tool-result message previews
- tool calls with redacted parameters
- AgentSentry lightweight findings and alerts
- tool completion or tool error events
- approval resolutions and `allow-always` cache hits

## Guard Capabilities

The OpenClaw plugin now ports the core AgentSentry guard model into TypeScript:

- TaskSpec V2 explicit capability extraction from the latest user message; quoted, negated, vague, memory-derived, and non-concrete side-effect requests do not grant authority
- workspace provenance scan for malicious `SKILL.md` files, risky configs, embedded secrets, and sensitive workspace files
- deterministic sink checks for email/message, file, API, shell, and sensitive asset access
- prompt-injection detection on messages and tool results
- field-level provenance IDs and taint feedback: only fields that actually influence a high-risk sink inherit taint
- session-scoped Semantic Action Graph V2 connecting intent, capability authorization, actions, field lineage, transformations, and sinks across tool calls
- SHA-256 digest-pinned Tool Security Manifests; unknown tools require approval and integrity changes block
- trajectory checks for repeated tool use
- normalized tool names so OpenClaw tools map onto AgentSentry actions
- isolated OpenAI-compatible semantic judge that emits `semantic` findings and can only tighten deterministic decisions
- optional semantic workspace provenance scan for `SKILL.md` and configuration files
- policy-versioned exact-operation approval cache: `allow-always` matches the same tool, normalized parameters, and security configuration only
- persistent approval cache stored at `~/.openclaw/agentsentry/approval-cache.json`
- optional response covering after contaminated tool results

## Semantic Action Graph V2

The plugin has two complementary components whose names should not be conflated:

- `core/action-semantics.ts` extracts a flat set of semantic facts from one tool call. It recognizes operations, sensitive references, external sinks, persistence, local reads, network writes, privilege effects, benign capability claims, and decoded variants in the current arguments.
- `core/semantic-action-graph.ts` maintains the real session DAG. It joins TaskSpec intent and capabilities, attempted actions, field-level provenance, transformations, and final sinks across multiple calls.

The session DAG contains `intent`, `capability`, `action`, `data`, and `sink` nodes. Its nine directed edge types are `declares`, `governs`, `authorizes`, `constrains`, `requests`, `consumes`, `produces`, `derives`, and `targets`. When a related capability exists but the attempted recipient, attachment/path, host, HTTP method, or command falls outside its constraints, `capability -> action` is retained as `constrains` rather than misreported as authorization. The graph therefore separates `unauthorized_side_effect` (no explicit side-effect capability) from `target_scope_mismatch` (a concrete target exceeds an existing capability).

Action lifecycle states are `proposed`, `awaiting_approval`, `blocked`, `executing`, `succeeded`, `failed`, and `observed`. A `produces` edge is added only after successful execution; blocked and failed calls cannot become data sources. A successful callback received after a block does not rewrite the blocked node: the plugin records a lifecycle anomaly, represents the unexpected execution as a separate synthetic `observed` node with reason `post_block_execution`, and emits a score-100 deterministic finding with `event=enforcement_bypass` and `execution_status=executed_after_block`. Subsequent replays of that terminal result return no new finding and do not grow provenance, exposure, node, or edge state.

Every edge records a `basis` (`observed`, `decoded`, or `conservative`) and confidence. `exact` and `encoded_exact` input matches support observed-grade deterministic lineage. Substring/fuzzy matches and opaque black-box propagation are conservative evidence: they request approval and, when enabled, semantic review instead of claiming that the graph proved the flow. Independent hard rules remain separate and may still make the merged result `deny`.

Directed route selection prefers evidence strength over convenience. If any route from a source to a sink contains no conservative edge, routes containing conservative edges are excluded. The remaining route maximizes bottleneck confidence and then minimizes hop count with deterministic tie-breaking. Across candidate risk sources, observed paths rank before conservative paths and higher-confidence paths rank next before the six-path report bound is applied.

For transformations, lineage is routed through `input data -> action -> output data`. If a secret webpage field becomes an opaque summary reference and that reference is later sent externally, the graph retains a conservative source-to-sink hypothesis even though the output has no sensitive keyword; it does not describe that hypothesis as observed fact. Provenance remains field-specific: consuming `$.public_summary` does not connect an unrelated secret sibling such as `$.account_token`.

The graph itself stores no raw user task, tool argument, or tool result. It keeps bounded hashes, fingerprints, JSON paths, classifications, tool names, and transformation labels and validates cycles and dangling edges. Session state uses a `session:`-namespaced SHA-256 of the structured `(sessionKey, sessionId)` tuple. The 500-session cache never evicts an in-flight graph call or runtime checkpoint; when all slots are busy, the plugin fails closed for a new session rather than running it without tracked state.

`policyTrustSnapshot()` publishes at most 36 nodes, 40 edges, and 6 complete paths in `semantic_action_graph`, reserving active authorization nodes before recent supporting data. Serialized output has a 64 KiB hard limit and degrades to a truncated/minimal snapshot rather than exceeding it. Long report lists keep their head and tail, including the final sink, while findings expose a bounded `causal_chain` plus path certainty and confidence for audit consumers.

`semanticActionGraphJudgeProjection()` is separate from the audit snapshot. Its default serialized ceiling is 2,400 UTF-8 bytes, it progressively reduces paths/actions/capabilities/anomalies when needed, and the surrounding Judge envelope may provide a smaller sub-budget (currently capped at 1,800 bytes). This keeps graph context structured and bounded without sending the full session graph to the Judge.

The dashboard also receives only a sanitized connected projection, not the raw session graph. Its `trace_kind` is `attack`, `authorized`, or `enforcement_bypass`; bypass wins over attack, and attack wins over a normal authorized trace. Paths longer than the display budget retain their source and sink and replace the middle with a synthetic collapsed node and summary edges. Every such bridge is explicitly `display_only=true`, synthetic, conservative, and confidence `0`, so it cannot be interpreted as additional lineage evidence. `/security-screen` renders this projection in the **因果** tab using topological ranks and barycentric layer ordering, supports fit/pan/wheel or button zoom, and lets operators click a node or edge to inspect sanitized evidence and focus its upstream/downstream chain. The original **态势** 3D topology is unchanged.

Records are stored as JSONL at:

```text
~/.openclaw/agentsentry/records.jsonl
```

The dashboard can also export recent records:

```text
http://127.0.0.1:8765/api/export?format=json&limit=5000
http://127.0.0.1:8765/api/export?format=csv&limit=5000
```

## Enforcement

Default mode is `observe`, so the plugin records and alerts without changing OpenClaw behavior.

You can switch `enforcement.mode` in OpenClaw plugin config:

- `observe`: record only
- `approval`: ask approval for high-risk tool calls
- `block`: block high-risk tool calls

Named postures are available under `profiles/`:

```text
/agentsentry profile observe
/agentsentry profile balanced
/agentsentry profile competition
/agentsentry profile high-security
```

Proactive notifications are disabled by default. Enable them with:

```text
/agentsentry config set notifications.enableProactiveNotifications true
```

Notifications are best-effort and currently route through OpenClaw channels when the session provider is `qqbot` or `feishu`.

## Semantic Judge

Semantic judging is disabled by default. It uses an OpenAI-compatible `/chat/completions` endpoint and silently falls back to rule-based detection if the API key or network is unavailable.

```text
/agentsentry config set semantic.enabled true
/agentsentry config set semantic.baseUrl https://api.openai.com/v1
/agentsentry config set semantic.model gpt-4o-mini
/agentsentry config set semantic.apiKeyEnv AGENTSENTRY_API_KEY
/agentsentry config set semantic.judgeProvenance true
```

PowerShell example:

```powershell
$env:AGENTSENTRY_API_KEY="sk-..."
```

For DeepSeek-compatible usage:

```text
/agentsentry config set semantic.baseUrl https://api.deepseek.com/v1
/agentsentry config set semantic.model deepseek-chat
```

## Response Cover

Response covering is disabled by default. Enable it when you want AgentSentry to replace the next assistant response after contaminated tool output is detected:

```text
/agentsentry config set responseCover.enabled true
/agentsentry config set responseCover.message AgentSentry detected contaminated tool output; review the dashboard before trusting this turn.
```

## Development

```powershell
npm run build
npm run typecheck
npm run lint
npm run test:coverage
npm run test:policy
npm run ci
node -e "import('./dist/index.js').then(m => console.log(m.default.id))"
```
