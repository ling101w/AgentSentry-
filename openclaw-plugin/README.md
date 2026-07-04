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

- TaskSpec inference from the latest user message
- workspace provenance scan for malicious `SKILL.md` files, risky configs, embedded secrets, and sensitive workspace files
- deterministic sink checks for email/message, file, API, shell, and sensitive asset access
- prompt-injection detection on messages and tool results
- taint feedback: contaminated tool results tighten later high-risk sinks
- trajectory checks for repeated tool use
- normalized tool names so OpenClaw tools map onto AgentSentry actions
- optional OpenAI-compatible semantic judge that emits `learned` findings for tool calls and messages
- optional semantic workspace provenance scan for `SKILL.md` and configuration files
- exact-operation approval cache: when an OpenClaw approval is resolved as `allow-always`, the same tool name and parameter hash is allowed without repeated approval
- persistent approval cache stored at `~/.openclaw/agentsentry/approval-cache.json`
- optional response covering after contaminated tool results

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
npm run test:policy
node -e "import('./dist/index.js').then(m => console.log(m.default.id))"
```
