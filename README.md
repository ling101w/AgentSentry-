# AgentSentry

AgentSentry is a runnable M2 prototype for an LLM-agent behavior firewall:

- OpenAI-compatible JSON-action agent interface.
- Sandboxed tools: webpage, file read/write, email, API, memory.
- Deterministic policy gate with taint labels and a YAML DSL.
- Lightweight behavior sentry for intent drift, suspicious sinks, memory poisoning, and adaptive variants.
- Two-dimensional defense framing: lifecycle interception layers x guarantee strength.
- SQLite event store and a FastAPI-served monitoring dashboard.
- Built-in benign/attack evaluation suite with ablations.

## Quick Start

```powershell
python -m uvicorn agentsentry.app:app --reload --app-dir src
```

Open http://127.0.0.1:8000 and run a scenario from the dashboard.

The production-style situation screen is available at http://127.0.0.1:8000/security-screen.
It is backed by `GET /api/security/overview`, which can show the local SQLite experiment store, OpenClaw plugin records, or a combined research view; when the API is unavailable it shows an explicit empty state rather than generated statistics.

## OpenClaw Plugin

AgentSentry can also run inside OpenClaw as a plugin, similar to AgentWard. The plugin records OpenClaw lifecycle events, tool calls, lightweight AgentSentry findings, approval decisions, and serves a local records dashboard with JSON/CSV export.

```powershell
cd .\openclaw-plugin
npm run build
.\setup.ps1 -Force
```

After installing, use `/agentsentry` in OpenClaw. The dashboard defaults to http://127.0.0.1:8765 and JSONL records are stored under `~/.openclaw/agentsentry/records.jsonl`.

The plugin dashboard includes:

- `/` records console with JSON/CSV export.
- `/command-lab` business request console that maps adversarial instructions to controlled business tools, runs the same policy decision path, executes allowed requests, and writes `tool_decision`, `guard_finding`, `alert`, and `tool_result` records.
- `/security-screen` situation screen. Its default KPI scope is OpenClaw plugin records, so the top-left total matches `GET /api/stats`. Use `/api/security/overview?source=combined` only for the combined research view.

The plugin defaults to observe-only mode. To actively gate risky tool calls, change `enforcement.mode` in the OpenClaw plugin config to `approval` or `block`. In approval mode, an OpenClaw `allow-always` resolution caches the exact tool name and parameter hash in `~/.openclaw/agentsentry/approval-cache.json`; clear it with `/agentsentry approvals reset`.

The OpenClaw plugin now also has optional AgentWard-style semantic foundation scan and response covering:

```text
/agentsentry config set semantic.enabled true
/agentsentry config set semantic.judgeFoundation true
/agentsentry config set responseCover.enabled true
```

Useful runtime commands:

```text
/agentsentry status
/agentsentry config get
/agentsentry config set enforcement.mode approval
/agentsentry approvals status
/agentsentry approvals reset
/agentsentry reset
```

To use a real OpenAI-compatible endpoint, set:

```powershell
$env:OPENAI_API_KEY="sk-your-key"
$env:OPENAI_BASE_URL="https://api.wushuang233.com/v1"
$env:OPENAI_MODEL="gpt-5.5"
```

The dashboard is configured for the real model path. The scenario selector changes the task template and run metadata.

PowerShell example:

```powershell
$env:OPENAI_API_KEY="sk-..."
$env:OPENAI_BASE_URL="https://api.openai.com/v1"
$env:OPENAI_MODEL="gpt-4o-mini"
python -m uvicorn --app-dir src agentsentry.app:app --host 127.0.0.1 --port 8000
```

For compatible providers, either `https://host` or `https://host/v1` works; AgentSentry normalizes the chat-completions URL. The model must return one JSON action per step, for example:

```json
{"tool":"call_api","args":{"url":"http://127.0.0.1:8765/api/health"},"reason":"check plugin health"}
```

## API

- `POST /api/runs` starts a supervised agent run.
- `GET /api/events` returns recent runs, alerts, decisions, and taint edges.
- `GET /api/security/overview?source=combined|openclaw|local` returns the real-time situation-screen aggregate for KPIs, topology nodes, alerts, stages, rules, timeline, and source metadata.
- `GET /api/health` returns service, LLM, runtime path, and OpenClaw availability status.
- `GET /api/openclaw/records` proxies recent OpenClaw plugin audit records when the plugin dashboard is reachable.
- `POST /api/eval/run?defense_mode=full` runs the built-in M2 evaluation suite.
- `GET /api/eval/results` returns saved metric summaries.
- `GET /api/eval/export.csv` exports evaluation metrics.
- `GET /api/cases` returns the Chinese security case suite.
- `GET /api/cases/export.json` exports the case suite.
- `POST /api/reset` clears local SQLite run records.

## Experiment Runner

```powershell
python scripts/run_competition_experiments.py
```

Competition materials:

- Chinese case suite: `cases/agentsentry_cases.yaml`
- System functionality document: `reports/system_functionality.md`
- Report outline: `docs/report_outline.md`
- Reproduction guide: `reports/operator_guide.md`
- Operator guide: `reports/operator_guide.md`
- OpenClaw UI proof: `python scripts/check_openclaw_ui.py`
- UI layout proof: `reports/ui-screenshots/layout-check.json`

## Tests

```powershell
pytest
```

## Defense Modes

- `full`: deterministic gate, behavior sentry, and feedback tightening.
- `no_deterministic`: sentry only.
- `no_sentry`: deterministic gate only.
- `no_feedback`: deterministic gate plus sentry without feedback tightening.
- `none`: no deterministic or sentry defense.

## Defense Matrix

| Layer | Deterministic | Heuristic / Learned |
|---|---|---|
| Foundation | config and sink coverage checks | baseline misconfiguration warnings |
| Input Sanitization | none | prompt-injection taint tagging |
| Cognition Protection | provenance-preserving memory labels | drift and poisoning hints |
| Decision Alignment | explicit task-intent mismatch | trajectory drift and feedback tightening |
| Execution Control | sink / path / host / taint hard blocks | risk scoring only after hard checks |

`ask` means "not released"; it is recorded for operator review and does not execute tools.

## Rita-Style Prompt Extraction Scenario

The `rita_prompt_extraction` scenario models a staged prompt-extraction attack: untrusted web content frames hidden system/developer prompt recovery as a harmless audit task, asks for tool declarations and output-format rules, then requests omitted lines as an appendix. AgentSentry records the untrusted prompt-extraction indicators at Input Sanitization and blocks the attempted `system_prompt.txt` read at Execution Control.
