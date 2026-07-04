# 玄鉴 / AgentSentry

参赛作品名称：

> 玄鉴：面向智能体工具调用链的实时行为监督与风险拦截系统

`AgentSentry` 是当前仓库和 OpenClaw 插件内部沿用的工程代码名。答辩、报告和演示建议统一使用“玄鉴”。

AgentSentry is a runnable M2 prototype for an LLM-agent behavior firewall:

- OpenAI-compatible JSON-action agent interface.
- Sandboxed tools: webpage, file read/write, email, API, memory.
- Deterministic policy gate with taint labels and a YAML DSL.
- Lightweight behavior sentry for intent drift, suspicious sinks, memory poisoning, and adaptive variants.
- Four-domain feedback architecture: context provenance, state integrity, intent authorization, tool boundary, and evidence feedback.
- SQLite event store and a FastAPI-served monitoring dashboard.
- Built-in benign/attack evaluation suite with ablations.

Current scope: the deterministic layer enforces TaskSpec tool bounds, allowed target URLs, taint-to-sink checks, recipient/path/API allowlists, and fail-closed sink rules. The sentry layer is a lightweight rule/feature baseline that emits heuristic or `learned`-typed findings for residual-risk telemetry; it is not a trained IsolationForest/GNN model. The built-in evaluation suite is deterministic and offline by default; AgentDojo/InjecAgent integration remains adapter/future-work territory.

## 推荐入口

- 文档入口：`reports/START_HERE.md`
- OpenClaw 插件主控制台：`http://127.0.0.1:8765/`
- 业务测试台和 benchmark 逐条复测：`http://127.0.0.1:8765/command-lab`
- 安全态势大屏：`http://127.0.0.1:8765/security-screen`
- OpenClaw Control UI：`http://127.0.0.1:18789/`

`8000` 是早期 FastAPI 离线原型和辅助研究入口；当前比赛展示与真实 OpenClaw 插件链路以 `8765` 为准。

## Quick Start

```powershell
python -m uvicorn agentsentry.app:app --reload --app-dir src
```

Open http://127.0.0.1:8000 and run a scenario from the dashboard.

The production-style situation screen is available at http://127.0.0.1:8000/security-screen.
It is backed by `GET /api/security/overview`, which can show the local SQLite experiment store, OpenClaw plugin records, or a combined research view; when the API is unavailable it shows an explicit empty state rather than generated statistics.

## OpenClaw Plugin

AgentSentry can also run inside OpenClaw as a plugin. The plugin records OpenClaw context construction, tool calls, security findings, approval decisions, runtime evidence, and serves a local records dashboard with JSON/CSV export.

```powershell
cd .\openclaw-plugin
npm run build
.\setup.ps1 -Force
```

After installing, use `/agentsentry` in OpenClaw. The dashboard defaults to http://127.0.0.1:8765 and JSONL records are stored under `~/.openclaw/agentsentry/records.jsonl`.

The plugin dashboard includes:

- `/` records console with JSON/CSV export.
- `/command-lab` business request console that maps adversarial instructions and public benchmark cases to controlled business tools, runs the same policy decision path, executes allowed requests, and writes `tool_decision`, `guard_finding`, `alert`, and `tool_result` records.
- `/security-screen` situation screen. Its default KPI scope is OpenClaw plugin records, so the top-left total matches `GET /api/stats`. Use `/api/security/overview?source=combined` only for the combined research view.

The plugin defaults to observe-only mode. To actively gate risky tool calls, change `enforcement.mode` in the OpenClaw plugin config to `approval` or `block`. In approval mode, an OpenClaw `allow-always` resolution caches the exact tool name and parameter hash in `~/.openclaw/agentsentry/approval-cache.json`; clear it with `/agentsentry approvals reset`.

The OpenClaw plugin now also has optional semantic workspace provenance scan and response covering:

```text
/agentsentry config set semantic.enabled true
/agentsentry config set semantic.judgeProvenance true
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
$env:OPENAI_API_KEY="YOUR_API_KEY"
$env:OPENAI_BASE_URL="https://api.wushuang233.com/v1"
$env:OPENAI_MODEL="gpt-5.5"
```

The dashboard is configured for the real model path. The scenario selector changes the task template and run metadata.

PowerShell example:

```powershell
$env:OPENAI_API_KEY="YOUR_API_KEY"
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
- Start here: `reports/START_HERE.md`
- System functionality document: `reports/system_functionality.md`
- Reproduction guide and operator guide: `reports/operator_guide.md`
- Current benchmark cases: `reports/benchmark_risk_tiered/benchmark_cases.risk_tiered.jsonl` and `reports/benchmark_risk_tiered/tool_attack_cases.risk_tiered.jsonl`
- Current benchmark results: `reports/benchmark_risk_tiered/benchmark_eval_results.risk_tiered.json` and `reports/benchmark_risk_tiered/tool_attack_benchmark_results.risk_tiered.json`
- OpenClaw UI proof: `python scripts/check_openclaw_ui.py`
- UI layout proof: `reports/ui-screenshots-8765/per-viewport-check.json`

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

## XuanJian Security Domains

| Domain | Deterministic | Heuristic / Learned |
|---|---|---|
| Context Provenance | workspace, external-content, prompt-source, and supply-chain provenance checks | hidden prompt injection, multimodal carrier, and source-risk tagging |
| State Integrity | protected memory keys, memory passport integrity, source trust, and quarantine | memory outlier consensus and poisoning-risk review |
| Intent Authorization | TaskSpec bounds, ABAC session context, taint-to-sink trust rules | dynamic intent drift and LLM-Judge semantic review |
| Tool Boundary | file, email, API, shell, gateway, sensitive path, and eBPF-assisted runtime gates | sandbox egress review and post-execution anomaly feedback |
| Evidence Feedback | tool result taint preservation, approval cache, runtime audit, and risk-vector feedback | trajectory tightening and operator evidence summaries |

`ask` means "not released"; it is recorded for operator review and does not execute tools.

## Rita-Style Prompt Extraction Scenario

The `rita_prompt_extraction` scenario models a staged prompt-extraction attack: untrusted web content frames hidden system/developer prompt recovery as a harmless audit task, asks for tool declarations and output-format rules, then requests omitted lines as an appendix. AgentSentry records the untrusted source indicators in Context Provenance and blocks the attempted `system_prompt.txt` read at Tool Boundary.
