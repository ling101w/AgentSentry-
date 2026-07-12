# 玄鉴 / AgentSentry

参赛作品名称：

> 玄鉴：面向智能体工具调用链的实时行为监督与风险拦截系统

`AgentSentry` 是当前仓库和 OpenClaw 插件内部沿用的工程代码名。答辩、报告和演示建议统一使用“玄鉴”。

AgentSentry is a runnable OpenClaw supervision plugin for an LLM-agent tool chain:

- OpenAI-compatible JSON-action agent interface.
- Sandboxed tools: webpage, file read/write, email, API, memory.
- TaskSpec V2 explicit capability authorization with recipient, path, host, method, command, evidence, and expiry constraints.
- Field-level provenance and taint-to-sink checks, Tool Security Manifests, Memory Guard, and a monotonic semantic Judge.
- Lightweight statistical behavior baselines for intent drift and unusual tool trajectories. These are not trained anomaly models.
- Four-domain feedback architecture: context provenance, state integrity, intent authorization, tool boundary, and evidence feedback.
- SQLite event store and a FastAPI-served monitoring dashboard.
- Label-isolated regression/blind/benign/native evaluation protocol with ablations and confidence intervals.

Current scope: deterministic policy enforces explicit TaskSpec capabilities and fail-closed high-risk sinks. Findings are named `deterministic`, `heuristic`, `behavioral`, or `semantic`; the behavioral layer is an online statistical baseline, not IsolationForest/GNN. Historical AgentDojo/InjecAgent rows are public cases mapped into the local command-lab harness, not native benchmark execution. The native AgentDojo adapter and credential-free runtime contract are implemented, but the model-backed 120-trial result remains honestly marked `not_run` in `evaluation/native/agentdojo_results.json` until a clean release run is completed.

## 推荐入口

- 文档入口：`reports/START_HERE.md`
- OpenClaw 插件主控制台：`http://127.0.0.1:8765/`
- 业务测试台和 benchmark 逐条复测：`http://127.0.0.1:8765/command-lab`
- 安全态势大屏：`http://127.0.0.1:8765/security-screen`
- OpenClaw Control UI：`http://127.0.0.1:18789/`

`8000` 是早期 FastAPI 离线原型和辅助研究入口；当前比赛展示与真实 OpenClaw 插件链路以 `8765` 为准。

## Quick Start: OpenClaw Plugin

```powershell
cd .\openclaw-plugin
npm ci --legacy-peer-deps
npm run ci
.\setup.ps1 -Force
```

After OpenClaw loads the plugin, run:

```text
/agentsentry profile competition
/agentsentry status
```

Open `http://127.0.0.1:8765/`. The earlier FastAPI research prototype remains available on port `8000`, but it is not the competition's primary evidence chain.

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

The plugin defaults to observe-only mode. Use `/agentsentry profile competition` for the judged demo. In approval mode, `allow-always` caches the exact tool, normalized parameters, TaskSpec policy contract version, and security-relevant configuration fingerprint; clear it with `/agentsentry approvals reset`.

The OpenClaw plugin now also has optional semantic workspace provenance scan and response covering:

```text
/agentsentry config set semantic.enabled true
/agentsentry config set semantic.judgeProvenance true
/agentsentry config set responseCover.enabled true
```

Useful runtime commands:

```text
/agentsentry status
/agentsentry profile competition
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

## Evaluation Credibility

The archived 520 + 320 results are development regression runs made from public benchmark content mapped into `/command-lab`. They are useful for rule regression and ablation, but they do not establish unknown-attack generalization and must not be described as native AgentDojo/InjecAgent results.

The new protocol under `evaluation/` keeps labels in an evaluator-owned envelope. Only `user_message`, `tool_name`, `tool_args`, `tool_result`, and `session_history` cross the detector boundary. The real `evaluation/blind/blind_holdout.jsonl` is ignored by Git and must be supplied after the release commit is frozen.

Current evidence is intentionally incomplete: `evaluation/benign/realistic_benign_tasks.jsonl` contains six reviewed seed cases, not the planned 200-case benign suite. Native AgentDojo now has a fixed 20 benign + 20 attack-pair selection over three seeds and a verified runtime adapter, while the model-backed score is still `not_run`.

```powershell
python scripts/run_blind_evaluation.py
```

Native AgentDojo uses the official `agentdojo==0.1.35` environment and utility/security evaluators. Install the heavy optional dependency in a dedicated virtual environment, then verify the contract without model credentials:

```powershell
python -m pip install -e ".[dev,native-agentdojo]"
npm --prefix openclaw-plugin run build
python scripts/run_agentdojo_native.py --doctor
python scripts/run_agentdojo_native.py --plan
python scripts/run_agentdojo_native.py --contract
```

`--contract` executes a real read-only AgentDojo tool through the isolated Node policy process and checks the official utility evaluator. It is wiring evidence, not a benchmark score. A reportable run additionally requires a clean Git worktree, an explicit AgentDojo model, provider credentials, and `AGENTSENTRY_API_KEY` for the competition-profile Judge:

```powershell
$env:OPENAI_API_KEY="YOUR_MODEL_KEY"
$env:AGENTSENTRY_API_KEY="YOUR_JUDGE_KEY"
python scripts/run_agentdojo_native.py --model gpt-4o-mini-2024-07-18 --publish
```

The runner creates evaluator-private transcripts and labels only after detector subprocesses exit, under ignored `runtime/agentdojo/`. It publishes only aggregate metrics and hashes. AgentDojo `security=true` is treated as attack success (ASR), never as protection.

The runner refuses a dirty or non-Git workspace by default so results cannot be attributed to the wrong commit. `--allow-dirty` exists only for local pipeline development and records the dirty state in the report.

Default output contains aggregate metrics and the holdout hash, not per-case hidden labels. `--include-case-details` is for evaluator-private diagnostics and must not be published.

Reports include ASR, protection rate, FPR, Ask Rate, Utility, Overblocking Rate, P50/P95/P99 latency, Judge-call rate, token/cost fields, decision stability, and 95% Wilson intervals.

Repeated seeds remain visible as trials. Wilson intervals use conservative unique-case aggregation, and harness errors are reported separately rather than counted as protection or failure.

## Experiment Runner

```powershell
python scripts/run_competition_experiments.py
```

Competition materials:

- Chinese case suite: `cases/agentsentry_cases.yaml`
- Start here: `reports/START_HERE.md`
- System functionality document: `reports/system_functionality.md`
- Reproduction guide and operator guide: `reports/operator_guide.md`
- Label-isolated evaluation protocol: `evaluation/README.md`
- Current benchmark results: `reports/benchmark_risk_tiered/benchmark_eval_results.risk_tiered.json` and `reports/benchmark_risk_tiered/tool_attack_benchmark_results.risk_tiered.json`
- OpenClaw UI proof: `python scripts/check_openclaw_ui.py`
- UI layout proof: `reports/ui-screenshots-8765/per-viewport-check.json`

## Tests

```powershell
python -m pytest
cd openclaw-plugin
npm run ci
```

## Defense Modes

- `full`: deterministic gate, behavior sentry, and feedback tightening.
- `no_deterministic`: sentry only.
- `no_sentry`: deterministic gate only.
- `no_feedback`: deterministic gate plus sentry without feedback tightening.
- `none`: no deterministic or sentry defense.

## XuanJian Security Domains

| Domain | Deterministic | Heuristic / Behavioral / Semantic |
|---|---|---|
| Context Provenance | workspace, external-content, prompt-source, and supply-chain provenance checks | hidden prompt injection, multimodal carrier, and source-risk tagging |
| State Integrity | protected memory keys, memory passport integrity, source trust, and quarantine | memory outlier consensus and poisoning-risk review |
| Intent Authorization | TaskSpec bounds, ABAC session context, taint-to-sink trust rules | dynamic intent drift and LLM-Judge semantic review |
| Tool Boundary | file, email, API, shell, gateway, sensitive path, and eBPF-assisted runtime gates | sandbox egress review and post-execution anomaly feedback |
| Evidence Feedback | tool result taint preservation, approval cache, runtime audit, and risk-vector feedback | trajectory tightening and operator evidence summaries |

`ask` means "not released"; it is recorded for operator review and does not execute tools.

## Rita-Style Prompt Extraction Scenario

The `rita_prompt_extraction` scenario models a staged prompt-extraction attack: untrusted web content frames hidden system/developer prompt recovery as a harmless audit task, asks for tool declarations and output-format rules, then requests omitted lines as an appendix. AgentSentry records the untrusted source indicators in Context Provenance and blocks the attempted `system_prompt.txt` read at Tool Boundary.
