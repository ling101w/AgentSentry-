# 玄鉴 / AgentSentry

参赛作品名称：

> 玄鉴：面向智能体工具调用链的实时行为监督与风险拦截系统

`AgentSentry` 是当前仓库和 OpenClaw 插件内部沿用的工程代码名。答辩、报告和演示建议统一使用“玄鉴”。

AgentSentry is a runnable OpenClaw supervision plugin for an LLM-agent tool chain:

- OpenAI-compatible JSON-action agent interface.
- Sandboxed tools: webpage, file read/write, email, API, memory.
- TaskSpec V2 explicit capability authorization with recipient, path, host, method, command, evidence, and expiry constraints.
- Session-scoped Semantic Action Graph V2 linking TaskSpec intent, capabilities, actions, field-level provenance, transformations, and sinks into evidence-qualified directed paths.
- Field-level taint-to-sink checks, Tool Security Manifests, Memory Guard, and a monotonic semantic Judge.
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

## Semantic Action Graph V2

AgentSentry deliberately keeps two semantic layers separate:

1. `core/action-semantics.ts` is a per-call fact extractor. It recursively inspects the current tool arguments, expands common encodings, and reports flat categories such as sensitive references, local reads, network writes, persistence, and privileged effects. It can detect a dangerous combination inside one attempted call, but it does not by itself prove causality across calls.
2. `core/semantic-action-graph.ts` is a session-scoped directed acyclic graph. It connects TaskSpec intent and explicit capabilities to tool actions, field-level provenance, transformations, and final sinks across the OpenClaw and Command Lab lifecycles.

The V2 topology uses five node types (`intent`, `capability`, `action`, `data`, `sink`) and nine directed edge types (`declares`, `governs`, `authorizes`, `constrains`, `requests`, `consumes`, `produces`, `derives`, `targets`). `constrains` preserves the relevant capability boundary when an action has a capability candidate but its concrete recipient, path, host, HTTP method, or command is outside that scope. This lets the graph distinguish a side effect with no explicit capability (`unauthorized_side_effect`) from a concrete target that exceeds an existing capability (`target_scope_mismatch`).

Action nodes use `proposed`, `awaiting_approval`, `blocked`, `executing`, `succeeded`, `failed`, and `observed` lifecycle states. Only a successful tool call creates a `produces` edge, so a denied or failed action cannot later appear as a valid data source. If a supposedly blocked call nevertheless reports success, the blocked node remains immutable: the graph records a lifecycle anomaly, creates a separate `observed` execution node with `post_block_execution` evidence, and emits a score-100 deterministic `enforcement_bypass / executed_after_block` finding. Replayed terminal callbacks are ignored, so the same result cannot append provenance, exposures, nodes, edges, or findings twice.

Every edge carries an evidence `basis` (`observed`, `decoded`, or `conservative`) and a confidence value. `exact` and `encoded_exact` matches support observed-grade deterministic lineage; substring/fuzzy matches do not. For example, when a secret field returned by `read_webpage` is consumed by `summarize_text` and becomes an opaque value such as `summary-ref-7f4a9c01`, the graph preserves it only as a conservative black-box hypothesis, not as proof that the output contains the secret. That graph evidence requests approval and, when enabled, semantic review. An independent hard rule, such as an exact taint-to-sink match or explicit authorization violation, may still make the merged final decision `deny`. Conversely, if only `$.public_summary` enters the transform, a secret sibling such as `$.account_token` is not connected.

When more than one directed route reaches the same sink, route selection is evidence-first: any fully observed/decoded route outranks every route containing a conservative edge; among eligible routes the graph maximizes the minimum edge confidence, then chooses the shortest deterministic route. Report limits are applied only after observed paths have been ranked ahead of conservative candidates, so a newer weak hypothesis cannot hide stronger causal evidence.

The graph stores hashes, fingerprints, JSON paths, classifications, tool names, and transformation labels rather than raw task text, tool arguments, or tool results. It is bounded and rejects cycles and dangling edges. OpenClaw derives a namespaced SHA-256 identity from the structured `(sessionKey, sessionId)` tuple, preventing tuple or raw-key collisions. At the 500-session limit it evicts only idle state; if every slot has in-flight graph/runtime work, it refuses the new session instead of allowing an untracked one.

Recent snapshots expose at most 36 nodes, 40 edges, and 6 complete paths under `trust.semantic_action_graph`, reserve active intent/capability/pending authorization context, and enforce a 64 KiB serialized hard limit. A separate Judge projection has a 2,400-byte UTF-8 default ceiling and degrades through smaller structured variants; the enclosing Judge envelope can assign it an even smaller sub-budget. It contains bounded authorization context, recent actions, causal paths, graph counts, and lifecycle anomalies rather than the full audit snapshot.

The dashboard API emits a sanitized causal subgraph with `trace_kind=attack`, `authorized`, or `enforcement_bypass`; bypass evidence takes precedence, followed by attack paths and then a precisely authorized allow trace. A long path remains connected by retaining its head and tail and inserting a synthetic collapsed node plus summary edges marked `display_only=true`, confidence `0`, so layout continuity is never mistaken for new evidence. On `/security-screen`, the existing 3D topology remains available under **态势**, while **因果** uses a topological DAG layout, fit/pan/zoom controls, and clickable node/edge inspection with upstream and downstream focus.

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
