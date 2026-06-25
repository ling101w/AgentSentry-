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

Offline demos and tests use the deterministic fake LLM. To use a real OpenAI-compatible endpoint, set:

```powershell
$env:OPENAI_API_KEY="sk-your-key"
$env:OPENAI_BASE_URL="https://api.wushuang233.com/v1"
$env:OPENAI_MODEL="gpt-5.5"
```

Then call `POST /api/runs` or `POST /api/runs/stream` with `use_fake_llm=false`.

In the dashboard, switch `Agent 来源` from `稳定演示 FakeLLM` to `真实 OpenAI-compatible LLM`.
The scenario selector stays available in real LLM mode: it changes the task template and run metadata, but does not select a deterministic fake script. Only `use_fake_llm=true` activates the built-in FakeLLM scenario scripts.

PowerShell example:

```powershell
$env:OPENAI_API_KEY="sk-..."
$env:OPENAI_BASE_URL="https://api.openai.com/v1"
$env:OPENAI_MODEL="gpt-4o-mini"
python -m uvicorn --app-dir src agentsentry.app:app --host 127.0.0.1 --port 8000
```

For compatible providers, either `https://host` or `https://host/v1` works; AgentSentry normalizes the chat-completions URL. The model must return one JSON action per step, for example:

```json
{"tool":"read_webpage","args":{"url":"mock://benign"},"reason":"read the page"}
```

## API

- `POST /api/runs` starts a supervised agent run.
- `GET /api/events` returns recent runs, alerts, decisions, and taint edges.
- `POST /api/eval/run?defense_mode=full` runs the built-in M2 evaluation suite.
- `GET /api/eval/results` returns saved metric summaries.
- `GET /api/eval/export.csv` exports evaluation metrics.
- `GET /api/cases` returns the Chinese security case suite.
- `GET /api/cases/export.json` exports the case suite.
- `POST /api/reset` clears local SQLite demo data.

## One-Click Demo

```powershell
python scripts/demo_run.py
```

Competition materials:

- Chinese case suite: `cases/agentsentry_cases.yaml`
- Report outline: `docs/report_outline.md`
- Demo script: `docs/demo_script.md`

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
