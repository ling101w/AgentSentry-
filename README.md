# AgentSentry

AgentSentry is a runnable M2 prototype for an LLM-agent behavior firewall:

- OpenAI-compatible JSON-action agent interface.
- Sandboxed tools: webpage, file read/write, email, API, memory.
- Deterministic policy gate with taint labels and a YAML DSL.
- Lightweight behavior sentry for intent drift, suspicious sinks, memory poisoning, and adaptive variants.
- SQLite event store and a FastAPI-served monitoring dashboard.
- Built-in benign/attack evaluation suite with ablations.

## Quick Start

```powershell
python -m uvicorn agentsentry.app:app --reload --app-dir src
```

Open http://127.0.0.1:8000 and run a scenario from the dashboard.

Offline demos and tests use the deterministic fake LLM. To use a real OpenAI-compatible endpoint, set:

```powershell
$env:OPENAI_API_KEY="..."
$env:OPENAI_BASE_URL="https://api.openai.com/v1"
$env:OPENAI_MODEL="gpt-4o-mini"
```

Then call `POST /api/runs` with `use_fake_llm=false` and no fixed `scenario`.

In the dashboard, switch `Agent 来源` from `稳定演示 FakeLLM` to `真实 OpenAI-compatible LLM`.
When using the real LLM mode, `scenario` is intentionally sent as `null`; otherwise the deterministic demo script would be selected.

PowerShell example:

```powershell
$env:OPENAI_API_KEY="sk-..."
$env:OPENAI_BASE_URL="https://api.openai.com/v1"
$env:OPENAI_MODEL="gpt-4o-mini"
python -m uvicorn --app-dir src agentsentry.app:app --host 127.0.0.1 --port 8000
```

For compatible providers, keep the `/v1` style base URL if the provider follows the OpenAI chat-completions API. The model must return one JSON action per step, for example:

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
