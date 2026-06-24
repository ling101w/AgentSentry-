from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from .config import RuntimePaths, ensure_runtime
from .cases import load_cases
from .evaluation import run_ablation, run_eval
from .export import cases_to_json, eval_results_to_csv, eval_results_to_markdown
from .models import RunRequest, RunResponse
from .policy import Policy
from .storage import Store
from .supervisor import AgentSupervisor
from .tools import SandboxTools


STATIC_DIR = Path(__file__).resolve().parent / "static"


@lru_cache
def paths() -> RuntimePaths:
    return ensure_runtime()


@lru_cache
def policy() -> Policy:
    return Policy.from_file(paths().policy)


@lru_cache
def store() -> Store:
    return Store(paths().database)


def create_app() -> FastAPI:
    app = FastAPI(title="AgentSentry", version="0.1.0")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        return (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    @app.post("/api/runs", response_model=RunResponse)
    def start_run(request: RunRequest) -> RunResponse:
        tools = SandboxTools(paths().sandbox, policy())
        supervisor = AgentSupervisor(store=store(), policy=policy(), tools=tools)
        return supervisor.run(request)

    @app.get("/api/llm/config")
    def llm_config():
        return {
            "configured": bool(os.getenv("OPENAI_API_KEY")),
            "base_url": os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1",
            "model": os.getenv("OPENAI_MODEL") or "gpt-4o-mini",
        }

    @app.get("/api/events")
    def events(limit: int = Query(default=200, ge=1, le=1000)):
        return store().list_events(limit=limit)

    @app.post("/api/eval/run")
    def eval_run(defense_mode: str = "full"):
        return run_eval(store(), policy(), paths().sandbox, defense_mode=defense_mode).model_dump()

    @app.post("/api/eval/ablation")
    def eval_ablation():
        return run_ablation(store(), policy(), paths().sandbox)

    @app.get("/api/eval/results")
    def eval_results(limit: int = Query(default=20, ge=1, le=100)):
        return store().list_eval_results(limit=limit)

    @app.get("/api/eval/export.csv", response_class=PlainTextResponse)
    def eval_export_csv(limit: int = Query(default=20, ge=1, le=100)):
        return PlainTextResponse(
            eval_results_to_csv(store().list_eval_results(limit=limit)),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=agentsentry-eval.csv"},
        )

    @app.get("/api/eval/report.md", response_class=PlainTextResponse)
    def eval_report_markdown(limit: int = Query(default=20, ge=1, le=100)):
        return PlainTextResponse(
            eval_results_to_markdown(store().list_eval_results(limit=limit)),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=agentsentry-eval-report.md"},
        )

    @app.get("/api/cases")
    def cases():
        return load_cases()

    @app.get("/api/cases/export.json")
    def cases_export_json():
        return Response(
            cases_to_json(load_cases()),
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=agentsentry-cases.json"},
        )

    @app.post("/api/reset")
    def reset():
        store().reset()
        return {"ok": True}

    return app


app = create_app()
