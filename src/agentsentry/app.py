from __future__ import annotations

import json
import threading
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

from . import __version__
from .config import RuntimePaths, ensure_runtime
from .cases import load_cases
from .evaluation import run_ablation, run_eval
from .export import cases_to_json, eval_results_to_csv, eval_results_to_markdown
from .llm import OpenAICompatibleClient
from .models import RunRequest, RunResponse, new_id
from .openclaw_evidence import openclaw_health, openclaw_records
from .policy import Policy
from .security_overview import security_overview
from .storage import Store
from .supervisor import AgentSupervisor
from .tools import SandboxTools


STATIC_DIR = Path(__file__).resolve().parent / "static"


class CachedStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            suffix = Path(path).suffix.lower()
            if suffix == ".html":
                response.headers["Cache-Control"] = "no-cache"
            elif path.startswith("vendor/"):
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            elif suffix in {".js", ".mjs", ".css", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".pdf"}:
                response.headers["Cache-Control"] = "public, max-age=3600, stale-while-revalidate=86400"
            else:
                response.headers.setdefault("Cache-Control", "no-cache")
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response


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
    app = FastAPI(title="AgentSentry", version=__version__)
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.mount("/static", CachedStaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> HTMLResponse:
        return HTMLResponse(
            (STATIC_DIR / "index.html").read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/security-screen", response_class=HTMLResponse)
    def security_screen() -> HTMLResponse:
        return HTMLResponse(
            (STATIC_DIR / "security-screen.html").read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/screen", response_class=HTMLResponse)
    def screen_alias() -> HTMLResponse:
        return HTMLResponse(
            (STATIC_DIR / "security-screen.html").read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-cache"},
        )

    @app.post("/api/runs", response_model=RunResponse)
    def start_run(request: RunRequest) -> RunResponse:
        tools = SandboxTools(paths().sandbox, policy())
        supervisor = AgentSupervisor(store=store(), policy=policy(), tools=tools)
        return supervisor.run(request)

    @app.post("/api/runs/stream")
    def start_run_stream(request: RunRequest):
        def stream():
            tools = SandboxTools(paths().sandbox, policy())
            supervisor = AgentSupervisor(store=store(), policy=policy(), tools=tools)
            done = threading.Event()
            result_holder: dict[str, object] = {}
            seen_event_ids: set[str] = set()
            last_event_rowid = 0
            run_id = request.run_id or new_id("run")
            stream_request = request.model_copy(update={"run_id": run_id})

            def worker() -> None:
                try:
                    result = supervisor.run(stream_request)
                    result_holder["result"] = result.model_dump()
                except Exception as exc:  # pragma: no cover - defensive streaming wrapper
                    result_holder["error"] = str(exc)
                finally:
                    done.set()

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            yield _stream_line("status", {"status": "started"})
            yield _stream_line(
                "run",
                {
                    "id": run_id,
                    "task": request.task,
                    "scenario": request.scenario,
                    "defense_mode": request.defense_mode,
                    "final_output": "",
                    "created_at": "",
                },
            )

            while not done.is_set():
                for event in store().list_run_events(run_id, after_rowid=last_event_rowid):
                    last_event_rowid = max(last_event_rowid, int(event.get("rowid", 0)))
                    if event["id"] not in seen_event_ids:
                        seen_event_ids.add(event["id"])
                        yield _stream_line("event", event)
                if done.wait(0.25):
                    break

            for event in store().list_run_events(run_id, after_rowid=last_event_rowid):
                last_event_rowid = max(last_event_rowid, int(event.get("rowid", 0)))
                if event["id"] not in seen_event_ids:
                    seen_event_ids.add(event["id"])
                    yield _stream_line("event", event)
            if "result" in result_holder:
                yield _stream_line("done", result_holder["result"])
            else:
                yield _stream_line("error", {"error": result_holder.get("error", "unknown stream error")})
            thread.join(timeout=0.1)

        return StreamingResponse(stream(), media_type="application/x-ndjson; charset=utf-8")

    @app.get("/api/llm/config")
    def llm_config():
        client = OpenAICompatibleClient()
        return {
            "configured": bool(client.api_key),
            "base_url": client.base_url,
            "model": client.model,
        }

    @app.get("/api/health")
    def health():
        client = OpenAICompatibleClient()
        openclaw = openclaw_health()
        return {
            "ok": True,
            "service": "AgentSentry",
            "runtime": {
                "database": str(paths().database),
                "sandbox": str(paths().sandbox),
                "policy": str(paths().policy),
            },
            "llm": {
                "configured": bool(client.api_key),
                "base_url": client.base_url,
                "model": client.model,
            },
            "openclaw": {
                "available": openclaw.get("available", False),
                "dashboard": openclaw.get("dashboard"),
                "records_path": openclaw.get("records_path"),
            },
        }

    @app.get("/api/openclaw/health")
    def openclaw_health_api():
        return openclaw_health()

    @app.get("/api/openclaw/records")
    def openclaw_records_api(limit: int = Query(default=500, ge=1, le=5000)):
        return openclaw_records(limit=limit)

    @app.get("/api/security/overview")
    def security_overview_api(source: str = Query(default="combined", pattern="^(combined|openclaw|local)$")):
        return security_overview(store(), source=source)

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


def _stream_line(event_type: str, payload: object) -> str:
    return json.dumps({"type": event_type, "payload": payload}, ensure_ascii=False) + "\n"


app = create_app()
