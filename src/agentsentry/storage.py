from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .models import EvalResult, Event, utc_now


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    task TEXT NOT NULL,
    scenario TEXT,
    defense_mode TEXT NOT NULL,
    final_output TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS eval_results (
    id TEXT PRIMARY KEY,
    suite TEXT NOT NULL,
    defense_mode TEXT NOT NULL,
    metrics TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def create_run(self, run_id: str, task: str, scenario: str | None, defense_mode: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (id, task, scenario, defense_mode, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    task = excluded.task,
                    scenario = excluded.scenario,
                    defense_mode = excluded.defense_mode,
                    final_output = ''
                """,
                (run_id, task, scenario, defense_mode, utc_now()),
            )

    def finish_run(self, run_id: str, final_output: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE runs SET final_output = ? WHERE id = ?", (final_output, run_id))

    def add_event(self, event: Event) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events (id, run_id, type, payload, created_at) VALUES (?, ?, ?, ?, ?)",
                (event.id, event.run_id, event.type, json.dumps(event.payload, ensure_ascii=False), event.created_at),
            )

    def list_events(self, limit: int = 200) -> dict[str, Any]:
        with self._connect() as conn:
            runs = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            ]
            events = []
            for row in conn.execute(
                "SELECT rowid, id, run_id, type, payload, created_at FROM events ORDER BY rowid DESC LIMIT ?",
                (limit,),
            ).fetchall():
                item = dict(row)
                item["payload"] = json.loads(item["payload"])
                events.append(item)
            return {"runs": runs, "events": events}

    def list_run_events(self, run_id: str, after_rowid: int = 0, limit: int = 1000) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rowid, id, run_id, type, payload, created_at
                FROM events
                WHERE run_id = ? AND rowid > ?
                ORDER BY rowid ASC
                LIMIT ?
                """,
                (run_id, after_rowid, limit),
            ).fetchall()
        events = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item["payload"])
            events.append(item)
        return events

    def save_eval(self, result: EvalResult) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO eval_results (id, suite, defense_mode, metrics, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    result.id,
                    result.suite,
                    result.defense_mode,
                    json.dumps(result.metrics, ensure_ascii=False),
                    result.created_at,
                ),
            )

    def list_eval_results(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM eval_results ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["metrics"] = json.loads(item["metrics"])
            results.append(item)
        return results

    def overview_snapshot(self, event_limit: int = 2000, run_limit: int = 200, eval_limit: int = 100) -> dict[str, Any]:
        with self._connect() as conn:
            runs = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?",
                    (run_limit,),
                ).fetchall()
            ]
            events = []
            for row in conn.execute("SELECT * FROM events ORDER BY created_at DESC LIMIT ?", (event_limit,)).fetchall():
                item = dict(row)
                item["payload"] = json.loads(item["payload"])
                events.append(item)
            eval_rows = conn.execute("SELECT * FROM eval_results ORDER BY created_at DESC LIMIT ?", (eval_limit,)).fetchall()
        evals = []
        for row in eval_rows:
            item = dict(row)
            item["metrics"] = json.loads(item["metrics"])
            evals.append(item)
        return {"runs": runs, "events": events, "evals": evals}

    def reset(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM runs")
            conn.execute("DELETE FROM eval_results")
