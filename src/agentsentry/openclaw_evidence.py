from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


OPENCLAW_DASHBOARD = "http://127.0.0.1:8765"


def openclaw_records(limit: int = 500) -> dict[str, Any]:
    records, source = _load_records(limit)
    return {
        "available": bool(records),
        "source": source,
        "count": len(records),
        "records": records[:limit],
        "stats": _stats(records),
    }


def openclaw_health() -> dict[str, Any]:
    health = _dashboard_json("/api/health")
    stats = _dashboard_json("/api/stats")
    records_path = health.get("recordsPath") if isinstance(health, dict) else None
    return {
        "available": bool(health or stats or _default_records_path().exists()),
        "dashboard": OPENCLAW_DASHBOARD,
        "health": health,
        "stats": stats,
        "records_path": records_path or str(_default_records_path()),
    }


def _load_records(limit: int) -> tuple[list[dict[str, Any]], str]:
    dashboard = _dashboard_json(f"/api/records?limit={limit}")
    records = dashboard.get("records") if isinstance(dashboard, dict) else None
    if isinstance(records, list) and records:
        return [_redact(item) for item in records if isinstance(item, dict)], f"{OPENCLAW_DASHBOARD}/api/records"

    health = _dashboard_json("/api/health")
    records_path = health.get("recordsPath") if isinstance(health, dict) else None
    if isinstance(records_path, str):
        records = _load_jsonl(Path(records_path), limit)
        if records:
            return records, records_path

    default_path = _default_records_path()
    records = _load_jsonl(default_path, limit)
    return records, str(default_path) if records else ""


def _dashboard_json(path: str) -> dict[str, Any]:
    try:
        with urlopen(f"{OPENCLAW_DASHBOARD}{path}", timeout=1.5) as response:
            value = json.loads(response.read().decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, URLError, json.JSONDecodeError):
        return {}


def _load_jsonl(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    records: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(_redact(item))
    return list(reversed(records))


def _stats(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "by_type": dict(Counter(str(item.get("type", "unknown")) for item in records)),
        "by_severity": dict(Counter(str(item.get("severity", "unknown")) for item in records)),
        "by_layer": dict(Counter(str(item.get("layer", "unknown")) for item in records)),
    }


def _default_records_path() -> Path:
    return Path.home() / ".openclaw" / "agentsentry" / "records.jsonl"


def _redact(record: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(record, ensure_ascii=False)
    import re

    text = re.sub(r"sk-[A-Za-z0-9_-]{12,}", "sk-***redacted***", text)
    return json.loads(text)
