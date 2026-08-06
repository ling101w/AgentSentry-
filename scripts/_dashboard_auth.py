from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request


def dashboard_token() -> str:
    configured = os.environ.get("AGENTSENTRY_DASHBOARD_TOKEN", "").strip()
    if configured:
        return configured
    state_dir = Path(os.environ.get("OPENCLAW_STATE_DIR", "").strip() or Path.home() / ".openclaw")
    token_path = state_dir / "agentsentry" / "dashboard-session.key"
    try:
        return token_path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def dashboard_request(
    url: str,
    *,
    data: bytes | None = None,
    method: str | None = None,
    headers: dict[str, str] | None = None,
) -> Request:
    request_headers = dict(headers or {})
    token = dashboard_token()
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    return Request(url, data=data, method=method, headers=request_headers)


def dashboard_access_url(base_url: str, path: str = "/") -> str:
    target = f"{base_url.rstrip('/')}{path}"
    token = dashboard_token()
    if not token:
        return target
    separator = "&" if "?" in target else "?"
    return f"{target}{separator}{urlencode({'access_token': token})}"
