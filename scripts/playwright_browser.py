from __future__ import annotations

import os
from pathlib import Path

from playwright.sync_api import Browser, Error as PlaywrightError, Playwright


def launch_chromium(playwright: Playwright) -> Browser:
    """Launch bundled Chromium, then fall back to an installed browser."""
    try:
        return playwright.chromium.launch()
    except PlaywrightError as bundled_error:
        candidates = _browser_candidates()
        launch_errors: list[str] = []
        for executable in candidates:
            if not executable.is_file():
                continue
            try:
                return playwright.chromium.launch(executable_path=str(executable))
            except PlaywrightError as exc:
                launch_errors.append(f"{executable}: {exc}")

        detail = "\n".join(launch_errors)
        suffix = f"\nFallback launch errors:\n{detail}" if detail else ""
        raise RuntimeError(
            "No usable Chromium browser was found. Run `playwright install chromium` "
            "or set AGENTSENTRY_CHROMIUM_EXECUTABLE to a Chrome/Edge executable."
            f"{suffix}"
        ) from bundled_error


def _browser_candidates() -> list[Path]:
    program_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    program_files_x86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    configured = os.environ.get("AGENTSENTRY_CHROMIUM_EXECUTABLE", "").strip()

    raw_candidates = [
        configured,
        str(Path(program_files) / "Google/Chrome/Application/chrome.exe"),
        str(Path(program_files_x86) / "Google/Chrome/Application/chrome.exe"),
        str(Path(local_app_data) / "Google/Chrome/Application/chrome.exe") if local_app_data else "",
        str(Path(program_files) / "Microsoft/Edge/Application/msedge.exe"),
        str(Path(program_files_x86) / "Microsoft/Edge/Application/msedge.exe"),
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]

    unique: list[Path] = []
    seen: set[str] = set()
    for value in raw_candidates:
        if not value:
            continue
        path = Path(value).expanduser()
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique
