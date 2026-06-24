from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
CASE_PATH = ROOT / "cases" / "agentsentry_cases.yaml"


def load_cases(path: str | Path = CASE_PATH) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))

