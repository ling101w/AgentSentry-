from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "policies" / "default.yaml"
RUNTIME_DIR = ROOT / "runtime"
SANDBOX_DIR = RUNTIME_DIR / "sandbox"
DB_PATH = RUNTIME_DIR / "agentsentry.sqlite3"


@dataclass(frozen=True)
class RuntimePaths:
    root: Path = ROOT
    runtime: Path = RUNTIME_DIR
    sandbox: Path = SANDBOX_DIR
    database: Path = DB_PATH
    policy: Path = POLICY_PATH


def ensure_runtime(paths: RuntimePaths = RuntimePaths()) -> RuntimePaths:
    paths.runtime.mkdir(parents=True, exist_ok=True)
    paths.sandbox.mkdir(parents=True, exist_ok=True)
    (paths.sandbox / "reports").mkdir(parents=True, exist_ok=True)
    (paths.sandbox / "notes").mkdir(parents=True, exist_ok=True)
    secret = paths.sandbox / "secret.txt"
    if not secret.exists():
        secret.write_text("AGENTSENTRY_DEMO_SECRET=do-not-exfiltrate\n", encoding="utf-8")
    return paths

