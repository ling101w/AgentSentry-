#!/usr/bin/env bash
set -euo pipefail

: "${QWEN_BASE_URL:?QWEN_BASE_URL is required}"
: "${QWEN_API_KEY:?QWEN_API_KEY is required}"

QWEN_MODEL="${QWEN_MODEL:-qwen3.6-27b}"
export QWEN_MODEL

export OPENCLAW_STATE_DIR="${DEEPTRAP_QWEN_STATE_DIR:-/tmp/agentsentry-deeptrap-qwen-20260815}"
mkdir -p "$OPENCLAW_STATE_DIR"

provider_json="$(python3 - <<'PY'
import json
import os

print(json.dumps({
    "baseUrl": os.environ["QWEN_BASE_URL"],
    "apiKey": {"source": "env", "provider": "default", "id": "QWEN_API_KEY"},
    "auth": "api-key",
    "api": "openai-completions",
    "timeoutSeconds": 120,
    "models": [{
        "id": os.environ["QWEN_MODEL"],
        "name": os.environ["QWEN_MODEL"],
        "api": "openai-completions",
        "contextWindow": 131072,
        "maxTokens": 16384,
    }],
}, separators=(",", ":")))
PY
)"

openclaw config set models.mode '"merge"' --strict-json
openclaw config set models.providers.qwen "$provider_json" --strict-json
openclaw config set agents.defaults.model.primary "\"qwen/${QWEN_MODEL}\"" --strict-json
openclaw config validate
openclaw models list | grep -F "qwen/${QWEN_MODEL}"
