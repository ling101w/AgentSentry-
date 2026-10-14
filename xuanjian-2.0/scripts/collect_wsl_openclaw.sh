#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
INPUT_DIR="${OPENCLAW_SESSIONS_DIR:-${HOME}/.openclaw/agents/main/sessions}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_PATH="${1:-${PROJECT_ROOT}/data/openclaw/wsl_sessions_${STAMP}.jsonl}"
REPORT_PATH="${OUTPUT_PATH%.jsonl}.quality.md"
QUEUE_PATH="${OUTPUT_PATH%.jsonl}.label_queue.jsonl"

if [[ ! -d "${INPUT_DIR}" ]]; then
  printf 'OpenClaw session directory not found: %s\n' "${INPUT_DIR}" >&2
  exit 2
fi

python3 "${PROJECT_ROOT}/scripts/convert_openclaw.py" \
  "${INPUT_DIR}" \
  "${OUTPUT_PATH}"

python3 "${PROJECT_ROOT}/scripts/openclaw_dataset_report.py" \
  "${OUTPUT_PATH}" \
  --report "${REPORT_PATH}" \
  --queue "${QUEUE_PATH}"
