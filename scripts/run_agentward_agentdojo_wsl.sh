#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${AGENTDOJO_PYTHON:-/root/.venvs/agentsentry-agentdojo/bin/python}"
MODE="${1:-full}"
SMOKE_TRIALS="${AGENTWARD_SMOKE_TRIALS:-1}"

if [[ ! -x "${PYTHON}" ]]; then
  echo "AgentDojo Python environment not found: ${PYTHON}" >&2
  exit 2
fi

set -a
# shellcheck disable=SC1091
source "${ROOT}/.env"
set +a

export OPENAI_COMPATIBLE_BASE_URL="${baseurl}"
export OPENAI_COMPATIBLE_API_KEY="${key}"
export AGENT_WARD_API_KEY="${key}"
export AGENTWARD_JUDGE_PROVIDER="agentward-compatible"
export AGENTWARD_JUDGE_MODEL="deepseek/deepseek-v4-pro"
export AGENTWARD_JUDGE_API="openai-completions"
export AGENTWARD_JUDGE_BASE_URL="${baseurl}"
export AGENTWARD_JUDGE_TIMEOUT_MS="120000"
export AGENTWARD_JUDGE_MAX_TOKENS="2048"
export AGENTWARD_JUDGE_MAX_RETRIES="2"

args=(
  "${ROOT}/scripts/run_agentdojo_native.py"
  --defense agentward
  --model openai-compatible
  --model-id deepseek/deepseek-v4-pro
  --openai-compatible-system-role system
  --provider-timeout-seconds 120
  --provider-max-retries 2
  # The bridge can make three 120s Judge attempts when a response has no verdict.
  # Leave headroom for worker startup and response serialization.
  --bridge-timeout 390
  --allow-dirty
)

case "${MODE}" in
  smoke)
    if [[ ! "${SMOKE_TRIALS}" =~ ^[1-9][0-9]*$ ]]; then
      echo "AGENTWARD_SMOKE_TRIALS must be a positive integer" >&2
      exit 2
    fi
    args+=(--max-trials "${SMOKE_TRIALS}" --output-root "${ROOT}/runtime/agentward-agentdojo-smoke")
    ;;
  full)
    args+=(--output-root "${ROOT}/runtime/agentward-agentdojo-deepseek-v4-pro")
    ;;
  *)
    echo "Usage: $0 [smoke|full]" >&2
    exit 2
    ;;
esac

exec "${PYTHON}" "${args[@]}"
