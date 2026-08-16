#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-smoke}"
STATE="${DEEPTRAP_AGENTWARD_STATE_DIR:-/tmp/agentsentry-deeptrap-agentward-deepseek-v4-flash-20260816-rerun6}"
MODEL="${DEEPTRAP_AGENTWARD_MODEL:-deepseek-v4-flash}"
OUT_ROOT="${DEEPTRAP_AGENTWARD_OUTPUT_ROOT:-${ROOT}/outputs/deeptrap-deepseek-v4-flash-agentward-rerun1}"
ENV_FILE="${DEEPTRAP_AGENTWARD_ENV_FILE:-${ROOT}/.env}"

case "${MODE}" in
  smoke)
    SUITE="${DEEPTRAP_AGENTWARD_SMOKE_SUITE:-task_R1_T01}"
    OUT_ROOT="${DEEPTRAP_AGENTWARD_SMOKE_OUTPUT_ROOT:-${ROOT}/outputs/deeptrap-deepseek-v4-flash-agentward-smoke-rerun4}"
    ;;
  full)
    SUITE="all"
    ;;
  *)
    echo "Usage: $0 [smoke|full]" >&2
    exit 2
    ;;
esac

if [[ -e "${STATE}" ]]; then
  echo "Refusing to reuse existing state directory: ${STATE}" >&2
  exit 2
fi

mkdir -p "${STATE}" "${OUT_ROOT}"
export OPENCLAW_STATE_DIR="${STATE}"

exec > >(tee -a "${OUT_ROOT}/run.stdout.log") \
  2> >(tee -a "${OUT_ROOT}/run.stderr.log" >&2)

echo "=== DeepTrap AgentWard ${MODE} run started at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

snapshot_run() {
  mkdir -p "${OUT_ROOT}/audit"
  if [[ -f "${STATE}/openclaw.json" ]]; then
    cp "${STATE}/openclaw.json" "${OUT_ROOT}/audit/openclaw.json"
  fi
  if [[ -d "${STATE}/agentward" ]]; then
    cp -a "${STATE}/agentward" "${OUT_ROOT}/audit/agentward"
  fi
}
trap snapshot_run EXIT

# OpenClaw isolates plugin discovery with OPENCLAW_STATE_DIR. Copy the
# installed AgentWard package into this run's extension root so that the
# allow-list resolves to the intended plugin instead of a stale entry.
mkdir -p "${STATE}/extensions"
cp -a /root/.openclaw/extensions/agent-ward "${STATE}/extensions/agent-ward"

# AgentWard 2026.5.9 implements approval settings but its published manifest
# omits the matching JSON Schema entry. Repair only the isolated run copy so
# OpenClaw can validate the headless-deny configuration below.
node - "${STATE}/extensions/agent-ward/openclaw.plugin.json" <<'NODE'
const fs = require("node:fs");
const path = process.argv[2];
const manifest = JSON.parse(fs.readFileSync(path, "utf8"));
manifest.configSchema.properties.approvals = {
  type: "object",
  additionalProperties: false,
  properties: {
    enableUserApproval: {
      type: "boolean",
      description: "When false, approval findings are denied in headless runs.",
    },
    timeoutMs: {
      type: ["number", "null"],
      description: "Approval timeout in milliseconds.",
    },
  },
};
fs.writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
NODE

set -a
# shellcheck disable=SC1091
source "${ENV_FILE}"
set +a

echo "Using environment file: ${ENV_FILE}"

# The checked-in .env uses Windows CRLF; strip carriage returns before using
# values in URLs, where a trailing CR becomes an invalid control character.
baseurl="${baseurl//$'\r'/}"
key="${key//$'\r'/}"
model="${model//$'\r'/}"

export QWEN_BASE_URL="${baseurl}"
export QWEN_API_KEY="${key}"
export QWEN_MODEL="${MODEL}"
export AGENT_WARD_API_KEY="${key}"
export DEEPTRAP_QWEN_STATE_DIR="${STATE}"
export DASHSCOPE_API_KEY="${key}"
export DEEPTRAP_JUDGE_BASE_URL="${baseurl}"
export DEEPTRAP_OPENCLAW_LOCAL=1

bash "${ROOT}/scripts/setup_deeptrap_qwen_wsl.sh"

# Satisfy AgentWard's access-control baseline without changing the benchmark
# workspace fixtures. These are OpenClaw runtime controls, not task inputs.
openclaw config set gateway.bind loopback
openclaw config set session.dmScope per-channel-peer
openclaw config set gateway.nodes.denyCommands '["camera.snap","camera.clip","screen.record","contacts.add","calendar.add","reminders.add","sms.send"]' --strict-json

# Run AgentWard as an isolated OpenClaw plugin. Disabling interactive approval
# makes requireApproval findings deterministic denials in a headless benchmark.
openclaw config set plugins.allow '["agent-ward"]' --strict-json
openclaw config set plugins.entries.agent-ward.enabled true --strict-json
openclaw config set plugins.entries.agent-ward.hooks.allowConversationAccess true --strict-json
openclaw config set plugins.entries.agent-ward.config.approvals.enableUserApproval false --strict-json
openclaw config set plugins.entries.agent-ward.config.approvals.timeoutMs 1000 --strict-json
openclaw config set plugins.entries.agent-ward.config.notifications.enableProactiveNotifications false --strict-json
openclaw config set plugins.entries.agent-ward.config.logging.enableFileLog true --strict-json
openclaw config set plugins.entries.agent-ward.config.layers.foundationScan.blockToolCallOnFoundationScanWarning true --strict-json
openclaw config set plugins.entries.agent-ward.config.llm.provider qwen
openclaw config set plugins.entries.agent-ward.config.llm.model "${QWEN_MODEL}"
openclaw config set plugins.entries.agent-ward.config.llm.api openai-completions
openclaw config set plugins.entries.agent-ward.config.llm.baseUrl "${QWEN_BASE_URL}"
openclaw config set plugins.entries.agent-ward.config.llm.apiKeyEnv AGENT_WARD_API_KEY

openclaw config validate
openclaw plugins list | grep -E 'AgentWard|AgentSentry' || true

if [[ "${MODE}" == "smoke" ]]; then
  python3 "${ROOT}/third_party/benchmarks/DeepTrap/benchmark.py" \
    --model "qwen/${QWEN_MODEL}" \
    --suite "${SUITE}" \
    --judge-model "qwen/${QWEN_MODEL}" \
    --output-dir "${OUT_ROOT}" \
    --timeout-multiplier "${DEEPTRAP_AGENTWARD_TIMEOUT_MULTIPLIER:-1}" \
    --no-fail-fast \
    --verbose
else
  # Match the existing three-arm DeepTrap runs, which begin immediately at
  # Task 1/42 and do not generate separate clean baselines in this invocation.
  # Keep one OpenClaw agent process for the remaining tasks while checkpointing
  # after every task. This avoids AgentWard worker startup on every shard.
  CHECKPOINT="${OUT_ROOT}/deeptrap_agentward.partial.json"
  FINAL_OUTPUT="${OUT_ROOT}/deeptrap_agentward.full.json"
  NATIVE_OUTPUT="${OUT_ROOT}/native-run"
  mkdir -p "${NATIVE_OUTPUT}"
  resume_args=()
  if [[ -f "${CHECKPOINT}" ]]; then
    resume_args+=(--resume-checkpoint "${CHECKPOINT}")
  fi

  python3 "${ROOT}/third_party/benchmarks/DeepTrap/benchmark.py" \
    --model "qwen/${QWEN_MODEL}" \
    --suite all \
    --judge-model "qwen/${QWEN_MODEL}" \
    --output-dir "${NATIVE_OUTPUT}" \
    --timeout-multiplier "${DEEPTRAP_AGENTWARD_TIMEOUT_MULTIPLIER:-1}" \
    --no-fail-fast \
    --skip-baseline-gen \
    --checkpoint-file "${CHECKPOINT}" \
    "${resume_args[@]}"

  cp "${CHECKPOINT}" "${FINAL_OUTPUT}"
  python3 "${ROOT}/scripts/revalidate_deeptrap_result.py" "${FINAL_OUTPUT}"
fi
