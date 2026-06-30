#!/usr/bin/env bash
set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_NAME="agent-sentry"
OPENCLAW_CONFIG="${HOME}/.openclaw/openclaw.json"
FORCE=false
UNINSTALL_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force|-f)
      FORCE=true
      shift
      ;;
    --uninstall-only|-u)
      UNINSTALL_ONLY=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--force|-f] [--uninstall-only|-u]"
      exit 1
      ;;
  esac
done

if ! command -v openclaw >/dev/null 2>&1; then
  echo "openclaw CLI was not found in PATH. Install or open your OpenClaw shell, then run this script again." >&2
  exit 1
fi

echo "===== AgentSentry OpenClaw Setup ====="
echo "Plugin directory: ${PLUGIN_DIR}"

echo "[1/3] Uninstalling previous ${PLUGIN_NAME} if present..."
if [[ "${FORCE}" == "true" ]]; then
  openclaw plugins uninstall "${PLUGIN_NAME}" --force || true
else
  openclaw plugins uninstall "${PLUGIN_NAME}" || true
fi

if [[ "${UNINSTALL_ONLY}" == "true" ]]; then
  echo "===== Uninstall Complete ====="
  exit 0
fi

echo "[2/3] Building plugin..."
cd "${PLUGIN_DIR}"
npm run build

echo "[3/4] Installing plugin..."
if [[ "${FORCE}" == "true" ]]; then
  openclaw plugins install "${PLUGIN_DIR}" --dangerously-force-unsafe-install --force
else
  openclaw plugins install "${PLUGIN_DIR}" --dangerously-force-unsafe-install
fi

echo "[4/4] Ensuring hook permissions..."
if [[ -f "${OPENCLAW_CONFIG}" ]]; then
  node -e '
const fs = require("node:fs");
const path = process.argv[1];
const raw = fs.readFileSync(path, "utf8");
const cfg = JSON.parse(raw);
cfg.plugins ??= {};
cfg.plugins.entries ??= {};
cfg.plugins.entries["agent-sentry"] ??= {};
cfg.plugins.entries["agent-sentry"].enabled = true;
cfg.plugins.entries["agent-sentry"].hooks ??= {};
cfg.plugins.entries["agent-sentry"].hooks.allowConversationAccess = true;
fs.writeFileSync(path, JSON.stringify(cfg, null, 2) + "\n");
' "${OPENCLAW_CONFIG}"
else
  echo "OpenClaw config not found at ${OPENCLAW_CONFIG}; skipping hook permission patch." >&2
fi

echo ""
echo "===== Setup Complete ====="
echo "OpenClaw command: /agentsentry"
echo "Dashboard default: http://127.0.0.1:8765"
