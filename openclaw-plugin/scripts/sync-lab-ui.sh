#!/usr/bin/env bash
set -euo pipefail
SRC="/mnt/e/cslearn/AgentSentry/玄鉴-f/AgentSentry-c/openclaw-plugin/public"
PLUGIN_SRC="/mnt/e/cslearn/AgentSentry/玄鉴-f/AgentSentry-c/openclaw-plugin"
DST="/root/.openclaw/extensions/agent-sentry"
WIN_DIST="/mnt/e/cslearn/AgentSentry/玄鉴-f/AgentSentry-c/openclaw-plugin/dist/public"
files=(command-lab.html command-lab.css command-lab.js index.html dashboard.js dashboard.css dashboard-api.js)
test -f "$SRC/command-lab.html"
mkdir -p "$DST/public" "$DST/dist/public" "$WIN_DIST"
for f in "${files[@]}"; do
  cp -f "$SRC/$f" "$DST/public/$f"
  cp -f "$SRC/$f" "$DST/dist/public/$f"
  cp -f "$SRC/$f" "$WIN_DIST/$f"
  echo "copied $f"
done
if [[ -f "$PLUGIN_SRC/dist/server/dashboard.js" ]]; then
  mkdir -p "$DST/dist/server" "$DST/server"
  cp -f "$PLUGIN_SRC/dist/server/dashboard.js" "$DST/dist/server/dashboard.js"
  echo "copied dist/server/dashboard.js"
fi
grep -n "workspace_injection_12_11" "$DST/dist/public/command-lab.html" | head -5
