#!/usr/bin/env bash
# Batch launcher for manifest2: rides through provider rate-limit windows.
#
# Loop: probe the uds-deepseek endpoint directly (cheap, max_tokens=5);
# when it answers, run scripts/replay_wsl.sh --resume; when the runner
# hits its circuit breaker (exit 3) or fails, wait and try again. The
# runner's --resume mode only skips replay_ids that produced a live
# session, so every retry re-attempts the failed tail.
#
# Usage (inside WSL, from xuanjian-2.0 project root, detached):
#   nohup bash scripts/replay_batch_launcher.sh \
#     data/replay/manifest2.jsonl data/replay/sessions2.jsonl \
#     > data/replay/batch_launcher.log 2>&1 &

set -uo pipefail

MANIFEST="${1:?usage: replay_batch_launcher.sh <manifest.jsonl> <sessions_output.jsonl>}"
OUTPUT="${2:?usage: replay_batch_launcher.sh <manifest.jsonl> <sessions_output.jsonl>}"

PROBE_INTERVAL="${PROBE_INTERVAL:-60}"
OUTER_MAX="${OUTER_MAX:-40}"
OUTER_WAIT="${OUTER_WAIT:-600}"

# Direct provider probe: bypasses the gateway so we measure the actual
# upstream state. Reads the API key from the OpenClaw config.
probe_provider() {
  python3 - <<'PY'
import json, sys, urllib.request
try:
    with open("/root/.openclaw/openclaw.json", encoding="utf-8-sig") as fh:
        cfg = json.load(fh)
    key = cfg["models"]["providers"]["uds-deepseek"]["apiKey"]
except Exception:
    sys.exit(2)
body = json.dumps({"model": "deepseek-v4-flash",
                   "messages": [{"role": "user", "content": "Say OK"}],
                   "max_tokens": 5}).encode()
req = urllib.request.Request(
    "https://unlimitds.chat/v1/chat/completions", data=body,
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
}

attempt=0
while [[ ${attempt} -lt ${OUTER_MAX} ]]; do
  attempt=$((attempt + 1))
  echo "[launcher] round ${attempt}/${OUTER_MAX} $(date -u +%FT%TZ): waiting for provider"
  waited=0
  until probe_provider; do
    sleep "${PROBE_INTERVAL}"
    waited=$((waited + PROBE_INTERVAL))
    # print a heartbeat every 10 minutes so the log shows it is alive
    if (( waited % 600 == 0 )); then
      echo "[launcher] provider still unavailable after ${waited}s $(date -u +%FT%TZ)"
    fi
  done
  echo "[launcher] provider alive after ${waited}s; starting/resuming batch"
  if bash scripts/replay_wsl.sh "${MANIFEST}" "${OUTPUT}" 0 --resume; then
    echo "[launcher] batch COMPLETE $(date -u +%FT%TZ)"
    exit 0
  fi
  rc=$?
  echo "[launcher] runner exited rc=${rc} $(date -u +%FT%TZ); waiting ${OUTER_WAIT}s before next round"
  sleep "${OUTER_WAIT}"
done
echo "[launcher] gave up after ${OUTER_MAX} rounds $(date -u +%FT%TZ)"
exit 4
