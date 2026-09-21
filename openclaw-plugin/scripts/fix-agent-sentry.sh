#!/bin/bash
# Fix the agent-sentry (Xuanjian) plugin not loading.
#
# Root cause: the plugin index cached on 2026-08-19 marked the plugin as
# blocked ("world-writable path, mode=777"). The dist was rebuilt on
# 2026-08-21 with safe 644 permissions, but the stale index was never
# refreshed, so every gateway start since then skipped the plugin and its
# dashboard on 8765 never came up.
#
# Fix: strip writable bits, refresh the plugin registry, restart the gateway.
# Fallback: full reinstall from the current source path.
set -u

EXT="/root/.openclaw/extensions/agent-sentry"
SRC="/mnt/e/cslearn/AgentSentry/xuanjian/AgentSentry/openclaw-plugin"

port_open() {
  (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null
}

wait_port() {
  port="$1"; label="$2"; secs="$3"
  i=0
  while [ "$i" -lt "$secs" ]; do
    if port_open "$port"; then
      echo "      $label : UP (after ${i}s)"
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "      $label : still down after ${secs}s"
  return 1
}

echo "===== Xuanjian plugin fix ====="
echo

echo "[1/6] Current state"
port_open 18789 && echo "      gateway 18789 : UP" || echo "      gateway 18789 : DOWN"
port_open 8765  && echo "      plugin  8765  : UP" || echo "      plugin  8765  : DOWN (this is the problem)"
echo

echo "[2/6] Removing group/world write bits from the plugin dir"
if [ -d "$EXT" ]; then
  chmod -R go-w "$EXT"
  echo "      done. key file modes now:"
  ls -l "$EXT/dist/index.js" "$EXT/openclaw.plugin.json" 2>/dev/null | sed 's/^/      /'
else
  echo "      !! extension dir missing: $EXT"
  echo "      the reinstall step below will recreate it"
fi
echo

echo "[3/6] Refreshing the plugin registry (drops the stale 2026-08-19 block entry)"
openclaw plugins registry --refresh 2>&1 | tail -25 | sed 's/^/      /'
echo

echo "[4/6] Restarting the gateway"
openclaw gateway restart 2>&1 | tail -5 | sed 's/^/      /'
echo

echo "[5/6] Waiting for ports"
wait_port 18789 "gateway 18789" 60
if ! wait_port 8765 "plugin  8765 " 45; then
  echo
  echo "      8765 still down. Falling back to a full reinstall from:"
  echo "      $SRC"
  echo
  bash "$SRC/setup.sh" --force 2>&1 | tail -30 | sed 's/^/      /'
  echo
  echo "      Re-applying safe permissions after reinstall ..."
  chmod -R go-w "$EXT" 2>/dev/null || true
  openclaw plugins registry --refresh 2>&1 | tail -10 | sed 's/^/      /'
  openclaw gateway restart 2>&1 | tail -5 | sed 's/^/      /'
  echo
  echo "      Waiting for ports again ..."
  wait_port 18789 "gateway 18789" 60
  wait_port 8765 "plugin  8765 " 45
fi
echo

echo "[6/6] Final state"
port_open 18789 && echo "      gateway 18789 : UP" || echo "      gateway 18789 : DOWN"
port_open 8765  && echo "      plugin  8765  : UP" || echo "      plugin  8765  : DOWN"
echo
if port_open 8765; then
  echo "SUCCESS. Open http://127.0.0.1:8765/overview"
  echo "If you get a 401 page, that is by design:"
  echo "  1. open http://127.0.0.1:18789/"
  echo "  2. run the command:  /agentsentry"
  echo "  3. open the authenticated link it returns"
else
  echo "STILL DOWN. Run the diagnosis and send the output back:"
  echo "  bash /mnt/e/cslearn/AgentSentry/xuanjian/AgentSentry/openclaw-plugin/scripts/diagnose-openclaw.sh"
fi
echo
echo "===== fix script end ====="
