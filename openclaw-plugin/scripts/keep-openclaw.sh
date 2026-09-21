#!/bin/bash
# Keep OpenClaw (and therefore the Xuanjian/AgentSentry plugin) alive inside WSL.
# A running user process also prevents WSL from idle-stopping the distro.
set -u

GATEWAY_PORT="${OPENCLAW_GATEWAY_PORT:-18789}"  # OpenClaw platform / Control UI
PLUGIN_PORT="${OPENCLAW_PLUGIN_PORT:-8765}"     # AgentSentry plugin dashboard

# Port probe with no external dependency.
# bash's /dev/tcp is a built-in, so it still works when ss / netstat are absent.
port_up() {
  if (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; then
    return 0
  fi
  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | grep -q ":$1 " && return 0
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | grep -q ":$1 " && return 0
  fi
  return 1
}

wait_for_port() {
  port="$1"
  limit="$2"
  i=0
  while [ "$i" -lt "$limit" ]; do
    if port_up "$port"; then
      echo "port $port is listening"
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "port $port is NOT listening after ${limit}s"
  return 1
}

start_gateway() {
  echo "Starting OpenClaw gateway ..."
  openclaw gateway start >/dev/null 2>&1 || true
  if port_up "$GATEWAY_PORT"; then
    echo "port $GATEWAY_PORT is listening"
    return 0
  fi
  echo "Not up yet; restarting the gateway service ..."
  openclaw gateway restart 2>&1 | tail -3 || true
  wait_for_port "$GATEWAY_PORT" 60
}

watch_gateway() {
  echo "Keep this window open."
  echo "Gateway port : $GATEWAY_PORT   (this is what gets kept alive)"
  echo "Plugin panel : $PLUGIN_PORT    (reported only)"
  echo "Close the window only when you want to stop."
  misses=0
  while true; do
    if port_up "$GATEWAY_PORT"; then
      misses=0
      if port_up "$PLUGIN_PORT"; then
        echo "[$(date '+%H:%M:%S')] $GATEWAY_PORT ok, plugin panel $PLUGIN_PORT ok"
      else
        echo "[$(date '+%H:%M:%S')] $GATEWAY_PORT ok, plugin panel $PLUGIN_PORT down (plugin not loaded)"
      fi
    else
      misses=$((misses + 1))
      if [ "$misses" -ge 2 ]; then
        # Require two consecutive misses so the service is never hammered.
        echo "[$(date '+%H:%M:%S')] gateway $GATEWAY_PORT down, restarting OpenClaw ..."
        openclaw gateway restart >/dev/null 2>&1 || true
        misses=0
        sleep 10
      else
        echo "[$(date '+%H:%M:%S')] gateway $GATEWAY_PORT missed once, re-checking ..."
      fi
    fi
    sleep 15
  done
}

cmd="${1:-watch}"
case "$cmd" in
  start)
    start_gateway
    ;;
  watch)
    start_gateway || true
    watch_gateway
    ;;
  *)
    echo "usage: $0 start|watch"
    exit 1
    ;;
esac
