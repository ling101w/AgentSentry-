#!/bin/bash
# Diagnose Xuanjian (AgentSentry plugin) on top of OpenClaw.
# Read-only: it inspects state, it never restarts or modifies anything.
set -u

PLUGIN_PORT="${PLUGIN_PORT:-8765}"    # AgentSentry dashboard (the plugin panel)
GATEWAY_PORT="${GATEWAY_PORT:-18789}" # OpenClaw Control UI (the platform itself)

hr() {
  echo
  echo "==================== $1 ===================="
}

port_state() {
  if (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; then
    echo "OPEN"
  else
    echo "CLOSED"
  fi
}

hr "0. port map"
echo "18789 = OpenClaw platform (Control UI)"
echo "8765  = AgentSentry plugin dashboard"
echo
printf "127.0.0.1:%-6s -> %s\n" "$GATEWAY_PORT" "$(port_state "$GATEWAY_PORT")"
printf "127.0.0.1:%-6s -> %s\n" "$PLUGIN_PORT" "$(port_state "$PLUGIN_PORT")"

hr "1. environment"
date
echo "distro : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"')"
echo "init   : $(ps -p 1 -o comm= 2>/dev/null)"
echo "user   : $(id -un)"
echo "home   : $HOME"

hr "2. openclaw binary"
if command -v openclaw >/dev/null 2>&1; then
  command -v openclaw
  timeout 30 openclaw --version </dev/null 2>&1 | head -3
else
  echo "!! openclaw is NOT in PATH for this user"
fi

hr "3. openclaw gateway status"
# Hard timeout + closed stdin: CLI calls must never block on a TTY or on a
# gateway that is down (see the openclaw-doctor hang in plugin-status.sh).
if command -v openclaw >/dev/null 2>&1; then
  timeout 30 openclaw gateway status </dev/null 2>&1 | head -40
else
  echo "skipped"
fi

hr "4. systemd units (the real unit names)"
echo "-- system units --"
systemctl list-units --all --no-pager 2>/dev/null | grep -i openclaw || echo "(no system unit matches)"
echo "-- user units --"
systemctl --user list-units --all --no-pager 2>/dev/null | grep -i openclaw || echo "(no user unit matches)"

hr "5. unit files on disk"
grep -rls "openclaw" /etc/systemd/system /lib/systemd/system "$HOME/.config/systemd/user" 2>/dev/null | head -10 || echo "(none found)"

hr "6. listening sockets"
if command -v ss >/dev/null 2>&1; then
  ss -tlnp 2>&1 | head -40
elif command -v netstat >/dev/null 2>&1; then
  netstat -tlnp 2>&1 | head -40
else
  echo "!! neither ss nor netstat available (this alone breaks the old keep-openclaw.sh)"
fi

hr "7. openclaw-related processes"
ps -ef 2>/dev/null | grep -Ei "openclaw|wslrelay" | grep -v grep | head -20 || echo "(none)"

hr "8. openclaw state dir"
ls -la "$HOME/.openclaw" 2>&1 | head -30

hr "9. plugin registration (is agent-sentry enabled?)"
if [ -f "$HOME/.openclaw/openclaw.json" ]; then
  echo "-- file: $HOME/.openclaw/openclaw.json --"
  python3 - "$HOME/.openclaw/openclaw.json" <<'PY' 2>/dev/null || grep -n -i "agent-sentry\|agentsentry\|plugins" "$HOME/.openclaw/openclaw.json" | head -40
import json, sys
try:
    cfg = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print("cannot parse:", e); sys.exit(0)
plugins = cfg.get("plugins", {}) or {}
entries = plugins.get("entries") or {}
print("plugins.entries keys:", list(entries.keys()))
for name, val in entries.items():
    if "sentry" in name.lower() or "xuanjian" in name.lower():
        val = val or {}
        print("  entry:", name)
        print("  enabled:", val.get("enabled"))
        print("  hooks:", list((val.get("hooks") or {}).keys()))
print("plugins.enabled list:", plugins.get("enabled"))
PY
else
  echo "(no openclaw.json in $HOME/.openclaw)"
fi

hr "10. agent-sentry data dir"
ls -la "$HOME/.openclaw/agentsentry" 2>&1 | head -20

hr "11. where 8765 is configured"
grep -Rns "8765" "$HOME/.openclaw" 2>/dev/null | head -15 || echo "(no 8765 match under ~/.openclaw)"

hr "12. logs"
ls -la "$HOME/.openclaw/logs" 2>/dev/null | head -20 || echo "(no logs dir)"
find "$HOME/.openclaw" -maxdepth 3 -name "*.log" 2>/dev/null | head -10 || true

hr "done"
echo "Copy everything above back to the assistant."
