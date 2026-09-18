#!/bin/bash
# Read-only: ask the openclaw CLI what it thinks about the agent-sentry plugin.
# Nothing here changes state.
#
# Every CLI call goes through the oc() wrapper. Some subcommands never return
# on their own: `openclaw doctor` spawns an openclaw-doctor child and simply
# sits there, which hung this script for 19+ minutes on 2026-09-15 while it
# held a whole WSL session open. The wrapper adds a hard timeout and closes
# stdin so no call can block on a TTY.
set -u

OC_TIMEOUT="${OC_TIMEOUT:-30}"

oc() {
  local budget="$OC_TIMEOUT"
  if [ "${1:-}" = "--slow" ]; then
    shift
    budget=90
  fi
  timeout "$budget" openclaw "$@" </dev/null 2>&1
  local rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "!! 'openclaw $*' timed out after ${budget}s (skipped)"
  fi
  return 0
}

echo "########## 1. version ##########"
oc --version | head -3

echo
echo "########## 1b. openclaw --help (top-level commands) ##########"
oc --help | head -80

echo
echo "########## 2. plugins --help (command tree) ##########"
oc plugins --help | head -60

echo
echo "########## 3. plugins list ##########"
oc plugins list | head -100

echo
echo "########## 4. plugins list --all ##########"
oc plugins list --all | head -60

echo
echo "########## 5. plugins inspect agent-sentry ##########"
oc plugins inspect agent-sentry | head -40

echo
echo "########## 6. plugins doctor (plugin load issues) ##########"
oc --slow plugins doctor | head -60

echo
echo "########## 7. doctor (read-only report, no --fix) ##########"
oc --slow doctor | tail -80

echo
echo "########## 8. gateway status ##########"
oc gateway status | head -40

echo
echo "########## 9. ports ##########"
for p in 18789 8765; do
  if (exec 3<>/dev/tcp/127.0.0.1/"$p") 2>/dev/null; then
    echo "127.0.0.1:$p OPEN"
  else
    echo "127.0.0.1:$p CLOSED"
  fi
done

echo
echo "########## done ##########"
