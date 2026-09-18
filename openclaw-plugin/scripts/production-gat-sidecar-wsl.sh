#!/usr/bin/env bash
set -euo pipefail

PYTHON_WIN="${AGENTSENTRY_GRAPH_PYTHON_WIN:-E:\\soft\\miniconda\\python.exe}"
SCRIPT_WIN="$(wslpath -w "$(cd "$(dirname "$0")" && pwd)/production-gat-sidecar.py")"
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --checkpoint|--project-root)
      key="$1"
      shift
      value="$1"
      shift
      ARGS+=("$key" "$(wslpath -w "$value")")
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done
exec cmd.exe /d /c "$PYTHON_WIN" "$SCRIPT_WIN" "${ARGS[@]}"
