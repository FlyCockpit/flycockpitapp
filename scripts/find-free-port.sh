#!/usr/bin/env bash
# find-free-port.sh — print the first free TCP port in [start, end].
#
# Used by agents to pick a port before calling `pnpm dev:docker <port>`.
#
# Usage: scripts/find-free-port.sh [start] [end]
#        (defaults: 3100..4100)
#
# Examples:
#   PORT=$(pnpm --silent find-free-port) && pnpm dev:docker "$PORT"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/dev-docker-runtime.sh
. "$SCRIPT_DIR/lib/dev-docker-runtime.sh"

START="${1:-3100}"
END="${2:-4100}"

case "$START" in ''|*[!0-9]*) echo "error: start must be numeric" >&2; exit 1 ;; esac
case "$END"   in ''|*[!0-9]*) echo "error: end must be numeric"   >&2; exit 1 ;; esac

if [ "$START" -gt "$END" ]; then
  echo "error: start ($START) > end ($END)" >&2
  exit 1
fi

port="$START"
while [ "$port" -le "$END" ]; do
  if ! dev_docker_port_in_use "$port"; then
    printf '%s\n' "$port"
    exit 0
  fi
  port=$((port + 1))
done

echo "error: no free port in $START..$END" >&2
exit 1
