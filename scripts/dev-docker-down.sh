#!/usr/bin/env bash
# dev-docker-down.sh — tear down a dev-docker stack.
#
# Usage: pnpm dev:docker:down <port>
#
# Removes containers, network, and all ephemeral volumes for the project, so
# the next `pnpm dev:docker <port>` starts with a fresh database.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/dev-docker-runtime.sh
. "$SCRIPT_DIR/lib/dev-docker-runtime.sh"

PORT="${1:-}"
if [ -z "$PORT" ]; then
  echo "Usage: pnpm dev:docker:down <port>" >&2
  exit 1
fi

case "$PORT" in
  ''|*[!0-9]*) echo "error: port must be numeric, got: $PORT" >&2; exit 1 ;;
esac

RUNTIME=$(dev_docker_detect_runtime)
COMPOSE=$(dev_docker_pick_compose "$RUNTIME")

cd "$ROOT_DIR"
dev_docker_export_project_name_for_port "$ROOT_DIR" "$PORT"
# Compose interpolates ${AGENT_VOLUME_ROOT:?} even on `down`, so export it.
dev_docker_export_volume_root_for_port "$ROOT_DIR" "$PORT"

# shellcheck disable=SC2086
$COMPOSE -f docker-compose.agent.yml --profile dev --profile prod \
  down -v --remove-orphans

# node_modules now live in a gitignored bind dir, not a Docker named volume,
# so `down -v` does not touch them — remove them explicitly for a clean slate.
rm -rf "$AGENT_VOLUME_ROOT"

# Clear .agent-ports.json if it pointed at this port.
if [ -f .agent-ports.json ] && grep -q '"port": '$PORT .agent-ports.json; then
  rm -f .agent-ports.json
fi

echo "[dev-docker] torn down $COMPOSE_PROJECT_NAME"
