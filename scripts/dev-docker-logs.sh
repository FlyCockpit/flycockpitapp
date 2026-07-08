#!/usr/bin/env bash
# dev-docker-logs.sh — stream logs from a running dev-docker stack.
#
# Usage: pnpm dev:docker:logs <port> [service]
#
#   port      port the stack was started on (same <port> passed to dev-docker)
#   service   optional: app-dev | app-prod | worker-prod | postgres | redis
#             default: auto-picks app-dev or app-prod
#
# Follow mode with a 200-line backfill. Ctrl-C to detach (leaves the stack
# running).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/dev-docker-runtime.sh
. "$SCRIPT_DIR/lib/dev-docker-runtime.sh"

PORT="${1:-}"
SERVICE="${2:-}"

if [ -z "$PORT" ]; then
  echo "Usage: pnpm dev:docker:logs <port> [service]" >&2
  echo "       services: app-dev, app-prod, worker-prod, postgres, redis" >&2
  exit 1
fi

case "$PORT" in
  ''|*[!0-9]*) echo "error: port must be numeric, got: $PORT" >&2; exit 1 ;;
esac

RUNTIME=$(dev_docker_detect_runtime)
COMPOSE=$(dev_docker_pick_compose "$RUNTIME")

cd "$ROOT_DIR"
dev_docker_export_project_name_for_port "$ROOT_DIR" "$PORT"
# Compose interpolates ${AGENT_VOLUME_ROOT:?} when parsing the file, so export
# it even though `logs` never touches the volumes.
dev_docker_export_volume_root_for_port "$ROOT_DIR" "$PORT"

# Auto-pick the app service if none specified.
if [ -z "$SERVICE" ]; then
  if "$RUNTIME" ps \
       --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
       --filter "label=com.docker.compose.service=app-dev" \
       -q | grep -q .; then
    SERVICE="app-dev"
  elif "$RUNTIME" ps \
       --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
       --filter "label=com.docker.compose.service=app-prod" \
       -q | grep -q .; then
    SERVICE="app-prod"
  else
    echo "error: no running app container for project $COMPOSE_PROJECT_NAME" >&2
    echo "       start it with: pnpm dev:docker $PORT" >&2
    exit 1
  fi
fi

# shellcheck disable=SC2086
exec $COMPOSE -f docker-compose.agent.yml --profile dev --profile prod \
  logs -f --tail 200 "$SERVICE"
