#!/usr/bin/env bash
# compose.sh — thin wrapper that forwards args to the detected docker/podman
# compose implementation. Lets package.json scripts work with either runtime.
#
# Usage:
#   bash scripts/compose.sh -f docker-compose.dev.yml up -d
#   bash scripts/compose.sh up -d
#
# Honors CONTAINER_RUNTIME=docker|podman to force a choice.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/dev-docker-runtime.sh
. "$SCRIPT_DIR/lib/dev-docker-runtime.sh"

RUNTIME=$(dev_docker_detect_runtime)
COMPOSE=$(dev_docker_pick_compose "$RUNTIME")

# shellcheck disable=SC2086
exec $COMPOSE "$@"
