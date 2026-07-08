#!/usr/bin/env bash
# lib/dev-docker-runtime.sh — shared helpers for dev-docker.sh, dev-docker-logs.sh,
# and dev-docker-down.sh. Sourced, not executed.
#
# Works with docker OR podman. Override detection by exporting CONTAINER_RUNTIME.

# Prints the container runtime binary name to stdout, or returns non-zero if
# none is available.
dev_docker_detect_runtime() {
  if [ -n "${CONTAINER_RUNTIME:-}" ]; then
    if ! command -v "$CONTAINER_RUNTIME" >/dev/null 2>&1; then
      echo "error: CONTAINER_RUNTIME=$CONTAINER_RUNTIME not found in PATH" >&2
      return 1
    fi
    printf '%s\n' "$CONTAINER_RUNTIME"
    return 0
  fi
  if command -v docker >/dev/null 2>&1; then
    printf 'docker\n'
    return 0
  fi
  if command -v podman >/dev/null 2>&1; then
    printf 'podman\n'
    return 0
  fi
  echo "error: neither docker nor podman found in PATH" >&2
  echo "       install one, or set CONTAINER_RUNTIME=<binary>" >&2
  return 1
}

# Prints the compose invocation to stdout (possibly multi-word, e.g. "docker
# compose"). Caller must expand unquoted so the words split correctly.
# Arg 1: the runtime name (docker|podman).
dev_docker_pick_compose() {
  local runtime="$1"
  if "$runtime" compose version >/dev/null 2>&1; then
    printf '%s compose\n' "$runtime"
    return 0
  fi
  if [ "$runtime" = "podman" ] && command -v podman-compose >/dev/null 2>&1; then
    printf 'podman-compose\n'
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    printf 'docker-compose\n'
    return 0
  fi
  echo "error: no compose implementation found for $runtime" >&2
  echo "       install docker-compose-plugin, podman-compose, or a recent" >&2
  echo "       podman/docker that ships 'compose' as a subcommand." >&2
  return 1
}

# Returns 0 if the given TCP port on localhost is currently bound by a listener.
# Tries ss, then lsof, then /dev/tcp as a last resort.
# Arg 1: port number.
dev_docker_port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$port\$"
    return $?
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -i ":$port" -sTCP:LISTEN -t >/dev/null 2>&1
    return $?
  fi
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    exec 3<&- 3>&-
    return 0
  fi
  return 1
}

# Resolve a repo path to a canonical absolute path so symlinked checkouts hash
# to the same identity.
# Arg 1: repo root dir.
dev_docker_canonical_root_dir() {
  local root_dir="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$root_dir"
    return $?
  fi
  (
    cd "$root_dir" >/dev/null 2>&1 &&
    pwd -P
  )
}

# Print a short, deterministic hash for the given string. sha256 is preferred,
# with shasum/md5sum fallbacks for portability.
# Arg 1: string to hash.
dev_docker_short_hash() {
  local value="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$value" | sha256sum | awk '{print substr($1, 1, 10)}'
    return $?
  fi
  if command -v shasum >/dev/null 2>&1; then
    printf '%s' "$value" | shasum -a 256 | awk '{print substr($1, 1, 10)}'
    return $?
  fi
  if command -v md5sum >/dev/null 2>&1; then
    printf '%s' "$value" | md5sum | awk '{print substr($1, 1, 10)}'
    return $?
  fi
  echo "error: need sha256sum, shasum, or md5sum in PATH" >&2
  return 1
}

# Derive a Docker-Compose-safe project slug from the repo directory name.
# Compose requires the name to be lowercase and to match
# [a-z0-9][a-z0-9_-]*; sanitize accordingly, falling back to "app".
# Arg 1: repo root dir.
dev_docker_project_slug() {
  local root_dir="$1" slug
  # lowercase; map every char outside the allowed set to '-'; squeeze runs of
  # '-' (the trailing newline from basename becomes one and is stripped below).
  slug="$(basename "$root_dir" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_-' '-' | tr -s '-')"
  slug="${slug#-}"; slug="${slug%-}"   # strip leading/trailing separators
  slug="${slug#_}"                     # name must start with [a-z0-9], not '_'
  [ -n "$slug" ] || slug="app"
  printf '%s\n' "$slug"
}

# Print the default compose project name:
#   <repo-slug>-<short-hash-of-canonical-root>-<port>
# The basename keeps `docker ps` readable; the path hash avoids collisions
# between distinct checkouts that share the same directory name.
# Arg 1: repo root dir. Arg 2: port.
dev_docker_project_name() {
  local root_dir="$1" port="$2" canonical_root slug root_hash
  canonical_root="$(dev_docker_canonical_root_dir "$root_dir")" || return 1
  slug="$(dev_docker_project_slug "$canonical_root")"
  root_hash="$(dev_docker_short_hash "$canonical_root")" || return 1
  printf '%s-%s-%s\n' "$slug" "$root_hash" "$port"
}

# Read a field from .agent-ports.json if it matches the requested port.
# The file is written by dev-docker.sh and intentionally tiny/stable, so a
# minimal parser keeps the wrapper dependency-free.
# Args: 1=root dir 2=port 3=field name
dev_docker_saved_port_field() {
  local root_dir="$1" port="$2" field="$3" state_file saved_port
  state_file="$root_dir/.agent-ports.json"
  [ -f "$state_file" ] || return 1
  saved_port="$(sed -n 's/.*"port":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$state_file" | head -n 1)"
  [ "$saved_port" = "$port" ] || return 1
  sed -n "s/.*\"$field\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$state_file" | head -n 1
}

# Set COMPOSE_PROJECT_NAME for `up`: always derive it from the current repo
# path so same-basename checkouts do not collide.
# Arg 1: repo root dir. Arg 2: port.
dev_docker_export_project_name() {
  COMPOSE_PROJECT_NAME="$(dev_docker_project_name "$1" "$2")"
  export COMPOSE_PROJECT_NAME
}

# Set COMPOSE_PROJECT_NAME for `logs`/`down`: prefer the value persisted by the
# last successful `up` for this port so the wrappers still find the stack after
# the repo is renamed or moved. Fall back to the current-path-derived default.
# Arg 1: repo root dir. Arg 2: port.
dev_docker_export_project_name_for_port() {
  local root_dir="$1" port="$2" saved_project=""
  saved_project="$(dev_docker_saved_port_field "$root_dir" "$port" project 2>/dev/null || true)"
  COMPOSE_PROJECT_NAME="${saved_project:-$(dev_docker_project_name "$root_dir" "$port")}"
  export COMPOSE_PROJECT_NAME
}

# Derive and export AGENT_VOLUME_ROOT — the absolute, per-project directory the
# agent stack's node_modules bind mounts resolve to (see docker-compose.agent.yml).
# Every script that invokes compose with that file must call this AFTER setting
# COMPOSE_PROJECT_NAME, because the compose file fails fast (`${AGENT_VOLUME_ROOT:?}`)
# when the var is unset — that guard is what catches a raw `docker compose`
# invocation made outside these wrappers.
# Arg 1: repo root dir.
dev_docker_export_volume_root() {
  AGENT_VOLUME_ROOT="$1/.docker-volumes/$COMPOSE_PROJECT_NAME"
  export AGENT_VOLUME_ROOT
}

# Same as above, but prefer the persisted volume root for an existing port so
# `down` can still clean the old cache location after the repo moves.
# Arg 1: repo root dir. Arg 2: port.
dev_docker_export_volume_root_for_port() {
  local root_dir="$1" port="$2" saved_volume_root=""
  saved_volume_root="$(dev_docker_saved_port_field "$root_dir" "$port" volumeRoot 2>/dev/null || true)"
  AGENT_VOLUME_ROOT="${saved_volume_root:-$root_dir/.docker-volumes/$COMPOSE_PROJECT_NAME}"
  export AGENT_VOLUME_ROOT
}
