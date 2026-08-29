#!/usr/bin/env bash
# Lock-serialized Cargo entry point for worktree candidate validation.
#
# Rust validation runs only in the primary integration tree. Managed
# worktrees and linked git worktrees must never invoke Cargo; this wrapper
# fails closed if it is launched from one.
set -euo pipefail

usage() {
  echo "usage: wt-test.sh [cargo-args...]" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

primary=${WT_TEST_PRIMARY:-}
if [[ -z "$primary" ]]; then
  if git -C "$PWD" rev-parse --show-toplevel >/dev/null 2>&1; then
    primary=$(git -C "$PWD" rev-parse --show-toplevel)
  else
    primary=$PWD
  fi
fi

# Refuse managed Cockpit worktrees: .../worktrees/<uuid>
uuid_dir='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
if [[ "$PWD" =~ /worktrees/${uuid_dir}$ ]]; then
  echo "wt-test.sh: refusing to invoke cargo from a managed worktree: $PWD" >&2
  exit 2
fi
if [[ "$primary" =~ /worktrees/${uuid_dir}$ ]]; then
  echo "wt-test.sh: refusing primary that is a managed worktree: $primary" >&2
  exit 2
fi

if ! git -C "$PWD" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "wt-test.sh: refusing cargo; cannot prove cwd is not a worker worktree: $PWD" >&2
  exit 2
fi
gitdir=$(git -C "$PWD" rev-parse --git-dir) || {
  echo "wt-test.sh: refusing cargo; cannot inspect git-dir for $PWD" >&2
  exit 2
}
case "$gitdir" in
  *.git/worktrees/*)
    echo "wt-test.sh: refusing to invoke cargo from a linked git worktree: $PWD" >&2
    exit 2
    ;;
esac

cargo_bin=${WT_TEST_CARGO:-cargo}
lock_root=${CARGO_TARGET_DIR:-$primary/target}
mkdir -p "$lock_root"
cd "$primary"

if [[ "${WT_TEST_LOCK_HELD:-}" == "1" ]]; then
  exec "$cargo_bin" "$@"
fi

# Write owner identity first, then publish it atomically onto the well-known
# name with a hard link. Waiters never see a published lock without an owner.
lockfile=$lock_root/wt-test.lock
deadline=$((SECONDS + ${WT_TEST_LOCK_TIMEOUT_SECONDS:-120}))
nonce="$$-${RANDOM}-${RANDOM}"
claim=$(mktemp "$lock_root/.wt-test.lock.claim.XXXXXX")
printf '%s %s\n' "$$" "$nonce" > "$claim"
while ! ln "$claim" "$lockfile" 2>/dev/null; do
  owner=""
  if [[ -r "$lockfile" ]]; then
    read -r owner _ < "$lockfile" || true
  fi
  # Missing/unreadable owner is not stale. Only a parsed, dead pid is.
  if [[ -n "$owner" ]] && ! kill -0 "$owner" 2>/dev/null; then
    tombstone="${lockfile}.stale-$$-${RANDOM}"
    if mv -- "$lockfile" "$tombstone" 2>/dev/null; then
      rm -f -- "$tombstone"
    fi
    continue
  fi
  if (( SECONDS >= deadline )); then
    rm -f -- "$claim"
    echo "wt-test.sh: timed out waiting for candidate-validation lock" >&2
    exit 75
  fi
  sleep 0.05
done
rm -f -- "$claim"
trap 'if [[ -r "$lockfile" ]] && read -r pid held_nonce < "$lockfile" && [[ "$pid" == "$$" && "$held_nonce" == "$nonce" ]]; then rm -f -- "$lockfile"; fi' EXIT
"$cargo_bin" "$@"
