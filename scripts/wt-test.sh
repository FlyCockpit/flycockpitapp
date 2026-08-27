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
case "$PWD" in
  */worktrees/[0-9a-fA-F][0-9a-fA-F]*)
    echo "wt-test.sh: refusing to invoke cargo from a managed worktree: $PWD" >&2
    exit 2
    ;;
esac
case "$primary" in
  */worktrees/[0-9a-fA-F][0-9a-fA-F]*)
    echo "wt-test.sh: refusing primary that is a managed worktree: $primary" >&2
    exit 2
    ;;
esac

if git -C "$PWD" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  gitdir=$(git -C "$PWD" rev-parse --git-dir)
  case "$gitdir" in
    *.git/worktrees/*)
      echo "wt-test.sh: refusing to invoke cargo from a linked git worktree: $PWD" >&2
      exit 2
      ;;
  esac
fi

cargo_bin=${WT_TEST_CARGO:-cargo}
lock_root=${CARGO_TARGET_DIR:-$primary/target}
mkdir -p "$lock_root"
cd "$primary"

if [[ "${WT_TEST_LOCK_HELD:-}" == "1" ]]; then
  exec "$cargo_bin" "$@"
fi

lockdir=$lock_root/wt-test.lock.dir
deadline=$((SECONDS + ${WT_TEST_LOCK_TIMEOUT_SECONDS:-120}))
nonce="$$-${RANDOM}-${RANDOM}"
while ! mkdir "$lockdir" 2>/dev/null; do
  owner=""
  if [[ -r "$lockdir/owner" ]]; then
    read -r owner _ < "$lockdir/owner" || true
  fi
  stale=0
  if [[ -z "$owner" ]] || ! kill -0 "$owner" 2>/dev/null; then
    stale=1
  fi
  if (( stale )); then
    # Move the inspected name aside atomically before deletion. A competing
    # waiter can create a successor only at $lockdir, never in this tombstone.
    tombstone="${lockdir}.stale-$$-${RANDOM}"
    if mv -- "$lockdir" "$tombstone" 2>/dev/null; then
      rm -rf -- "$tombstone"
    fi
    continue
  fi
  if (( SECONDS >= deadline )); then
    echo "wt-test.sh: timed out waiting for candidate-validation lock" >&2
    exit 75
  fi
  sleep 0.05
done
printf '%s %s\n' "$$" "$nonce" > "$lockdir/owner"
trap 'if [[ -r "$lockdir/owner" ]] && read -r pid held_nonce < "$lockdir/owner" && [[ "$pid" == "$$" && "$held_nonce" == "$nonce" ]]; then rm -rf -- "$lockdir"; fi' EXIT
"$cargo_bin" "$@"
