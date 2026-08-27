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
while ! mkdir "$lockdir" 2>/dev/null; do
  sleep 0.05
done
trap 'rmdir "$lockdir"' EXIT
"$cargo_bin" "$@"
