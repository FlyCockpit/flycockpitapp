#!/usr/bin/env bash
set -euo pipefail

cutoff="v0.1.0"
if ! git rev-parse -q --verify "refs/tags/${cutoff}" >/dev/null; then
  echo "migration append-only check inactive: ${cutoff} has not been tagged"
  exit 0
fi

base="$(git merge-base HEAD "${cutoff}")"
changed="$(git diff --name-only "${base}"...HEAD -- crates/cockpit-db/src/db/migrations/)"
while IFS= read -r path; do
  [ -z "$path" ] && continue
  if git cat-file -e "${base}:${path}" 2>/dev/null; then
    echo "released migration was modified: ${path}" >&2
    exit 1
  fi
done <<<"${changed}"
