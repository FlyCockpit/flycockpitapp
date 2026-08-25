#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
matrix="$root/apps/cli/release/local-runtime-capabilities-v1.json"
tree="$(cargo tree --locked -e normal -p cockpit-cli --no-default-features --prefix none)"
while IFS= read -r dependency; do
  if grep -Eq "^${dependency}([[:space:]]|$)" <<<"$tree"; then
    echo "forbidden local dependency: $dependency" >&2
    exit 1
  fi
done < <(jq -r '.forbiddenDependencies[]' "$matrix")

if [[ -z "${COCKPIT_RELEASE_BIN:-}" ]]; then
  exit 0
fi
bin="$COCKPIT_RELEASE_BIN"
help="$($bin --help)"
for forbidden in account sync connect login logout whoami; do
  if grep -Eq "^[[:space:]]+${forbidden}([[:space:]]|$)" <<<"$help"; then
    echo "forbidden local command: $forbidden" >&2
    exit 1
  fi
done
test "$(wc -c < "$bin")" -le "$(jq -r '.artifactBudgetBytes' "$matrix")"
