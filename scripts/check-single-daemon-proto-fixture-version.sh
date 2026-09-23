#!/usr/bin/env bash
set -euo pipefail

# Single-protocol-version invariant. The daemon wire protocol has exactly one
# version (`cockpit_proto::PROTOCOL_VERSION = 1`) and no compatibility window,
# so the frozen daemon_proto fixture root may hold only `v1/` plus the archive
# checksum manifest. A new `vN/` directory would mean someone reintroduced a
# multi-version window (or copied fixtures "for archaeology"); bump in place
# and regenerate the v1 fixtures instead.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fixture_root="crates/cockpit-proto/tests/fixtures/daemon_proto"
allowed_version_dir="v1"

if [[ ! -d "$fixture_root/$allowed_version_dir" ]]; then
  echo "daemon_proto fixture invariant violation: missing $fixture_root/$allowed_version_dir/" >&2
  exit 1
fi

offenders=()
while IFS= read -r -d '' entry; do
  name="$(basename "$entry")"
  case "$name" in
    "$allowed_version_dir" | archive.sha256) ;;
    *) offenders+=("$entry") ;;
  esac
done < <(find "$fixture_root" -mindepth 1 -maxdepth 1 -print0)

if ((${#offenders[@]} > 0)); then
  echo "daemon_proto fixture invariant violation: only $allowed_version_dir/ and archive.sha256 may live under $fixture_root" >&2
  for entry in "${offenders[@]}"; do
    echo "  unexpected: $entry" >&2
  done
  echo "The protocol has a single version with no compatibility window; update the v1 fixtures in place." >&2
  exit 1
fi

echo "daemon_proto fixtures hold only $allowed_version_dir/"
