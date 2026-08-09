#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

metadata="$(cargo metadata --locked --format-version 1 --no-deps)"
python3 -c '
import json, sys
packages = json.load(sys.stdin)["packages"]
tui = next(p for p in packages if p["name"] == "cockpit-tui")
bad = [d["name"] for d in tui["dependencies"] if d["name"] == "cockpit-db"]
if bad:
    raise SystemExit("cockpit-tui must not depend directly on cockpit-db")
' <<<"$metadata"

if rg -n \
  -e 'cockpit_db' \
  -e 'cockpit_core::db' \
  -e '(^|[^[:alnum:]_])Db::(open|open_default|open_in_memory)' \
  crates/cockpit-tui apps/cli/src/commands/tui.rs; then
  echo "TUI database boundary violation" >&2
  exit 1
fi

# These are real compiler-negative fixtures, not comments. Each aliases a
# forbidden path so a text gate that only catches the obvious spelling is not
# sufficient. Both programs must remain uncompilable.
fixture_manifest="scripts/fixtures/tui-db-boundary/Cargo.toml"
for fixture in direct_alias core_alias; do
  if cargo check --quiet --manifest-path "$fixture_manifest" --bin "$fixture"; then
    echo "negative fixture unexpectedly compiled: $fixture" >&2
    exit 1
  fi
done

echo "cockpit-tui database boundary is intact"
