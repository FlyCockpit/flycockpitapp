#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"

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
  --glob '!**/tests/tui_db_boundary.rs' \
  -e 'cockpit_db' \
  -e 'cockpit_core::db' \
  -e '(^|[^[:alnum:]_])Db::(open|open_default|open_in_memory)' \
  crates/cockpit-tui apps/cli/src/commands/tui.rs; then
  echo "TUI database boundary violation" >&2
  exit 1
fi

# These are real compiler-negative fixtures, not comments. Compile them against
# the root workspace artifact so the proof uses the repository lockfile rather
# than a second dependency resolver that can fail before reaching the import.
cargo check --quiet --locked -p cockpit-core
dependency_dir="$CARGO_TARGET_DIR/debug/deps"
core_rmeta="$(find "$dependency_dir" -maxdepth 1 -name 'libcockpit_core-*.rmeta' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)"
if [[ -z "$core_rmeta" ]]; then
  echo "cockpit-core metadata artifact missing" >&2
  exit 1
fi
for fixture in direct_alias core_alias; do
  rustc_args=(--edition=2024 --crate-name "$fixture" --emit=metadata -L "dependency=$dependency_dir")
  if [[ "$fixture" == core_alias ]]; then
    rustc_args+=(--extern "cockpit_core=$core_rmeta")
  fi
  if output="$(rustc "${rustc_args[@]}" "scripts/fixtures/tui-db-boundary/${fixture}.rs" 2>&1)"; then
    echo "negative fixture unexpectedly compiled: $fixture" >&2
    exit 1
  fi
  if [[ "$fixture" == direct_alias ]]; then
    expected_diagnostic="unresolved import"
  else
    expected_diagnostic='crate `db` is private'
  fi
  if ! grep -q "${fixture}.rs" <<<"$output" || ! grep -q "$expected_diagnostic" <<<"$output"; then
    echo "negative fixture failed before proving the forbidden import: $fixture" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
done

echo "cockpit-tui database boundary is intact"
