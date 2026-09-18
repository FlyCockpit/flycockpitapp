#!/usr/bin/env bash
# No-source-scan test invariant (issue #423).
#
# Fails when a test (`#[test]` / `#[cfg(test)]` / Cargo `tests/` target)
# `include_str!`s a `.rs` file instead of asserting behaviour. Remaining
# workspace hits are an exact-count shrinking allowlist in
# scripts/lib/check_no_source_scan_tests.py: entries may only be removed.
#
# Default: run the fixture self-test, then ratchet the workspace.
#   --self-test       fixture proof only (clean tree exits 0; a reintroduced
#                     scan in a fixture fails)
#   --skip-self-test  workspace ratchet only
#   --dump            print every remaining hit (debug)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
exec python3 "$repo_root/scripts/lib/check_no_source_scan_tests.py" "$@"
