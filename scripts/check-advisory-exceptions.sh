#!/usr/bin/env bash
# Advisory-exception policy gate (issue #306).
#
# deny.toml's [advisories].ignore is the single source of truth for the
# advisory exceptions. This script enforces the two properties the file alone
# cannot:
#   1. Every exception is time-bounded: its reason must contain
#      "review by YYYY-MM-DD", and the date must not be past. Exceptions never
#      live past their documented review deadline — bump the affected crate,
#      or re-audit and re-date the reason.
#   2. `cargo audit`'s --ignore flags cannot drift from deny.toml: the flags
#      are derived here from the same `ignore` array, so adding, removing, or
#      re-dating an exception in deny.toml is the only edit needed.
#
# On success, prints the cargo-audit ignore flags (one "--ignore <ID>" pair per
# RUSTSEC entry; crate-spec entries cover yanked crates, which cargo audit
# does not check, so they produce no flag) and exits 0.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
from __future__ import annotations

import datetime
import re
import sys
import tomllib
from pathlib import Path

# Requires Python 3.11+ for tomllib (the supply-chain CI runners ship 3.12).
# Fail closed rather than silently skipping the policy check.
try:
    import tomllib  # noqa: F401
except ImportError:
    sys.exit("check-advisory-exceptions: tomllib is unavailable; Python 3.11+ is required")

DENY_TOML = Path("deny.toml")
REVIEW_BY = re.compile(r"review by (\d{4}-\d{2}-\d{2})")

failures: list[str] = []
audit_flags: list[str] = []

cfg = tomllib.loads(DENY_TOML.read_text(encoding="utf-8"))
advisories = cfg.get("advisories")
if not isinstance(advisories, dict):
    sys.exit("check-advisory-exceptions: deny.toml has no [advisories] section")

ignore = advisories.get("ignore")
if not isinstance(ignore, list):
    sys.exit("check-advisory-exceptions: deny.toml [advisories].ignore is missing or not an array")

today = datetime.date.today()

for i, entry in enumerate(ignore):
    where = f"deny.toml [advisories].ignore[{i}]"
    if not isinstance(entry, dict):
        failures.append(f"{where}: entries must be tables ({{ id = ... }} or {{ crate = ... }})")
        continue

    has_id, has_crate = "id" in entry, "crate" in entry
    if has_id == has_crate:
        failures.append(
            f"{where}: exactly one of `id` (RUSTSEC advisory) or `crate` "
            "(yanked version) is required"
        )
        continue

    reason = entry.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        failures.append(f"{where}: missing `reason`; every exception must be documented")
        continue

    m = REVIEW_BY.search(reason)
    if m is None:
        failures.append(
            f"{where}: reason has no 'review by YYYY-MM-DD' date; every "
            "exception must be time-bounded"
        )
        continue
    try:
        deadline = datetime.date.fromisoformat(m.group(1))
    except ValueError:
        failures.append(f"{where}: unparsable review-by date {m.group(1)!r}")
        continue
    if today > deadline:
        failures.append(
            f"{where}: review-by date {deadline} has passed; bump the affected "
            "crate or re-audit and re-date the reason in deny.toml"
        )
        continue

    if has_id:
        audit_flags.append(f"--ignore {entry['id']}")

if failures:
    for f in failures:
        print(f"::error::check-advisory-exceptions: {f}", file=sys.stderr)
    sys.exit(1)

print(" ".join(audit_flags))
PY
