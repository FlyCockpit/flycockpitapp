#!/usr/bin/env bash
set -euo pipefail

# Code-root constructor inventory ratchet. Generic Attach remains a closed
# Assistant/Computer route and must never regain a Code spelling or an omitted
# mode that could be resolved to Code from storage.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 <<'PY'
from pathlib import Path
import re
import sys

roots = [Path("apps/cli/src"), Path("crates/cockpit-client/src"), Path("crates/cockpit-core/src"), Path("crates/cockpit-tui/src")]
offenders = []

def blocks(source: str, marker: str):
    start = 0
    while True:
        found = source.find(marker, start)
        if found < 0:
            return
        brace = source.find("{", found + len(marker))
        if brace < 0:
            return
        depth = 0
        i = brace
        in_string = False
        escaped = False
        while i < len(source):
            char = source[i]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    yield found, source[found:i + 1]
                    start = i + 1
                    break
            i += 1
        else:
            return

for root in roots:
    for path in root.rglob("*.rs"):
        if path.name == "tests.rs" or path.name.endswith("_tests.rs") or "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        # Embedded unit-test modules are not production constructors.
        source = source.split("#[cfg(test)]", 1)[0]
        for offset, block in blocks(source, "Request::Attach"):
            if "SessionEntryMode::Code" in block or re.search(r"session_entry_mode\s*:\s*None\b", block):
                line = source.count("\n", 0, offset) + 1
                offenders.append(f"{path}:{line}: generic Attach can select Code")

if offenders:
    print("Code-root constructor inventory violation:", file=sys.stderr)
    print("\n".join(f"  {item}" for item in offenders), file=sys.stderr)
    sys.exit(1)

print("Code-root constructor inventory intact")
PY
