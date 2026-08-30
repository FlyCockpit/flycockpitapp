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

attach_constructor = re.compile(r"\bRequest::Attach\b\s*\{")

def blocks(source: str):
    start = 0
    while True:
        match = attach_constructor.search(source, start)
        if match is None:
            return
        found = match.start()
        brace = source.find("{", found, match.end())
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

cfg_test_item = re.compile(
    r"(?m)^[ \t]*#\[cfg\(\s*(?:test|all\(\s*test\b[^\]]*\))\s*\)\][ \t]*(?:\r?\n)?"
)

def test_only_item_end(source: str, start: int):
    """Return the end of the item controlled by a standalone #[cfg(test)]."""
    i = start
    in_string = False
    in_char = False
    escaped = False
    line_comment = False
    block_comment = False
    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                i += 1
        elif in_string or in_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (in_string and char == '"') or (in_char and char == "'"):
                in_string = False
                in_char = False
        elif char == "/" and next_char == "/":
            line_comment = True
            i += 1
        elif char == "/" and next_char == "*":
            block_comment = True
            i += 1
        elif char == '"':
            in_string = True
        elif char == "'":
            in_char = True
        elif char == ";":
            return i + 1
        elif char == "{":
            depth = 1
            i += 1
            while i < len(source) and depth:
                char = source[i]
                next_char = source[i + 1] if i + 1 < len(source) else ""
                if line_comment:
                    if char == "\n":
                        line_comment = False
                elif block_comment:
                    if char == "*" and next_char == "/":
                        block_comment = False
                        i += 1
                elif in_string or in_char:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif (in_string and char == '"') or (in_char and char == "'"):
                        in_string = False
                        in_char = False
                elif char == "/" and next_char == "/":
                    line_comment = True
                    i += 1
                elif char == "/" and next_char == "*":
                    block_comment = True
                    i += 1
                elif char == '"':
                    in_string = True
                elif char == "'":
                    in_char = True
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                i += 1
            return i
        i += 1
    return len(source)

def without_test_only_items(source: str) -> str:
    """Mask each #[cfg(test)] item while retaining later production items."""
    masked = list(source)
    search_from = 0
    while match := cfg_test_item.search(source, search_from):
        end = test_only_item_end(source, match.end())
        for i in range(match.start(), end):
            if masked[i] != "\n":
                masked[i] = " "
        search_from = end
    return "".join(masked)

for root in roots:
    for path in root.rglob("*.rs"):
        if path.name == "tests.rs" or path.name.endswith("_tests.rs") or "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        # Embedded unit-test modules are not production constructors, but a
        # test-only item can appear before later production routes.  Mask only
        # that item so the inventory covers the entire production-bearing file.
        source = without_test_only_items(source)
        for offset, block in blocks(source):
            if "SessionEntryMode::Code" in block or re.search(r"session_entry_mode\s*:\s*None\b", block):
                line = source.count("\n", 0, offset) + 1
                offenders.append(f"{path}:{line}: generic Attach can select Code")

if offenders:
    print("Code-root constructor inventory violation:", file=sys.stderr)
    print("\n".join(f"  {item}" for item in offenders), file=sys.stderr)
    sys.exit(1)

print("Code-root constructor inventory intact")
PY
