#!/usr/bin/env bash
# Unsafe SAFETY-comment ratchet (issue #306).
#
# Counts `unsafe` sites (unsafe blocks/functions/impls/traits, edition-2024
# `unsafe extern` blocks, and `#[unsafe(...)]` attributes) across the Rust
# workspace and requires a `// SAFETY:` comment within three physical lines
# above each one. As of 2026-09-01 not every site carries one yet, so this is a
# ratchet, not an absolute gate: the undocumented count must EXACTLY equal
# UNDOCUMENTED_CEILING below. Exact equality is deliberate (issue #306 review
# cycle 1): it forces the ceiling down whenever annotations land, so headroom
# can never accumulate to pay for future undocumented sites.
#
# Methodology note: a site is `unsafe` immediately followed by `{`, `fn`,
# `impl`, `trait`, `extern`, or `(` (the last one is the edition-2024
# `#[unsafe(...)]` attribute form; raw `unsafe` tokens in prose/strings do not
# count), and a site is documented when a comment (// or /* */) containing
# `safety:` (case-insensitive) appears on the same line before the token or on
# one of the three preceding lines. A bare `safety:` substring in code or a
# string literal is not documentation. The ceiling is only ever recalculated
# with the exact same script.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
from pathlib import Path
import re
import sys

# Ratchet: current workspace undocumented-unsafe-site count. Must equal the
# actual count: lower it whenever annotations land, never raise it without an
# audited reason.
UNDOCUMENTED_CEILING = 372

ROOTS = [Path("apps/cli"), Path("apps/tenant-authority"), Path("crates")]
UNSAFE_TOKEN = re.compile(r"\bunsafe\b")
NEXT = re.compile(r"(?:\{|\bfn\b|\bimpl\b|\btrait\b|\bextern\b|\()")
SAFETY = re.compile(r"(?://|/\*|\*).*safety:", re.IGNORECASE)


def sites(path: Path):
    try:
        src = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        src = path.read_text(encoding="utf-8", errors="replace")
    for match in UNSAFE_TOKEN.finditer(src):
        rest = src[match.end() : match.end() + 12].lstrip()
        if NEXT.match(rest):
            yield match, src


def documented(src, end):
    preceding = src[:end].splitlines()[-4:]
    return any(SAFETY.search(line) for line in preceding)


def main():
    total = documented_count = 0
    per_file = []
    for root in ROOTS:
        for path in sorted(root.rglob("*.rs")):
            file_total = file_documented = 0
            for match, src in sites(path):
                total += 1
                file_total += 1
                if documented(src, match.start()):
                    documented_count += 1
                    file_documented += 1
            if file_total:
                per_file.append((file_total - file_documented, file_total, path))
    undocumented = total - documented_count
    print(
        f"unsafe sites: {total} total, {documented_count} documented, "
        f"{undocumented} undocumented (ceiling {UNDOCUMENTED_CEILING})"
    )
    if undocumented == UNDOCUMENTED_CEILING:
        print("unsafe SAFETY-comment ratchet is intact")
        return
    per_file.sort(reverse=True)
    print("files with the most undocumented sites:")
    for missing, file_total, path in per_file[:10]:
        print(f"  {path}: {missing}/{file_total}")
    if undocumented > UNDOCUMENTED_CEILING:
        sys.exit(
            f"unsafe SAFETY-comment ratchet exceeded: {undocumented} "
            f"undocumented > {UNDOCUMENTED_CEILING}. Add // SAFETY: comments "
            "to the new sites (or annotate existing ones)."
        )
    sys.exit(
        f"unsafe SAFETY-comment ratchet has headroom: {undocumented} "
        f"undocumented < {UNDOCUMENTED_CEILING}. Lower UNDOCUMENTED_CEILING in "
        "scripts/check-unsafe-safety-comments.sh to the new count in the same "
        "change; the ceiling is exact so headroom cannot pay for future "
        "undocumented sites."
    )
main()
PY
