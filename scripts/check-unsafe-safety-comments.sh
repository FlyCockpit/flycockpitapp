#!/usr/bin/env bash
# Unsafe SAFETY-comment ratchet (issue #306).
#
# Counts `unsafe` sites (unsafe blocks/functions/impls/traits) across the Rust
# workspace and requires a `// SAFETY:` comment within three physical lines
# above each one. As of 2026-09-01 not every site carries one yet, so this is a
# ratchet, not an absolute gate: the undocumented count may not grow past
# UNDOCUMENTED_CEILING below. Every new unsafe site written with a SAFETY
# comment (or an old one annotated) lowers the count; please lower the ceiling
# to match instead of leaving headroom.
#
# Methodology note: a site is `unsafe` immediately followed by `{`, `fn`,
# `impl`, or `trait` (raw `unsafe` tokens in prose/strings do not count), and a
# site is documented when a `safety:` comment (case-insensitive) appears on the
# same line before the token or on one of the three preceding lines. The
# ceiling is only ever recalculated with the exact same script.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
from pathlib import Path
import re
import sys

# Ratchet: current workspace undocumented-unsafe-site count. Lower this number
# when annotations land; never raise it without an audited reason.
UNDOCUMENTED_CEILING = 334

ROOTS = [Path("apps/cli"), Path("apps/tenant-authority"), Path("crates")]
UNSAFE_TOKEN = re.compile(r"\bunsafe\b")
NEXT = re.compile(r"(?:\{|\bfn\b|\bimpl\b|\btrait\b)")
SAFETY = re.compile(r"safety:", re.IGNORECASE)


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
    if undocumented > UNDOCUMENTED_CEILING:
        per_file.sort(reverse=True)
        print("files with the most undocumented sites:")
        for missing, file_total, path in per_file[:10]:
            print(f"  {path}: {missing}/{file_total}")
        sys.exit(
            f"unsafe SAFETY-comment ratchet exceeded: {undocumented} "
            f"undocumented > {UNDOCUMENTED_CEILING}. Add // SAFETY: comments "
            "to the new sites (or annotate existing ones) and lower "
            "UNDOCUMENTED_CEILING in scripts/check-unsafe-safety-comments.sh "
            "to the new count."
        )
    if undocumented < UNDOCUMENTED_CEILING:
        print(
            "note: the undocumented count dropped below the ceiling; lower "
            "UNDOCUMENTED_CEILING in scripts/check-unsafe-safety-comments.sh "
            f"to {undocumented} to reclaim the headroom."
        )
    print("unsafe SAFETY-comment ratchet is intact")


main()
PY
