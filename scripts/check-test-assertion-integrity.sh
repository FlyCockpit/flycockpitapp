#!/usr/bin/env bash
set -euo pipefail

# Test-integrity ratchet: fail if a `dead_code` lint suppression appears in a
# Rust test target outside a small, shrinking allowlist. Silencing dead_code in
# a test target is how a parsed-but-never-asserted fixture field hides (see the
# tenant-authority conformance regression this guard was added with). Semantic
# weakening (assert-flips, deleted assertions, over-narrowed checks) is not
# reliably grep-detectable and is covered by the prose rule in AGENTS.md
# ("Test integrity"), not here.
#
# Per Decision 8 this is a NARROW, dead-code-only ratchet — it must not flag
# `unused`/`unused_*`, which are legitimate test-local suppressions.
#
# Robustness against comment-based bypasses: rather than play whack-a-mole with
# the regex, each file is first STRIPPED of all Rust comments (line `//` and
# nested block `/* … */`, string/char-literal aware) into a comment-free stream,
# and the `dead_code`-inside-`allow(...)` match runs on that. This defeats every
# comment-injection variant at once — e.g. `#[allow(/* ) */ dead_code)]` and
# `#[allow // reason\n (dead_code)]` — while still matching every real form:
# `#![allow(...)]`, multi-item lists (`allow(dead_code, ...)`), whitespace and
# newline-wrapped attributes, and `cfg_attr(..., allow(dead_code))`.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Scan roots — exactly these two paths. Do not widen to the whole monorepo,
# other `crates/*/tests` globs, or any production `src/` tree.
scan_roots=(
  "crates/cockpit-proto/tests"
  "apps/cli/tests"
)

# Allowlist — exactly these three named test-target files. This is a ratchet: it
# may only SHRINK, never gain a fourth entry. `apps/cli/tests/e2e/support/mod.rs`
# is module-level shared e2e support compiled per-binary, where unused-item
# warnings are expected. The remaining two carry grandfathered occurrences owned
# by other prompts. `tenant_authority_protocol_conformance.rs` is deliberately
# absent — its `#[allow(dead_code)]` was removed.
allowlist=(
  "crates/cockpit-proto/tests/remote_version_negotiation_fixtures.rs"
  "crates/cockpit-proto/tests/remote_attempt_grant_fixtures.rs"
  "apps/cli/tests/e2e/support/mod.rs"
)

# Strips Rust comments from the given file and reports (exit 0) whether the
# comment-free text still contains `dead_code` inside an `allow(...)` group.
# Exit 1 = clean. Comments become whitespace so tokens never fuse across them.
dead_code_in_allow() {
  python3 - "$1" <<'PY'
import re
import sys

src = open(sys.argv[1], encoding="utf-8", errors="replace").read()
out = []
i, n = 0, len(src)
while i < n:
    c = src[i]
    # String / char literal: copy verbatim so `//` or `/*` inside is not stripped.
    if c == '"' or c == "'":
        quote = c
        out.append(c)
        i += 1
        while i < n:
            out.append(src[i])
            if src[i] == "\\":  # escape: copy the escaped char too
                i += 1
                if i < n:
                    out.append(src[i])
                    i += 1
                continue
            if src[i] == quote:
                i += 1
                break
            i += 1
        continue
    # Line comment -> drop to end of line (newline preserved).
    if c == "/" and i + 1 < n and src[i + 1] == "/":
        while i < n and src[i] != "\n":
            i += 1
        continue
    # Block comment (nesting) -> collapse to a single space.
    if c == "/" and i + 1 < n and src[i + 1] == "*":
        depth, i = 1, i + 2
        while i < n and depth > 0:
            if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                depth += 1
                i += 2
                continue
            if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                depth -= 1
                i += 2
                continue
            i += 1
        out.append(" ")
        continue
    out.append(c)
    i += 1

stripped = "".join(out)
# dead_code (only) inside any allow(...) group; `[^)]*` stays within one group,
# `re.DOTALL`/`\s` span newlines for wrapped attributes.
pattern = re.compile(r"allow\s*\(\s*[^)]*\bdead_code", re.DOTALL)
sys.exit(0 if pattern.search(stripped) else 1)
PY
}

is_allowlisted() {
  local file="$1"
  local allowed_file
  for allowed_file in "${allowlist[@]}"; do
    [[ "$file" == "$allowed_file" ]] && return 0
  done
  return 1
}

offenders=()
while IFS= read -r -d '' file; do
  if dead_code_in_allow "$file" && ! is_allowlisted "$file"; then
    offenders+=("$file")
  fi
done < <(find "${scan_roots[@]}" -type f -name '*.rs' -print0)

if [[ ${#offenders[@]} -gt 0 ]]; then
  echo "Test-integrity violation: #[allow(dead_code)] found in a test target outside the allowlist:" >&2
  printf '  %s\n' "${offenders[@]}" >&2
  echo "Assert the field or delete it — do not silence unused test scaffolding." >&2
  exit 1
fi

echo "test assertion integrity intact"
