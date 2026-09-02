#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
from pathlib import Path

FORBIDDEN = (
    "Db::open_default",
    "CredentialStore::open",
    "vault_for_db",
    "open_for_db",
    "SealedCompartment::open_default",
)

# Exact file + symbol + occurrence count. A new open in an allow-listed file fails.
# CLI is empty since the CLI commands moved onto daemon RPCs (issue #306
# re-wired this guardrail into CI after the refactor): any direct CLI open is
# now a hard failure.
CLI_ALLOWED = {}

CORE_ALLOWED = {
    ("daemon/server/mod.rs", "Db::open_default"): 1,
    ("daemon/server/mod.rs", "open_for_db"): 1,
    # `Db::open_default_read_only_diagnostic()` is the sanctioned read-only
    # `cockpit doctor` / hidden diagnostic-snapshot opener; the needle below
    # matches its `Db::open_default` prefix.
    ("daemon/diagnostics_probe.rs", "Db::open_default"): 1,
    ("secure_key/mod.rs", "vault_for_db"): 1,
    ("secure_key/mod.rs", "open_for_db"): 1,
    ("secure_key/resolve.rs", "vault_for_db"): 1,
    ("secure_key/resolve.rs", "open_for_db"): 2,
    ("assistants/self_improvement.rs", "open_for_db"): 1,
    ("assistants/mod.rs", "open_for_db"): 1,
}


def strip_test_modules(src: str) -> str:
    out = []
    i = 0
    while i < len(src):
        rel = src.find("#[cfg(test)]", i)
        if rel < 0:
            out.append(src[i:])
            break
        out.append(src[i:rel])
        after = rel + len("#[cfg(test)]")
        brace = src.find("{", after)
        if brace < 0:
            i = after
            continue
        depth = 0
        j = brace
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        i = j
    return "".join(out)


def skip_path(path: Path, root: Path) -> bool:
    if "test" in path.name or path.name == "production_path_ratchet.rs":
        return True
    return any(part == "tests" for part in path.relative_to(root).parts)


def scan(root: Path, allowed: dict[tuple[str, str], int]) -> list[str]:
    hits = []
    seen = set()
    for path in root.rglob("*.rs"):
        if skip_path(path, root):
            continue
        rel = path.relative_to(root).as_posix()
        source = strip_test_modules(path.read_text())
        for needle in FORBIDDEN:
            count = source.count(needle)
            if count == 0:
                continue
            key = (rel, needle)
            expected = allowed.get(key)
            if expected is None:
                hits.append(f"{path}: {needle} ({count})")
                continue
            seen.add(key)
            if count != expected:
                hits.append(
                    f"{path}: {needle} {count} time(s), expected {expected}"
                )
    for key, expected in allowed.items():
        if key not in seen:
            hits.append(
                f"allow-list entry {key[0]} {key[1]} x{expected} was not observed"
            )
    return hits

violations = scan(Path("apps/cli/src"), CLI_ALLOWED)
violations += scan(Path("crates/cockpit-core/src"), CORE_ALLOWED)
if violations:
    raise SystemExit(
        "production-path ratchet violations:\n" + "\n".join(violations)
    )
print("production-path secret-open ratchet is intact")
PY
