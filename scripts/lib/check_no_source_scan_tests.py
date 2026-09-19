#!/usr/bin/env python3
"""Walker for `include_str!` of `.rs` files inside test context (issue #423).

A hit is an `include_str!` whose argument names a `.rs` file and which sits
inside a `#[cfg(test)]` item, a `#[test]` / `#[tokio::test]` function, a
`#![cfg(test)]` file, a file reached via `#[cfg(test)] mod …;`, or a Cargo
`tests/` target. Production `include_str!` of `.rs` is allowed.

Remaining workspace hits live in ALLOWLIST as an exact per-file count
ratchet: one sorted entry per file that still contains source-scan tests.
Entries may only be removed (or have their count lowered). Do not add
entries. A new file, a hit not in the allowlist, or a count increase is
a hard failure.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import os
import re
import sys

SCAN_TOP = ("apps/cli", "apps/tenant-authority", "crates", "tools")
FIXTURE_REL = Path("scripts/fixtures/no-source-scan-tests")

# Phase-1 ratchet: every remaining source-scan test file and its hit count.
# One sorted entry per file that still contains source-scan tests. Shrink
# (or delete) an entry when that file is converted to behavioural
# assertions. Entries may only be removed; never add a row.
ALLOWLIST: tuple[tuple[str, int], ...] = (
    ("apps/cli/src/commands/ask.rs", 1),
    ("apps/cli/src/commands/debug.rs", 1),
    ("apps/cli/src/commands/flycockpit.rs", 3),
    ("apps/cli/src/commands/mcp.rs", 1),
    ("apps/cli/src/lib.rs", 7),
    ("apps/cli/src/terminal_host.rs", 1),
    ("apps/cli/tests/e2e/agent_installation_daemon.rs", 1),
    ("apps/cli/tests/local_offline_acceptance_contract.rs", 1),
    ("apps/cli/tests/runtime_release_contract.rs", 1),
    ("crates/cockpit-core/src/computer/coordinator.rs", 1),
    ("crates/cockpit-core/src/computer/mod.rs", 3),
    ("crates/cockpit-core/src/computer/target_tests.rs", 2),
    ("crates/cockpit-core/src/credentials.rs", 2),
    ("crates/cockpit-core/src/daemon/agent_authoring.rs", 10),
    ("crates/cockpit-core/src/daemon/agent_installation.rs", 1),
    ("crates/cockpit-core/src/daemon/client_tests.rs", 1),
    ("crates/cockpit-core/src/daemon/fs_api.rs", 2),
    ("crates/cockpit-core/src/daemon/org_sync.rs", 1),
    ("crates/cockpit-core/src/daemon/remote_attempt/tests.rs", 1),
    ("crates/cockpit-core/src/daemon/server/attachments.rs", 1),
    ("crates/cockpit-core/src/daemon/server/dispatch.rs", 14),
    ("crates/cockpit-core/src/daemon/server/image_control_mutations/tests.rs", 2),
    ("crates/cockpit-core/src/daemon/server/tests.rs", 35),
    ("crates/cockpit-core/src/daemon/session_worker/tests.rs", 1),
    ("crates/cockpit-core/src/engine/agent/hooks/tests.rs", 1),
    ("crates/cockpit-core/src/engine/agent/outcome.rs", 1),
    ("crates/cockpit-core/src/engine/agent/tool_dispatch.rs", 1),
    ("crates/cockpit-core/src/engine/agent/turn_scheduler.rs", 23),
    ("crates/cockpit-core/src/engine/builtin/mod.rs", 4),
    ("crates/cockpit-core/src/engine/compact.rs", 1),
    ("crates/cockpit-core/src/engine/driver/tests/model_switch.rs", 4),
    ("crates/cockpit-core/src/engine/driver/tests/tools_apply.rs", 1),
    ("crates/cockpit-core/src/engine/driver/tests/turn_loop.rs", 1),
    ("crates/cockpit-core/src/engine/model/display_dispatch.rs", 1),
    ("crates/cockpit-core/src/image_generation/adapters/openrouter.rs", 1),
    ("crates/cockpit-core/src/image_generation_job.rs", 1),
    ("crates/cockpit-core/src/image_generation_runtime/tests.rs", 1),
    ("crates/cockpit-core/src/mcp/builtin.rs", 1),
    ("crates/cockpit-core/src/mcp/forwarded.rs", 1),
    ("crates/cockpit-core/src/onboarding_agent.rs", 1),
    ("crates/cockpit-core/src/redact/tests.rs", 1),
    ("crates/cockpit-core/src/sealed/tests/authorization.rs", 1),
    ("crates/cockpit-core/src/sealed/tests/marker_predicate.rs", 1),
    ("crates/cockpit-core/src/sealed/tests/non_enumeration.rs", 4),
    ("crates/cockpit-core/src/sealed/tests/orthogonality.rs", 1),
    ("crates/cockpit-core/src/sealed/tests/reference_matrix.rs", 8),
    ("crates/cockpit-core/src/secret_ref.rs", 4),
    ("crates/cockpit-core/src/secure_key/sealed_state.rs", 1),
    ("crates/cockpit-core/src/session/export/tests.rs", 1),
    ("crates/cockpit-core/src/session/lifecycle.rs", 2),
    ("crates/cockpit-core/src/session/sealed_values.rs", 2),
    ("crates/cockpit-core/src/tags.rs", 1),
    ("crates/cockpit-core/src/tools/bash/tests.rs", 22),
    ("crates/cockpit-core/src/tools/mcp_tool.rs", 1),
    ("crates/cockpit-core/src/worktree_orchestration/tests.rs", 3),
    ("crates/cockpit-core/src/worktree_orchestration/validation.rs", 1),
    ("crates/cockpit-core/tests/agent_tree_production_paths.rs", 20),
    ("crates/cockpit-core/tests/computer_live_production_paths.rs", 20),
    ("crates/cockpit-db/tests/local_release_schema_contract.rs", 7),
    ("crates/cockpit-proto/src/agent_authoring.rs", 1),
    ("crates/cockpit-proto/src/remote_device_identity_enrollment.rs", 1),
    ("crates/cockpit-proto/src/request.rs", 1),
    ("crates/cockpit-proto/tests/remote_device_identity_enrollment_conformance.rs", 1),
    ("crates/cockpit-tui/src/tui/app/async_actions.rs", 1),
    ("crates/cockpit-tui/src/tui/app/blocking_operation_tests.rs", 26),
    ("crates/cockpit-tui/src/tui/app/chat_header_tests.rs", 1),
    ("crates/cockpit-tui/src/tui/app/composer_controls_tests.rs", 9),
    ("crates/cockpit-tui/src/tui/app/control_request_tests.rs", 1),
    ("crates/cockpit-tui/src/tui/app/ctrl_c_tests.rs", 6),
    ("crates/cockpit-tui/src/tui/app/events.rs", 2),
    ("crates/cockpit-tui/src/tui/app/input.rs", 3),
    ("crates/cockpit-tui/src/tui/app/inventory_tests.rs", 8),
    ("crates/cockpit-tui/src/tui/app/mouse_gesture_app_tests.rs", 2),
    ("crates/cockpit-tui/src/tui/app/prediction.rs", 1),
    ("crates/cockpit-tui/src/tui/app/session_rail.rs", 1),
    ("crates/cockpit-tui/src/tui/app/session_setup.rs", 4),
    ("crates/cockpit-tui/src/tui/app/startup_first_paint_tests.rs", 1),
    ("crates/cockpit-tui/src/tui/history/tests.rs", 2),
    ("crates/cockpit-tui/src/tui/settings/image_sidecar/tests.rs", 1),
    ("crates/cockpit-tui/src/tui/settings/mcp_page.rs", 2),
    ("crates/cockpit-tui/src/tui/settings/pointer_acceptance_tests.rs", 2),
    ("crates/cockpit-tui/src/tui/settings/providers/tests.rs", 2),
    ("crates/cockpit-tui/src/tui/settings/tests.rs", 29),
    ("crates/cockpit-tui/tests/composer_registry_boundary.rs", 8),
)

MOD_DECL = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*(;|\{)"
)
PATH_ATTR = re.compile(r'#\[path\s*=\s*"([^"]+)"\s*\]')
CFG_ATTR = re.compile(r"#\[cfg\s*\((.*?)\)\]", re.S)
CFG_INNER = re.compile(r"#!\[cfg\s*\((.*?)\)\]", re.S)
TEST_ATTR = re.compile(r"#\[(?:tokio::)?test(?:\s*\([^)]*\))?\]")


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    argument: str


class CfgTok:
    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0

    def skip(self) -> None:
        while self.i < len(self.text) and self.text[self.i].isspace():
            self.i += 1

    def peek(self) -> str:
        self.skip()
        return self.text[self.i :][:1]

    def ident(self) -> str | None:
        self.skip()
        match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", self.text[self.i :])
        if not match:
            return None
        self.i += match.end()
        return match.group(0)

    def string(self) -> str:
        self.skip()
        if self.peek() != '"':
            return ""
        self.i += 1
        start = self.i
        while self.i < len(self.text) and self.text[self.i] != '"':
            if self.text[self.i] == "\\":
                self.i += 2
                continue
            self.i += 1
        value = self.text[start : self.i]
        if self.peek() == '"':
            self.i += 1
        return value

    def eat(self, ch: str) -> bool:
        if self.peek() == ch:
            self.i += 1
            return True
        return False


def parse_cfg_atom(tok: CfgTok):
    ident = tok.ident()
    if ident is None:
        return ("true",)
    if ident in {"all", "any", "not"}:
        if not tok.eat("("):
            return (ident,)
        args = []
        while tok.peek() and tok.peek() != ")":
            args.append(parse_cfg_atom(tok))
            tok.eat(",")
        tok.eat(")")
        return (ident, args)
    if tok.eat("="):
        return ("kv", ident, tok.string())
    return (ident,)


def dnf_or(left, right):
    return simplify_dnf(left + right)


def dnf_and(left, right):
    return simplify_dnf([a | b for a in left for b in right])


def simplify_dnf(dnf):
    if any(len(term) == 0 for term in dnf):
        return [frozenset()]
    unique = []
    for term in dnf:
        if any(term >= other and term != other for other in dnf):
            continue
        if term not in unique:
            unique.append(term)
    return unique


def cfg_dnf(node):
    kind = node[0]
    if kind == "true":
        return [frozenset()]
    if kind == "test":
        return [frozenset({"__test__"})]
    if kind == "kv":
        if node[1] == "feature":
            return [frozenset({node[2]})]
        return [frozenset()]
    if kind == "not":
        inner = node[1][0] if node[1] else ("true",)
        inner_dnf = cfg_dnf(inner)
        if inner_dnf == [frozenset()]:
            return []
        return [frozenset()]
    if kind == "all":
        acc = [frozenset()]
        for arg in node[1]:
            acc = dnf_and(acc, cfg_dnf(arg))
        return acc
    if kind == "any":
        acc = []
        for arg in node[1]:
            acc = dnf_or(acc, cfg_dnf(arg))
        return acc
    return [frozenset()]


def cfg_requires_test(inner: str) -> bool:
    try:
        dnf = cfg_dnf(parse_cfg_atom(CfgTok(inner)))
    except (IndexError, ValueError):
        return False
    if not dnf:
        return False
    return all("__test__" in term for term in dnf)


def _is_char_literal(src: str, i: int) -> bool:
    """True for `'x'` / `'\\n'`, false for lifetimes such as `'static`."""
    if i >= len(src) or src[i] != "'":
        return False
    if i + 1 >= len(src):
        return False
    nxt = src[i + 1]
    if nxt == "\\":
        return True
    return i + 2 < len(src) and src[i + 2] == "'"


def strip_comments_preserve_ws(src: str) -> tuple[str, tuple[tuple[int, int], ...]]:
    out: list[str] = []
    literals: list[tuple[int, int]] = []
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        if ch == "r" and i + 1 < n and src[i + 1] in '"#':
            hashes = 0
            k = i + 1
            while k < n and src[k] == "#":
                hashes += 1
                k += 1
            if k < n and src[k] == '"':
                start = len(out)
                out.extend(src[i : k + 1])
                k += 1
                close = '"' + "#" * hashes
                end = src.find(close, k)
                if end < 0:
                    out.extend(src[k:])
                    literals.append((start, len(out)))
                    break
                out.extend(src[k : end + len(close)])
                literals.append((start, len(out)))
                i = end + len(close)
                continue
        if ch == '"' or (ch == "'" and _is_char_literal(src, i)):
            quote = ch
            start = len(out)
            out.append(ch)
            i += 1
            while i < n:
                out.append(src[i])
                if src[i] == "\\":
                    i += 1
                    if i < n:
                        out.append(src[i])
                        i += 1
                    continue
                if src[i] == quote:
                    i += 1
                    break
                i += 1
            literals.append((start, len(out)))
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            out.extend("  ")
            i += 2
            depth = 1
            while i < n and depth:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    out.extend("  ")
                    i += 2
                    depth += 1
                    continue
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    out.extend("  ")
                    i += 2
                    depth -= 1
                    continue
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), tuple(literals)


def is_in_literal(ranges: tuple[tuple[int, int], ...], index: int) -> bool:
    for start, end in ranges:
        if start <= index < end:
            return True
        if start > index:
            return False
    return False


def skip_ws(src: str, i: int) -> int:
    n = len(src)
    while i < n and src[i] in " \t\r\n":
        i += 1
    return i


def skip_attr(src: str, i: int) -> int:
    if not src.startswith("#[", i) and not src.startswith("#![", i):
        return i
    j = src.find("[", i)
    depth = 0
    while j < len(src):
        if src[j] == "[":
            depth += 1
        elif src[j] == "]":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(src)


def matching_delimited(src: str, open_at: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    i = open_at
    n = len(src)
    in_string = False
    in_char = False
    escaped = False
    raw_close = None
    while i < n:
        ch = src[i]
        if raw_close is not None:
            if src.startswith(raw_close, i):
                i += len(raw_close)
                raw_close = None
                continue
            i += 1
            continue
        if in_string or in_char:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif (in_string and ch == '"') or (in_char and ch == "'"):
                in_string = False
                in_char = False
            i += 1
            continue
        if ch == "r" and i + 1 < n and src[i + 1] in '"#':
            hashes = 0
            k = i + 1
            while k < n and src[k] == "#":
                hashes += 1
                k += 1
            if k < n and src[k] == '"':
                raw_close = '"' + "#" * hashes
                i = k + 1
                continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == "'" and _is_char_literal(src, i):
            in_char = True
            i += 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def item_end(src: str, start: int) -> int:
    i = skip_ws(src, start)
    n = len(src)
    while i < n and (src.startswith("#[", i) or src.startswith("#![", i)):
        i = skip_ws(src, skip_attr(src, i))
    while i < n:
        ch = src[i]
        if ch == ";":
            return i + 1
        if ch == "{":
            return matching_delimited(src, i, "{", "}") + 1
        if ch == "(":
            i = matching_delimited(src, i, "(", ")") + 1
            continue
        i += 1
    return n


def preceding_attrs(src: str, index: int) -> str:
    i = index
    chunks: list[str] = []
    while i > 0:
        j = i
        while j > 0 and src[j - 1] in " \t\r\n":
            j -= 1
        if j == 0 or src[j - 1] != "]":
            break
        depth = 1
        k = j - 2
        while k >= 0 and depth:
            if src[k] == "]":
                depth += 1
            elif src[k] == "[":
                depth -= 1
            k -= 1
        l = k
        while l >= 0 and src[l] in " \t":
            l -= 1
        if l < 0 or src[l] != "#":
            break
        start = l
        if start > 0 and src[start - 1] == "!":
            start -= 1
            if start > 0 and src[start - 1] == "#":
                start -= 1
        chunks.append(src[start:i])
        i = start
    return "".join(reversed(chunks))


def path_from_attrs(attrs: str) -> str | None:
    match = PATH_ATTR.search(attrs)
    return match.group(1) if match else None


def resolve_mod_file(parent: Path, name: str, path_attr: str | None) -> Path | None:
    if path_attr is not None:
        candidate = (parent.parent / path_attr).resolve()
        return candidate if candidate.is_file() else None
    if parent.name in {"mod.rs", "lib.rs", "main.rs"}:
        directory = parent.parent
    else:
        directory = parent.parent / parent.stem
    for candidate in (directory / f"{name}.rs", directory / name / "mod.rs"):
        if candidate.is_file():
            return candidate.resolve()
    return None


def extract_string_literals(arg: str) -> list[str]:
    out: list[str] = []
    i, n = 0, len(arg)
    while i < n:
        ch = arg[i]
        if ch == "r" and i + 1 < n and arg[i + 1] in '"#':
            hashes = 0
            k = i + 1
            while k < n and arg[k] == "#":
                hashes += 1
                k += 1
            if k < n and arg[k] == '"':
                k += 1
                close = '"' + "#" * hashes
                end = arg.find(close, k)
                if end < 0:
                    break
                out.append(arg[k:end])
                i = end + len(close)
                continue
        if ch == '"':
            i += 1
            buf: list[str] = []
            while i < n:
                if arg[i] == "\\":
                    i += 1
                    if i < n:
                        buf.append(arg[i])
                        i += 1
                    continue
                if arg[i] == '"':
                    i += 1
                    break
                buf.append(arg[i])
                i += 1
            out.append("".join(buf))
            continue
        i += 1
    return out


def names_rs_file(arg: str) -> bool:
    strings = extract_string_literals(arg)
    if not strings:
        return False
    joined = "".join(strings)
    if joined.endswith(".rs"):
        return True
    return any(value.endswith(".rs") for value in strings)


def iter_include_str(src: str, literals: tuple[tuple[int, int], ...]):
    needle = "include_str!"
    start = 0
    while True:
        i = src.find(needle, start)
        if i < 0:
            return
        if is_in_literal(literals, i):
            start = i + len(needle)
            continue
        j = skip_ws(src, i + len(needle))
        if j >= len(src) or src[j] != "(":
            start = i + len(needle)
            continue
        close = matching_delimited(src, j, "(", ")")
        yield i, src[j + 1 : close]
        start = close + 1


def package_dirs(base: Path) -> list[Path]:
    found: list[Path] = []
    for top in SCAN_TOP:
        root = base / top
        if (root / "Cargo.toml").is_file():
            found.append(root)
        elif root.is_dir():
            for child in sorted(root.iterdir()):
                if (child / "Cargo.toml").is_file():
                    found.append(child)
    return found


def rust_files(package_dir: Path) -> list[Path]:
    files: list[Path] = []
    for folder in ("src", "tests"):
        root = package_dir / folder
        if root.is_dir():
            files.extend(path.resolve() for path in root.rglob("*.rs"))
    return files


def is_cargo_tests_file(path: Path, package_dir: Path) -> bool:
    try:
        rel = path.relative_to(package_dir.resolve())
    except ValueError:
        return False
    return len(rel.parts) >= 2 and rel.parts[0] == "tests"


def posix_rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def collect_hits_for_package(package_dir: Path, base: Path) -> list[Hit]:
    files = rust_files(package_dir)
    if not files:
        return []
    raws: dict[Path, str] = {}
    include_files: list[Path] = []
    for path in files:
        raw = path.read_text(encoding="utf-8", errors="replace")
        raws[path] = raw
        if "include_str!" in raw:
            include_files.append(path)
    if not include_files:
        return []

    needed = set(include_files)
    changed = True
    while changed:
        changed = False
        for path in list(needed):
            # Walk a few ancestors so `#[cfg(test)] mod foo;` marks foo.rs.
            directory = path.parent
            for candidate in (
                directory / "mod.rs",
                directory / "lib.rs",
                directory / "main.rs",
                directory.parent / f"{directory.name}.rs",
            ):
                resolved = candidate.resolve() if candidate.is_file() else None
                if resolved is not None and resolved in raws and resolved not in needed:
                    needed.add(resolved)
                    changed = True

    cache: dict[Path, tuple[str, tuple[tuple[int, int], ...]]] = {}

    def scan(path: Path) -> tuple[str, tuple[tuple[int, int], ...]]:
        cached = cache.get(path)
        if cached is None:
            cached = strip_comments_preserve_ws(raws[path])
            cache[path] = cached
        return cached

    test_files: set[Path] = set()
    for path in files:
        if is_cargo_tests_file(path, package_dir):
            test_files.add(path)

    for path in needed:
        src, literals = scan(path)
        for match in CFG_INNER.finditer(src):
            if is_in_literal(literals, match.start()):
                continue
            if cfg_requires_test(match.group(1)):
                test_files.add(path)

    graph_changed = True
    while graph_changed:
        graph_changed = False
        for path in needed:
            src, literals = scan(path)
            parent_is_test = path in test_files
            for match in MOD_DECL.finditer(src):
                if match.group(2) != ";":
                    continue
                if is_in_literal(literals, match.start()):
                    continue
                attrs = preceding_attrs(src, match.start())
                gated = parent_is_test
                for cfg in CFG_ATTR.finditer(attrs):
                    if cfg_requires_test(cfg.group(1)):
                        gated = True
                if not gated:
                    continue
                target = resolve_mod_file(path, match.group(1), path_from_attrs(attrs))
                if target is not None and target not in test_files:
                    test_files.add(target)
                    graph_changed = True

    hits: list[Hit] = []
    for path in include_files:
        src, literals = scan(path)
        spans: list[tuple[int, int]] = []
        if path in test_files:
            spans.append((0, len(src)))
        else:
            for match in CFG_ATTR.finditer(src):
                if is_in_literal(literals, match.start()):
                    continue
                if not cfg_requires_test(match.group(1)):
                    continue
                spans.append((match.start(), item_end(src, match.start())))
            for match in TEST_ATTR.finditer(src):
                if is_in_literal(literals, match.start()):
                    continue
                spans.append((match.start(), item_end(src, match.start())))
        if not spans:
            continue
        rel = posix_rel(path, base)
        for pos, arg in iter_include_str(src, literals):
            if not any(start <= pos < end for start, end in spans):
                continue
            if not names_rs_file(arg):
                continue
            hits.append(
                Hit(rel, src.count("\n", 0, pos) + 1, re.sub(r"\s+", " ", arg.strip())[:120])
            )
    return hits


def find_hits(base: Path) -> list[Hit]:
    hits: list[Hit] = []
    for package_dir in package_dirs(base):
        hits.extend(collect_hits_for_package(package_dir, base))
    hits.sort(key=lambda hit: (hit.path, hit.line, hit.argument))
    return hits


def die(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def _must_fail_allowlist(hits: list[Hit], allowlist: tuple[tuple[str, int], ...], why: str) -> None:
    try:
        check_allowlist(hits, allowlist=allowlist, verbose=False)
    except SystemExit as exc:
        if exc.code == 1:
            return
        raise
    die(why)


def self_test(repo_root: Path) -> None:
    fixtures = repo_root / FIXTURE_REL
    clean_lib = fixtures / "clean/crates/demo/src/lib.rs"
    if not clean_lib.is_file() or 'include_str!("helper.rs")' not in clean_lib.read_text(
        encoding="utf-8"
    ):
        die("clean fixture must keep a production include_str! of a .rs file")

    clean_hits = find_hits(fixtures / "clean")
    if clean_hits:
        formatted = "\n".join(f"  {hit.path}:{hit.line}: {hit.argument}" for hit in clean_hits)
        die(f"clean fixture produced source-scan hits:\n{formatted}")
    check_allowlist(clean_hits, allowlist=(), verbose=False)

    cases = (
        "violation-test-fn",
        "violation-cfg-test",
        "violation-cfg-test-file",
        "violation-inner-cfg",
        "violation-integration",
        "violation-concat",
    )
    for name in cases:
        hits = find_hits(fixtures / name)
        if not hits:
            die(f"{name} fixture produced no source-scan hits")
        _must_fail_allowlist(
            hits,
            (),
            f"{name} fixture hits were accepted by an empty allowlist",
        )

    _must_fail_allowlist(
        [Hit("scripts/fixtures/synthetic.rs", 1, '"lib.rs"')],
        (),
        "empty allowlist accepted a new source-scan file",
    )
    _must_fail_allowlist(
        [Hit("keep.rs", 1, '"a.rs"'), Hit("keep.rs", 2, '"b.rs"')],
        (("keep.rs", 1),),
        "count ratchet accepted a new hit in an allowlisted file",
    )
    _must_fail_allowlist(
        [],
        (("keep.rs", 1),),
        "stale allowlist entry was accepted after the file went clean",
    )


def dump_hits(hits: list[Hit]) -> None:
    grouped: dict[str, list[Hit]] = defaultdict(list)
    for hit in hits:
        grouped[hit.path].append(hit)
    for path in sorted(grouped):
        print(f"{path}: {len(grouped[path])}")
        for hit in grouped[path]:
            print(f"  {hit.line}: {hit.argument}")
    print(f"TOTAL files={len(grouped)} hits={len(hits)}", file=sys.stderr)


def check_allowlist(
    hits: list[Hit],
    allowlist: tuple[tuple[str, int], ...] | None = None,
    *,
    verbose: bool = True,
) -> None:
    actual: dict[str, list[Hit]] = defaultdict(list)
    for hit in hits:
        actual[hit.path].append(hit)
    expected = dict(ALLOWLIST if allowlist is None else allowlist)
    errors: list[str] = []

    for path in sorted(set(actual) | set(expected)):
        got = len(actual.get(path, []))
        want = expected.get(path)
        if want is None:
            details = ", ".join(f":{hit.line}" for hit in actual[path][:8])
            errors.append(
                f"new source-scan test in {path} ({got} hit(s){details}); "
                "replace include_str! of .rs with a behavioural assertion"
            )
            continue
        if got != want:
            if got == 0:
                errors.append(
                    f"{path}: allowlist count {want} but the file is clean; "
                    "remove it from ALLOWLIST"
                )
            elif got < want:
                errors.append(
                    f"{path}: allowlist count {want} but found {got}; lower the ratchet"
                )
            else:
                errors.append(
                    f"{path}: allowlist count {want} but found {got}; "
                    "do not add source-scan tests"
                )

    if errors:
        if verbose:
            print("Source-scan test invariant failed:", file=sys.stderr)
            for error in errors:
                print(f"  {error}", file=sys.stderr)
        raise SystemExit(1)


def assert_allowlist_shape() -> None:
    paths = [path for path, _ in ALLOWLIST]
    if paths != sorted(paths):
        die("ALLOWLIST must be sorted by path")
    if len(paths) != len(set(paths)):
        die("ALLOWLIST has duplicate paths")
    if any(count < 1 for _, count in ALLOWLIST):
        die("ALLOWLIST counts must be positive; delete a cleaned file instead")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    repo_root = Path(__file__).resolve().parents[2]
    os.chdir(repo_root)

    dump = "--dump" in argv or os.environ.get("DUMP_HITS") == "1"
    skip_self_test = "--skip-self-test" in argv
    self_test_only = "--self-test" in argv
    if self_test_only and skip_self_test:
        die("cannot combine --self-test and --skip-self-test")

    assert_allowlist_shape()

    if not skip_self_test:
        self_test(repo_root)
        print("no-source-scan fixture self-test passed")
        if self_test_only:
            return 0

    hits = find_hits(repo_root)
    if dump:
        dump_hits(hits)
        return 0
    check_allowlist(hits)
    print(
        "no-source-scan test invariant intact "
        f"({len(hits)} allowlisted hit(s) across {len({hit.path for hit in hits})} file(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
