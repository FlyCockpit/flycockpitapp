#!/usr/bin/env bash
set -euo pipefail

# Feature-gated test coverage ratchet.
#
# Every test that compiles only when a Cargo feature is on — `[[test]]`
# `required-features` and `#[cfg(feature = "...")]` on a `#[test]` /
# `#[tokio::test]`, including module- and crate-level cfg inheritance — must
# execute on a CI gate whose nextest/test invocation selects that package and
# enables that feature.
#
# Compile-only steps (`cargo check` / `clippy` / `build`) and
# `continue-on-error` jobs do not count. A nextest `-E` filter covers only the
# tests it positively selects (`test(name)` / `binary(name)`); any other filter
# covers nothing. `--run-ignored ignored-only` covers ignored tests only.
#
# Features in LIVE_INFRA_FEATURES may be executed by a workflow_dispatch
# opt-in. Every other feature must run on a blocking pull_request/push job.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(".")
WORKFLOWS = ROOT / ".github" / "workflows"

LIVE_INFRA_FEATURES = frozenset(
    {
        "daemon-custody-pkcs11",
        "turn-coturn-conformance",
    }
)

# package -> feature -> same-package features it enables (Cargo feature graph).
FEATURE_GRAPH: dict[str, dict[str, set[str]]] = {}

TEST_ATTR = re.compile(r"#\[(?:tokio::)?test(?:\s*\([^)]*\))?\]")
CFG_ATTR = re.compile(r"#\[cfg\s*\((.*?)\)\]", re.S)
CFG_INNER_ATTR = re.compile(r"#!\[cfg\s*\((.*?)\)\]", re.S)
IGNORE_ATTR = re.compile(r"#\[ignore\b")
MOD_DECL = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*(;|\{)"
)
JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.M)
TOKEN_RE = re.compile(r"""(?:[^\s"']+|"[^"]*"|'[^']*')""")


def die(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Comment stripping
# ---------------------------------------------------------------------------

def strip_comments_preserve_ws(src: str) -> str:
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        if ch == '"' or ch == "'":
            quote = ch
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
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            out.extend("  ")
            i += 2
            while i < n - 1 and not (src[i] == "*" and src[i + 1] == "/"):
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n - 1:
                out.extend("  ")
                i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_FILE_CACHE: dict[Path, str] = {}


def stripped(path: Path) -> str:
    cached = _FILE_CACHE.get(path)
    if cached is None:
        cached = strip_comments_preserve_ws(
            path.read_text(encoding="utf-8", errors="replace")
        )
        _FILE_CACHE[path] = cached
    return cached


# ---------------------------------------------------------------------------
# cfg(*) → DNF of required cargo features
#
# `test` is true (these are test builds). Target predicates (`unix`,
# `target_os = "linux"`, …) are treated as true so a linux CI leg can cover
# them. `any(test, feature = "X")` is therefore not cargo-feature-gated.
# ---------------------------------------------------------------------------

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
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", self.text[self.i :])
        if not m:
            return None
        self.i += m.end()
        return m.group(0)

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


def parse_cfg(text: str):
    tok = CfgTok(text)
    node = parse_cfg_or(tok)
    return node


def parse_cfg_or(tok: CfgTok):
    left = parse_cfg_and(tok)
    while tok.ident() is None and False:
        break
    return left


def parse_cfg_and(tok: CfgTok):
    return parse_cfg_atom(tok)


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


def dnf_or(a: list[frozenset[str]], b: list[frozenset[str]]) -> list[frozenset[str]]:
    return simplify_dnf(a + b)


def dnf_and(a: list[frozenset[str]], b: list[frozenset[str]]) -> list[frozenset[str]]:
    return simplify_dnf([x | y for x in a for y in b])


def simplify_dnf(dnf: list[frozenset[str]]) -> list[frozenset[str]]:
    if any(len(term) == 0 for term in dnf):
        return [frozenset()]
    unique: list[frozenset[str]] = []
    for term in dnf:
        if any(term >= other and term != other for other in dnf):
            continue
        if term not in unique:
            unique.append(term)
    return unique


def cfg_dnf(node) -> list[frozenset[str]]:
    """DNF of cargo features that must be on. `[frozenset()]` means already true."""
    kind = node[0]
    if kind == "true":
        return [frozenset()]
    if kind == "test":
        return [frozenset()]
    if kind == "kv":
        key, value = node[1], node[2]
        if key == "feature":
            return [frozenset({value})]
        # target_os / target_family / … — assume a CI runner satisfies them.
        return [frozenset()]
    if kind == "not":
        inner = node[1][0] if node[1] else ("true",)
        inner_dnf = cfg_dnf(inner)
        # `not(feature = "X")` is true on the default (feature-off) build.
        # `not(test)` is false in a test build.
        if inner_dnf == [frozenset()]:
            return []
        return [frozenset()]
    if kind == "all":
        acc = [frozenset()]
        for arg in node[1]:
            acc = dnf_and(acc, cfg_dnf(arg))
        return acc
    if kind == "any":
        acc: list[frozenset[str]] = []
        for arg in node[1]:
            acc = dnf_or(acc, cfg_dnf(arg))
        return acc
    # Bare ident: unix/windows/linux/macos/… — assume a runner exists.
    return [frozenset()]


def cfg_text_dnf(inner: str) -> list[frozenset[str]]:
    try:
        return cfg_dnf(parse_cfg(inner))
    except (IndexError, ValueError):
        return [frozenset()]


def cargo_features_in(dnf: list[frozenset[str]]) -> frozenset[str]:
    out: set[str] = set()
    for term in dnf:
        out.update(term)
    return frozenset(out)


# ---------------------------------------------------------------------------
# Source scan
# ---------------------------------------------------------------------------

def rust_files(package_dir: Path) -> list[Path]:
    files: list[Path] = []
    for folder in ("src", "tests"):
        root = package_dir / folder
        if not root.is_dir():
            continue
        files.extend(root.rglob("*.rs"))
    return files


def resolve_mod_file(parent: Path, name: str) -> Path | None:
    candidates = [
        parent.parent / f"{name}.rs",
        parent.parent / name / "mod.rs",
    ]
    if parent.name == "mod.rs":
        candidates.insert(0, parent.parent / f"{name}.rs")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


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


def skip_ws(src: str, i: int) -> int:
    n = len(src)
    while i < n and src[i] in " \t\r\n":
        i += 1
    return i


def collect_following_attrs(src: str, i: int) -> tuple[str, int]:
    chunks: list[str] = []
    j = skip_ws(src, i)
    while src.startswith("#[", j):
        end = skip_attr(src, j)
        chunks.append(src[j:end])
        j = skip_ws(src, end)
    return "".join(chunks), j


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


def dnf_from_attrs(attrs: str) -> list[frozenset[str]]:
    acc = [frozenset()]
    for match in CFG_ATTR.finditer(attrs):
        acc = dnf_and(acc, cfg_text_dnf(match.group(1)))
    for match in CFG_INNER_ATTR.finditer(attrs):
        acc = dnf_and(acc, cfg_text_dnf(match.group(1)))
    return acc


def collect_file_inherited_dnf(package_dir: Path) -> dict[Path, list[frozenset[str]]]:
    inherited: dict[Path, list[frozenset[str]]] = {}
    files = rust_files(package_dir)
    for path in files:
        text = stripped(path)
        acc = [frozenset()]
        for match in CFG_INNER_ATTR.finditer(text):
            acc = dnf_and(acc, cfg_text_dnf(match.group(1)))
        if acc != [frozenset()]:
            inherited[path] = acc

    changed = True
    while changed:
        changed = False
        for path in files:
            text = stripped(path)
            current = inherited.get(path, [frozenset()])
            for match in MOD_DECL.finditer(text):
                if match.group(2) != ";":
                    continue
                attrs = preceding_attrs(text, match.start())
                dnf = dnf_and(current, dnf_from_attrs(attrs))
                if dnf == [frozenset()]:
                    continue
                target = resolve_mod_file(path, match.group(1))
                if target is None:
                    continue
                before = inherited.get(target, [frozenset()])
                merged = dnf_and(before, dnf) if target in inherited else dnf
                if merged != before:
                    inherited[target] = merged
                    changed = True
    return inherited


@dataclass(frozen=True)
class GatedTest:
    package: str
    dnf: tuple[frozenset[str], ...]
    path: Path
    name: str
    ignored: bool
    kind: str  # "fn" | "bin"

    @property
    def features(self) -> frozenset[str]:
        return cargo_features_in(list(self.dnf))


def fn_name_after(src: str, index: int) -> str:
    match = re.search(r"\b(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)", src[index:])
    return match.group(1) if match else "<unnamed>"


def matching_brace(src: str, open_at: int) -> int:
    depth = 0
    i = open_at
    n = len(src)
    while i < n:
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def inline_module_ranges(src: str) -> list[tuple[int, int, list[frozenset[str]]]]:
    """(start, end, dnf) for each `#[cfg] mod name { ... }` inline module."""
    ranges: list[tuple[int, int, list[frozenset[str]]]] = []
    for match in MOD_DECL.finditer(src):
        if match.group(2) != "{":
            continue
        attrs = preceding_attrs(src, match.start())
        dnf = dnf_from_attrs(attrs)
        if dnf == [frozenset()]:
            continue
        end = matching_brace(src, match.end() - 1)
        ranges.append((match.start(), end, dnf))
    return ranges


def scan_source_tests(
    package: str,
    path: Path,
    file_dnf: list[frozenset[str]],
    extra: frozenset[str],
) -> list[GatedTest]:
    src = stripped(path)
    if "#[test]" not in src and "#[tokio::test" not in src:
        return []
    extra_dnf = [extra] if extra else [frozenset()]
    crate_dnf = file_dnf
    for match in CFG_INNER_ATTR.finditer(src):
        crate_dnf = dnf_and(crate_dnf, cfg_text_dnf(match.group(1)))
    modules = inline_module_ranges(src)
    tests: list[GatedTest] = []
    for test_match in TEST_ATTR.finditer(src):
        following, after = collect_following_attrs(src, test_match.end())
        attrs = preceding_attrs(src, test_match.start()) + test_match.group(0) + following
        ignored = bool(IGNORE_ATTR.search(attrs))
        dnf = dnf_and(crate_dnf, extra_dnf)
        for start, end, module_dnf in modules:
            if start <= test_match.start() <= end:
                dnf = dnf_and(dnf, module_dnf)
        dnf = dnf_and(dnf, dnf_from_attrs(attrs))
        if not dnf or dnf == [frozenset()]:
            continue
        tests.append(
            GatedTest(
                package,
                tuple(dnf),
                path,
                fn_name_after(src, after),
                ignored,
                "fn",
            )
        )
    return tests


def load_feature_graph() -> None:
    FEATURE_GRAPH.clear()
    for package_dir in parse_workspace_members():
        data = tomllib.loads((package_dir / "Cargo.toml").read_text(encoding="utf-8"))
        package = data.get("package", {}).get("name")
        if not package:
            continue
        graph: dict[str, set[str]] = {}
        for feature, deps in (data.get("features") or {}).items():
            enabled: set[str] = set()
            for dep in deps or []:
                if not isinstance(dep, str):
                    continue
                if dep.startswith("dep:") or "/" in dep:
                    continue
                enabled.add(dep)
            graph[feature] = enabled
        FEATURE_GRAPH[package] = graph


def feature_closure(package: str, seeds: set[str]) -> set[str]:
    out = set(seeds)
    work = list(seeds)
    graph = FEATURE_GRAPH.get(package, {})
    while work:
        current = work.pop()
        for dep in graph.get(current, ()):
            if dep not in out:
                out.add(dep)
                work.append(dep)
    return out


def parse_workspace_members() -> list[Path]:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    members = cargo.get("workspace", {}).get("members", [])
    if not members:
        die("workspace.members missing from Cargo.toml")
    paths = []
    for member in members:
        path = ROOT / member
        if not (path / "Cargo.toml").is_file():
            die(f"workspace member {member} has no Cargo.toml")
        paths.append(path)
    return paths


def discover_gated_tests() -> list[GatedTest]:
    found: list[GatedTest] = []
    seen: set[tuple] = set()

    def add(test: GatedTest) -> None:
        if not test.features:
            return
        key = (test.package, test.dnf, str(test.path), test.name, test.ignored, test.kind)
        if key in seen:
            return
        seen.add(key)
        found.append(test)

    for package_dir in parse_workspace_members():
        data = tomllib.loads((package_dir / "Cargo.toml").read_text(encoding="utf-8"))
        package = data.get("package", {}).get("name")
        if not package:
            die(f"{package_dir}/Cargo.toml missing package.name")
        declared = set((data.get("features") or {}).keys()) - {"default"}
        inherited = collect_file_inherited_dnf(package_dir)
        required_by_file: dict[Path, frozenset[str]] = {}
        for entry in data.get("test", []) or []:
            name = entry.get("name")
            if not name:
                continue
            rel = entry.get("path", f"tests/{name}.rs")
            path = package_dir / rel
            required = frozenset(entry.get("required-features") or [])
            required_by_file[path] = required
            # Record the binary only when the file has no #[test] we will scan
            # (or the file is missing). Avoid a fake non-ignored bin next to
            # ignored tests in the same target.
            if required and not path.is_file():
                add(
                    GatedTest(
                        package, (required,), path, name, False, "bin"
                    )
                )

        for path in rust_files(package_dir):
            extra = required_by_file.get(path, frozenset())
            file_dnf = inherited.get(path, [frozenset()])
            for test in scan_source_tests(package, path, file_dnf, extra):
                if not test.features <= declared | extra:
                    # Drop terms that mention unknown names (should not happen
                    # after cfg parsing, but keep the bound tight).
                    filtered = tuple(term & (declared | extra) for term in test.dnf)
                    filtered = tuple(term for term in filtered if term)
                    if not filtered:
                        continue
                    test = GatedTest(
                        test.package, filtered, test.path, test.name, test.ignored, test.kind
                    )
                if not test.features:
                    continue
                add(test)
            # Manifest-gated binary with tests: the tests already carry extra.
            # If the file has no tests, still require the binary to run.
            if extra and path in required_by_file:
                src = stripped(path) if path.is_file() else ""
                if "#[test]" not in src and "#[tokio::test" not in src:
                    add(
                        GatedTest(
                            package,
                            (extra,),
                            path,
                            path.stem,
                            False,
                            "bin",
                        )
                    )
    return found


# ---------------------------------------------------------------------------
# Workflow / invocation parsing
# ---------------------------------------------------------------------------

def split_jobs(text: str) -> dict[str, str]:
    jobs_at = text.find("\njobs:\n")
    if jobs_at < 0:
        return {}
    body = text[jobs_at + len("\njobs:\n") :]
    matches = list(JOB_HEADER.finditer(body))
    jobs = {}
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(body)
        jobs[match.group(1)] = body[start:end]
    return jobs


def workflow_triggers(text: str) -> set[str]:
    events: set[str] = set()
    on_list = re.search(r"(?m)^on:\s*\[([^\]]+)\]", text)
    if on_list:
        for part in on_list.group(1).split(","):
            events.add(part.strip().strip("'\""))
        return events
    on_map = re.search(r"(?m)^(?:\"on\"|on):\s*\n((?:  .*\n)+)", text)
    if on_map:
        for line in on_map.group(1).splitlines():
            key = line.strip()
            if key.endswith(":"):
                key = key[:-1].strip()
            key = key.strip("'\"")
            if key and not key.startswith("#"):
                events.add(key)
    return events


def job_continue_on_error(job: str) -> bool:
    return bool(re.search(r"(?m)^\s+continue-on-error:\s*true\s*$", job))


def job_if(job: str) -> str:
    match = re.search(r"(?m)^\s+if:\s*(.+)$", job)
    return match.group(1).strip() if match else ""


def is_blocking_job(triggers: set[str], job_if_expr: str, continue_on_error: bool) -> bool:
    if continue_on_error:
        return False
    if "pull_request" not in triggers and "push" not in triggers:
        return False
    if "workflow_dispatch" in job_if_expr and "inputs." in job_if_expr:
        return False
    if re.search(r"github\.event_name\s*==\s*'workflow_dispatch'", job_if_expr):
        return False
    return True


def is_opt_in_job(job_if_expr: str) -> bool:
    return "workflow_dispatch" in job_if_expr and "inputs." in job_if_expr


def folded_run_scripts(job: str) -> list[str]:
    scripts: list[str] = []
    lines = job.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped_line = line.lstrip()
        if not stripped_line.startswith("run:"):
            i += 1
            continue
        rest = stripped_line[len("run:") :].strip()
        indent = len(line) - len(line.lstrip(" "))
        if rest in (">", "|", ">-", "|-"):
            folded = rest.startswith(">")
            block: list[str] = []
            i += 1
            while i < len(lines):
                nxt = lines[i]
                if not nxt.strip():
                    block.append("")
                    i += 1
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= indent:
                    break
                prefix = " " * (indent + 2)
                block.append(nxt[len(prefix) :] if nxt.startswith(prefix) else nxt.lstrip())
                i += 1
            if folded:
                scripts.append(" ".join(part.strip() for part in block if part.strip()))
            else:
                scripts.append("\n".join(block))
            continue
        scripts.append(rest)
        i += 1
    return scripts


def tokenize(command: str) -> list[str]:
    tokens = []
    for match in TOKEN_RE.finditer(command):
        tok = match.group(0)
        if (tok.startswith('"') and tok.endswith('"')) or (
            tok.startswith("'") and tok.endswith("'")
        ):
            tok = tok[1:-1]
        tokens.append(tok)
    return tokens


@dataclass
class Invocation:
    workflow: str
    job: str
    blocking: bool
    opt_in: bool
    packages: set[str] | None
    excluded: set[str]
    workspace: bool
    features: dict[str, set[str]]
    unqualified_features: set[str]
    all_features: bool
    e_filter: str | None
    run_ignored: str | None
    command: str

    def selects_package(self, package: str) -> bool:
        if package in self.excluded:
            return False
        if self.workspace:
            return True
        if self.packages is None:
            return False
        return package in self.packages

    def enabled_features(self, package: str) -> set[str]:
        if self.all_features:
            return set(FEATURE_GRAPH.get(package, {}))
        seeds = set(self.unqualified_features)
        seeds.update(self.features.get(package, set()))
        return feature_closure(package, seeds)

    def enables_feature(self, package: str, feature: str) -> bool:
        return feature in self.enabled_features(package)

    def enables_term(self, package: str, term: frozenset[str]) -> bool:
        return all(self.enables_feature(package, feature) for feature in term)

    def ignored_mode(self) -> str:
        if self.run_ignored == "ignored-only":
            return "ignored"
        if self.run_ignored == "all":
            return "all"
        return "non-ignored"

    def filter_matches(self, test: GatedTest) -> bool:
        if not self.e_filter:
            return True
        expr = self.e_filter.strip()
        match = re.fullmatch(r"test\(([^)]+)\)", expr)
        if match:
            return match.group(1) in test.name
        match = re.fullmatch(r"binary\(([^)]+)\)", expr)
        if match:
            needle = match.group(1)
            return needle in test.name or needle in test.path.stem
        return False


def parse_cargo_test_command(
    command: str,
    workflow: str,
    job: str,
    blocking: bool,
    opt_in: bool,
) -> Invocation | None:
    tokens = tokenize(command)
    if len(tokens) < 3 or tokens[0] != "cargo":
        return None
    tool = tokens[1]
    if tool not in {"nextest", "test"}:
        return None
    rest = tokens[2:]
    if tool == "nextest":
        if not rest or rest[0] != "run":
            return None
        rest = rest[1:]
    if "--doc" in rest:
        return None
    packages: set[str] = set()
    excluded: set[str] = set()
    workspace = False
    unqualified: set[str] = set()
    qualified: dict[str, set[str]] = defaultdict(set)
    all_features = False
    e_filter: str | None = None
    run_ignored: str | None = None
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in {"-p", "--package"} and i + 1 < len(rest):
            packages.add(rest[i + 1])
            i += 2
            continue
        if tok == "--workspace":
            workspace = True
            i += 1
            continue
        if tok == "--exclude" and i + 1 < len(rest):
            excluded.add(rest[i + 1])
            i += 2
            continue
        if tok in {"--features", "-F"} and i + 1 < len(rest):
            for item in rest[i + 1].split(","):
                item = item.strip()
                if not item:
                    continue
                if "/" in item:
                    pkg, feat = item.split("/", 1)
                    qualified[pkg].add(feat)
                else:
                    unqualified.add(item)
            i += 2
            continue
        if tok.startswith("--features="):
            for item in tok.split("=", 1)[1].split(","):
                item = item.strip()
                if not item:
                    continue
                if "/" in item:
                    pkg, feat = item.split("/", 1)
                    qualified[pkg].add(feat)
                else:
                    unqualified.add(item)
            i += 1
            continue
        if tok == "--all-features":
            all_features = True
            i += 1
            continue
        if tok in {"-E", "--filterset"} and i + 1 < len(rest):
            e_filter = rest[i + 1]
            i += 2
            continue
        if tok == "--run-ignored" and i + 1 < len(rest):
            run_ignored = rest[i + 1]
            i += 2
            continue
        i += 1
    if workspace:
        selected: set[str] | None = None
    elif packages:
        selected = packages
    else:
        return None
    return Invocation(
        workflow=workflow,
        job=job,
        blocking=blocking,
        opt_in=opt_in,
        packages=selected,
        excluded=excluded,
        workspace=workspace,
        features=dict(qualified),
        unqualified_features=unqualified,
        all_features=all_features,
        e_filter=e_filter,
        run_ignored=run_ignored,
        command=command,
    )


def iter_commands(script: str) -> list[str]:
    commands = [line.strip() for line in script.splitlines() if line.strip()]
    joined = " ".join(script.split())
    if ("cargo nextest" in joined or "cargo test" in joined) and joined not in commands:
        commands.append(joined)
    return commands


def discover_invocations() -> list[Invocation]:
    invocations: list[Invocation] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        triggers = workflow_triggers(text)
        for job_name, job in split_jobs(text).items():
            cont = job_continue_on_error(job)
            if_expr = job_if(job)
            blocking = is_blocking_job(triggers, if_expr, cont)
            opt_in = is_opt_in_job(if_expr)
            for script in folded_run_scripts(job):
                for command in iter_commands(script):
                    parsed = parse_cargo_test_command(
                        command, path.name, job_name, blocking, opt_in
                    )
                    if parsed is not None:
                        invocations.append(parsed)
    return invocations


def covers(inv: Invocation, test: GatedTest) -> bool:
    if not inv.selects_package(test.package):
        return False
    if not any(inv.enables_term(test.package, term) for term in test.dnf):
        return False
    mode = inv.ignored_mode()
    if mode == "non-ignored" and test.ignored:
        return False
    if mode == "ignored" and not test.ignored:
        return False
    if not inv.filter_matches(test):
        return False
    return True


def main() -> int:
    load_feature_graph()
    tests = discover_gated_tests()
    invocations = discover_invocations()
    missing: list[str] = []

    for test in sorted(tests, key=lambda t: (t.package, str(t.features), t.name, str(t.path))):
        matches = [inv for inv in invocations if covers(inv, test)]
        blocking = [m for m in matches if m.blocking]
        opt_in = [m for m in matches if m.opt_in]
        live = bool(test.features & LIVE_INFRA_FEATURES)
        if blocking:
            continue
        if live and opt_in:
            continue
        feats = ",".join(sorted(test.features)) or "?"
        where = (
            f"{test.package} features={feats} {test.kind}:{test.name} "
            f"({test.path.as_posix()}"
        )
        if test.ignored:
            where += ", ignored"
        where += ")"
        if matches and not live:
            where += f" only on non-blocking {[m.job for m in matches]}"
        missing.append(where)

    if missing:
        print("feature-gated tests missing an executing CI gate:", file=sys.stderr)
        for line in missing:
            print(f"  {line}", file=sys.stderr)
        print(
            "\nEach cargo-feature-gated test must run on a cargo nextest/test "
            "invocation that selects the package and enables the required "
            "feature(s). Compile-only and continue-on-error jobs do not count. "
            "Live-infra features "
            f"({', '.join(sorted(LIVE_INFRA_FEATURES))}) may be workflow_dispatch "
            "opt-ins; every other feature must be a blocking PR/push job.",
            file=sys.stderr,
        )
        return 1

    by_pair: dict[tuple[str, str], int] = defaultdict(int)
    for test in tests:
        for feature in test.features:
            by_pair[(test.package, feature)] += 1
    print("feature-gated test coverage:")
    for (package, feature), count in sorted(by_pair.items()):
        kind = "opt-in live-infra" if feature in LIVE_INFRA_FEATURES else "blocking"
        print(f"  {package} / {feature}: {count} test(s), {kind}")
    print(
        f"{len(tests)} gated tests across {len(by_pair)} package/feature pairs are covered"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
