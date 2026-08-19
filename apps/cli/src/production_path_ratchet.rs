//! Production-path allow-list for CLI SQLite / vault construction.
//!
//! Later CLI-via-daemon prompts shrink this list. A warning is not enough.
//! Each entry is an exact file + forbidden symbol + occurrence count. A new
//! open in an allow-listed file fails.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &[
    "Db::open_default",
    "CredentialStore::open",
    "vault_for_db",
    "open_for_db",
    "SealedCompartment::open_default",
];

/// Cited production sites. Counts are after `#[cfg(test)]` modules are stripped.
const ALLOWED: &[(&str, &str, usize)] = &[
    ("commands/ask.rs", "Db::open_default", 1),
    ("commands/ask.rs", "vault_for_db", 1),
    ("commands/assistant.rs", "Db::open_default", 4),
    ("commands/connect.rs", "Db::open_default", 1),
    ("commands/connect.rs", "vault_for_db", 1),
    ("commands/debug.rs", "Db::open_default", 1),
    ("commands/export.rs", "Db::open_default", 1),
    ("commands/export.rs", "vault_for_db", 1),
    ("commands/kcl.rs", "Db::open_default", 1),
    ("commands/packages.rs", "Db::open_default", 4),
    ("commands/session.rs", "Db::open_default", 2),
    ("commands/sync.rs", "Db::open_default", 1),
    ("commands/sync.rs", "vault_for_db", 1),
];

fn repo_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn relative_src(path: &Path) -> String {
    path.strip_prefix(repo_src())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn production_source(path: &Path) -> String {
    let raw = fs::read_to_string(path).unwrap();
    strip_test_modules(&raw)
}

fn strip_test_modules(src: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    let bytes = src.as_bytes();
    while i < src.len() {
        if let Some(rel) = src[i..].find("#[cfg(test)]") {
            out.push_str(&src[i..i + rel]);
            let after = i + rel + "#[cfg(test)]".len();
            if let Some(mod_rel) = src[after..].find('{') {
                let mut depth = 0;
                let mut j = after + mod_rel;
                while j < src.len() {
                    match bytes[j] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j;
            } else {
                i = after;
            }
            continue;
        }
        out.push_str(&src[i..]);
        break;
    }
    out
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if name == "tests" {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if !name.contains("test") && name != "production_path_ratchet.rs" {
                out.push(path);
            }
        }
    }
}

fn count_matches(source: &str, needle: &str) -> usize {
    source.matches(needle).count()
}

/// Production settings/model paths are a stricter boundary than the older
/// CLI-wide DB allow-list above.  Keep this inventory explicit: adding a new
/// settings or model path without adding it here would silently put it outside
/// the ratchet.
const DAEMON_ONLY_SYMBOLS: &[&str] = &[
    "CredentialStore::open",
    "credentials::default_path(",
    "Db::open_default",
    "envref::resolve(",
    "vault_for_db",
    "secret_ref::load_effective",
    "resolve_provider_request",
    "fetch_models_for_provider",
    "persist_provider",
    "fetch_all_provider_usage",
];

const CLI_DAEMON_ONLY_FILES: &[&str] = &[
    "apps/cli/src/commands/setup.rs",
    "apps/cli/src/commands/providers.rs",
    "apps/cli/src/commands/models.rs",
    "apps/cli/src/commands/fetch_models.rs",
    "apps/cli/src/commands/config.rs",
    // `mcp add` publishes MCP config through the owner-remoted `SaveMcpConfig`
    // RPC so it inherits the daemon's atomic cross-kind ownership guard rather
    // than writing `.cockpit/mcp.json` directly.
    "apps/cli/src/commands/mcp.rs",
];

/// The two non-settings TUI app files the daemon-only inventory must also scan.
/// Kept as a named constant so the inventory assertion can verify each one is
/// actually present rather than merely counting entries.
const TUI_APP_DAEMON_ONLY_FILES: &[&str] = &[
    "crates/cockpit-tui/src/tui/app/models_refresh.rs",
    "crates/cockpit-tui/src/tui/app/async_actions.rs",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn daemon_only_paths() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut paths = CLI_DAEMON_ONLY_FILES
        .iter()
        .map(|path| root.join(path))
        .collect::<Vec<_>>();
    let settings = root.join("crates/cockpit-tui/src/tui/settings");
    collect_rs_files(&settings, &mut paths);
    for rel in TUI_APP_DAEMON_ONLY_FILES {
        paths.push(root.join(rel));
    }
    paths
}

fn is_test_file(path: &Path) -> bool {
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        value == "test" || value == "tests"
    }) || path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.contains("test"))
}

/// Replace comments and literals with spaces while retaining byte offsets and
/// code punctuation.  This keeps the ratchet from reporting a documentation
/// example or a test fixture string as a production call.
fn mask_non_code(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut masked = bytes.to_vec();
    let mut i = 0;
    let mut block_depth = 0usize;
    while i < bytes.len() {
        if block_depth > 0 {
            if bytes.get(i..i + 2) == Some(b"/*") {
                masked[i] = b' ';
                masked[i + 1] = b' ';
                block_depth += 1;
                i += 2;
            } else if bytes.get(i..i + 2) == Some(b"*/") {
                masked[i] = b' ';
                masked[i + 1] = b' ';
                block_depth -= 1;
                i += 2;
            } else {
                if bytes[i] != b'\n' {
                    masked[i] = b' ';
                }
                i += 1;
            }
            continue;
        }
        if bytes.get(i..i + 2) == Some(b"//") {
            masked[i] = b' ';
            masked[i + 1] = b' ';
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                masked[i] = b' ';
                i += 1;
            }
            continue;
        }
        if bytes.get(i..i + 2) == Some(b"/*") {
            masked[i] = b' ';
            masked[i + 1] = b' ';
            block_depth = 1;
            i += 2;
            continue;
        }

        // Raw strings (including byte raw strings) can contain arbitrary
        // braces and comments.  Detect the prefix, then mask through the
        // matching quote/hash suffix.
        let raw_prefix = if bytes[i] == b'r' {
            Some(i + 1)
        } else if bytes[i] == b'b' && bytes.get(i + 1) == Some(&b'r') {
            Some(i + 2)
        } else {
            None
        };
        if let Some(mut quote) = raw_prefix {
            while quote < bytes.len() && bytes[quote] == b'#' {
                quote += 1;
            }
            if quote < bytes.len() && bytes[quote] == b'"' {
                let hashes = quote - raw_prefix.unwrap();
                let end_marker = format!("\"{}", "#".repeat(hashes));
                if let Some(end_rel) = source[quote + 1..].find(&end_marker) {
                    let end = quote + 1 + end_rel + end_marker.len();
                    for byte in &mut masked[i..end] {
                        if *byte != b'\n' {
                            *byte = b' ';
                        }
                    }
                    i = end;
                    continue;
                }
            }
        }

        // Character literals can contain braces used by the test-item
        // balancer (notably `'}'`).  Do not treat lifetimes such as `'a` as
        // literals: only enter this branch for an escaped character or a
        // one-byte character followed immediately by its closing quote.
        if bytes[i] == b'\''
            && (bytes.get(i + 1) == Some(&b'\\') || bytes.get(i + 2) == Some(&b'\''))
        {
            masked[i] = b' ';
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                let byte = bytes[i];
                if byte != b'\n' {
                    masked[i] = b' ';
                }
                i += 1;
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'\'' {
                    break;
                }
            }
            continue;
        }

        if bytes[i] == b'"' {
            masked[i] = b' ';
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                let byte = bytes[i];
                if byte != b'\n' {
                    masked[i] = b' ';
                }
                i += 1;
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    break;
                }
            }
            continue;
        }
        i += 1;
    }
    String::from_utf8(masked).expect("source masking preserves UTF-8 for ASCII source")
}

/// Remove every `#[cfg(test)]` item (functions, nested helpers, and modules)
/// from already masked source.  Unlike splitting at `mod tests {`, this also
/// handles test-only functions inside production impls and does not mistake a
/// brace in a comment/string for the item's closing brace.
fn production_source_for_daemon_only(source: &str) -> String {
    let mut masked = mask_non_code(source).into_bytes();
    let original = masked.clone();
    let mut search = 0;
    while let Some(relative) = String::from_utf8_lossy(&original[search..]).find("#[cfg(test)]") {
        let start = search + relative;
        let after_attr = start + "#[cfg(test)]".len();
        let mut item = after_attr;
        while item < original.len() && original[item].is_ascii_whitespace() {
            item += 1;
        }
        let mut cursor = item;
        let mut opening = None;
        let mut semicolon = None;
        while cursor < original.len() {
            match original[cursor] {
                b'{' => {
                    opening = Some(cursor);
                    break;
                }
                b';' => {
                    semicolon = Some(cursor + 1);
                    break;
                }
                _ => cursor += 1,
            }
        }
        let end = if let Some(end) = semicolon {
            end
        } else if let Some(open) = opening {
            let mut depth = 0usize;
            let mut close = open;
            while close < original.len() {
                match original[close] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            close += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                close += 1;
            }
            close
        } else {
            after_attr
        };
        let end = end.min(masked.len());
        for byte in &mut masked[start..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        search = end.max(after_attr);
    }
    String::from_utf8(masked).expect("masked source remains UTF-8")
}

fn daemon_only_violations(path: &Path, source: &str) -> Vec<String> {
    let production = production_source_for_daemon_only(source);
    DAEMON_ONLY_SYMBOLS
        .iter()
        .filter_map(|symbol| {
            let count = production.matches(symbol).count();
            (count > 0).then(|| format!("{} contains {symbol} ({count})", path.display()))
        })
        .collect()
}

#[test]
fn production_path_ratchet_forbids_cli_db_open() {
    let mut files = Vec::new();
    collect_rs_files(&repo_src(), &mut files);
    let mut seen = vec![false; ALLOWED.len()];
    let mut violations = Vec::new();
    for path in files {
        let rel = relative_src(&path);
        let source = production_source(&path);
        for needle in FORBIDDEN {
            let count = count_matches(&source, needle);
            if count == 0 {
                continue;
            }
            match ALLOWED
                .iter()
                .position(|&(file, symbol, _)| file == rel && symbol == *needle)
            {
                Some(idx) => {
                    seen[idx] = true;
                    let expected = ALLOWED[idx].2;
                    if count != expected {
                        violations.push(format!(
                            "{rel} contains {needle} {count} time(s), expected {expected}"
                        ));
                    }
                }
                None => violations.push(format!("{rel} contains {needle} ({count})")),
            }
        }
    }
    for (idx, &(file, symbol, expected)) in ALLOWED.iter().enumerate() {
        if !seen[idx] {
            violations.push(format!(
                "allow-list entry {file} {symbol} x{expected} was not observed"
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "CLI production-path ratchet violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn daemon_only_paths_have_no_local_secret_or_provider_resolution() {
    let mut violations = Vec::new();
    let paths = daemon_only_paths();
    // Non-vacuous inventory: assert every declared daemon-only file is actually
    // in the scanned set (rather than a loose `len() >=` lower bound), so a
    // future `Db::open_default` / `vault_for_db` / `secret_ref::load_effective`
    // reintroduction in any of them — `commands/config.rs` included — is caught
    // instead of silently skipped because the file was never scanned.
    let root = workspace_root();
    for rel in CLI_DAEMON_ONLY_FILES
        .iter()
        .chain(TUI_APP_DAEMON_ONLY_FILES)
    {
        let expected = root.join(rel);
        assert!(
            paths.contains(&expected),
            "AC11 daemon-only inventory must scan {rel}"
        );
    }
    for path in paths {
        if is_test_file(&path) {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("read AC11 production source {}: {error}", path.display())
        });
        violations.extend(daemon_only_violations(&path, &source));
    }
    assert!(
        violations.is_empty(),
        "settings-and-cli-secrets-via-daemon AC11 violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn daemon_only_scanner_detects_planted_production_violation_but_allows_tests() {
    let planted = r#"
        fn production() {
            cockpit_core::credentials::CredentialStore::open_default();
            // Db::open_default in a comment is not a call.
            let _doc = "vault_for_db and persist_provider";
        }

        #[cfg(test)]
        mod tests {
            fn fixture() {
                Db::open_default();
                secret_ref::load_effective(&cwd);
                resolve_provider_request_async();
                fetch_models_for_provider_with_fallback();
                fetch_all_provider_usage_async();
            }
        }
    "#;
    let violations = daemon_only_violations(Path::new("planted.rs"), planted);
    assert_eq!(
        violations,
        vec!["planted.rs contains CredentialStore::open (1)"],
        "the scanner must detect a real production call while excluding comments,
         literals, and cfg(test) modules"
    );
}

#[test]
fn daemon_only_scanner_rejects_local_reference_resolution_and_paths() {
    let planted = r#"
        fn production() {
            let _refs = cockpit_core::envref::resolve("Bearer $TOKEN");
            let _path = cockpit_core::credentials::default_path();
            let _safe = cockpit_core::envref::referenced_names("$TOKEN");
        }

        #[cfg(test)]
        mod tests {
            fn fixture() {
                cockpit_core::envref::resolve("$TEST");
                cockpit_core::credentials::default_path();
            }
        }
    "#;
    let mut violations = daemon_only_violations(Path::new("planted.rs"), planted);
    violations.sort();
    assert_eq!(
        violations,
        vec![
            "planted.rs contains credentials::default_path( (1)",
            "planted.rs contains envref::resolve( (1)",
        ],
        "the scanner must reject process-vault resolution while allowing syntax-only refs"
    );
}
