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
    ("commands/assistant.rs", "Db::open_default", 6),
    ("commands/config.rs", "Db::open_default", 1),
    ("commands/connect.rs", "Db::open_default", 1),
    ("commands/connect.rs", "vault_for_db", 1),
    ("commands/debug.rs", "Db::open_default", 1),
    ("commands/export.rs", "Db::open_default", 1),
    ("commands/export.rs", "vault_for_db", 1),
    ("commands/fetch_models.rs", "Db::open_default", 1),
    ("commands/fetch_models.rs", "open_for_db", 1),
    ("commands/flycockpit.rs", "Db::open_default", 4),
    ("commands/flycockpit.rs", "vault_for_db", 1),
    ("commands/import.rs", "Db::open_default", 1),
    ("commands/kcl.rs", "Db::open_default", 1),
    ("commands/packages.rs", "Db::open_default", 4),
    ("commands/providers.rs", "Db::open_default", 1),
    ("commands/providers.rs", "open_for_db", 1),
    ("commands/setup.rs", "Db::open_default", 1),
    ("commands/setup.rs", "open_for_db", 1),
    ("commands/run.rs", "Db::open_default", 1),
    ("commands/run.rs", "vault_for_db", 1),
    ("commands/session.rs", "Db::open_default", 5),
    ("commands/skill.rs", "Db::open_default", 1),
    ("commands/stats.rs", "Db::open_default", 1),
    ("commands/sync.rs", "Db::open_default", 1),
    ("commands/sync.rs", "vault_for_db", 1),
    ("commands/trust.rs", "Db::open_default", 2),
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
