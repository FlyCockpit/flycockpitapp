//! Production-path allow-list for core SQLite / vault construction.
//!
//! Later owner-RPC prompts shrink this list. A warning is not enough.
//! Each entry is an exact file + forbidden symbol + occurrence count. A new
//! open in an allow-listed file fails. The only permitted production
//! `Db::open_default` opens are daemon boot, and the offline `doctor`
//! diagnostic (`daemon/diagnostics_probe.rs`) which reports database health
//! in-process when no daemon is available.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &[
    "Db::open_default",
    "CredentialStore::open",
    "vault_for_db",
    "open_for_db",
    "SealedCompartment::open_default",
];

/// Cited A2 / daemon-boot production sites. Counts are after `#[cfg(test)]`
/// modules are stripped.
const ALLOWED: &[(&str, &str, usize)] = &[
    ("daemon/server/mod.rs", "Db::open_default", 1),
    ("daemon/diagnostics_probe.rs", "Db::open_default", 1),
    ("daemon/server/mod.rs", "open_for_db", 1),
    ("secure_key/mod.rs", "vault_for_db", 1),
    ("secure_key/mod.rs", "open_for_db", 1),
    ("secure_key/resolve.rs", "vault_for_db", 1),
    ("secure_key/resolve.rs", "open_for_db", 2),
    ("assistants/self_improvement.rs", "open_for_db", 1),
    ("assistants/mod.rs", "open_for_db", 1),
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

/// True when a `#[cfg(...)]` attribute enables test-only code, e.g.
/// `#[cfg(test)]` or `#[cfg(all(test, feature = "remote"))]`. A negated gate
/// (`#[cfg(not(test))]`) selects the production fallback and is not stripped.
fn cfg_enables_test(attr: &str) -> bool {
    attr.contains("test") && !attr.contains("not(test)")
}

fn strip_test_modules(src: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    let bytes = src.as_bytes();
    while i < src.len() {
        if let Some(rel) = src[i..].find("#[cfg(") {
            out.push_str(&src[i..i + rel]);
            let attr_start = i + rel;
            let Some(attr_end_rel) = src[attr_start..].find(']') else {
                out.push_str(&src[attr_start..]);
                break;
            };
            let attr_end = attr_start + attr_end_rel + 1;
            let attr = &src[attr_start..attr_end];
            if !cfg_enables_test(attr) {
                out.push_str(attr);
                i = attr_end;
                continue;
            }
            // A test-gated item is stripped whole: an inline `mod`/`fn` block
            // up to its matching brace, or a file-module declaration up to its
            // semicolon (the sibling file is scanned on its own).
            let mut j = attr_end;
            while j < src.len() && bytes[j] != b'{' && bytes[j] != b';' {
                j += 1;
            }
            if j < src.len() && bytes[j] == b';' {
                i = j + 1;
                continue;
            }
            if j < src.len() && bytes[j] == b'{' {
                let mut depth = 0;
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
                continue;
            }
            out.push_str(attr);
            i = attr_end;
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
fn production_path_ratchet_forbids_core_credential_open() {
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
        "core production-path ratchet violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn no_production_sealed_compartment_open_default() {
    let source = production_source(&repo_src().join("tools/use_sealed_value.rs"));
    assert!(
        !source.contains("SealedCompartment::open_default"),
        "use_sealed_value must not fall back to SealedCompartment::open_default"
    );
}

#[test]
fn use_sealed_value_has_no_open_default_fallback() {
    no_production_sealed_compartment_open_default();
}

#[test]
fn export_redaction_uses_injected_vault() {
    let source = production_source(&repo_src().join("session/export/mod.rs"));
    assert!(
        !source.contains("vault_for_db"),
        "export redaction must not call vault_for_db"
    );
    assert!(
        !source.contains("fn export_vault"),
        "export_vault helper must be deleted"
    );
}

#[test]
fn session_fork_uses_injected_vault() {
    let source = production_source(&repo_src().join("session/lifecycle.rs"));
    let fork = source
        .split("pub fn create_fork")
        .nth(1)
        .and_then(|rest| rest.split("pub fn resume").next())
        .expect("create_fork");
    assert!(
        fork.contains("vault: Arc<crate::secure_key::SecretVault>"),
        "create_fork must take an injected vault"
    );
    assert!(
        !fork.contains("vault_for_db"),
        "create_fork must not open a vault"
    );
}

#[test]
fn sealed_value_persist_uses_injected_vault() {
    let source = production_source(&repo_src().join("session/sealed_values.rs"));
    assert!(
        !source.contains("vault_for_db"),
        "sealed persist must use the session-held vault"
    );
}

#[test]
fn diagnostics_does_not_open_db() {
    let source = production_source(&repo_src().join("diagnostics.rs"));
    assert!(
        !source.contains("Db::open_default"),
        "diagnostics must not open SQLite"
    );
    assert!(
        !source.contains("CredentialStore::open"),
        "diagnostics must not open the credential store"
    );
}

#[test]
fn no_production_credential_store_open_default() {
    let mut files = Vec::new();
    collect_rs_files(&repo_src(), &mut files);
    let mut leftover = Vec::new();
    for path in files {
        let rel = relative_src(&path);
        let source = production_source(&path);
        let count = count_matches(&source, "CredentialStore::open");
        if count > 0 && rel != "secure_key/mod.rs" {
            leftover.push(format!("{rel} contains CredentialStore::open ({count})"));
        }
    }
    assert!(
        leftover.is_empty(),
        "production credential opens remain:\n{}",
        leftover.join("\n")
    );
}

#[test]
fn oauth_refresh_uses_injected_store() {
    let refresh = production_source(&repo_src().join("auth/refresh_guard.rs"));
    assert!(
        !refresh.contains("CredentialStore::open"),
        "oauth refresh must take an injected store"
    );
}

#[test]
fn tool_web_and_skill_use_injected_lookup() {
    let web = production_source(&repo_src().join("tools/web.rs"));
    let skill = production_source(&repo_src().join("tools/skill.rs"));
    assert!(
        !web.contains("CredentialStore::open"),
        "web tool must use the session vault"
    );
    assert!(
        !skill.contains("CredentialStore::open"),
        "skill tool must use the session vault"
    );
    assert!(
        web.contains("credential_store()") || web.contains("secret_vault"),
        "web tool must read the injected session store"
    );
}
