//! Completeness ratchet for the exclusive global-layer creator invariant.
//!
//! Fully closed properties:
//! - Production `cockpit_config_dir()` has a single consumer:
//!   [`cockpit_config::config::dirs::global_config_dir`]. Other layers resolve
//!   the platform config path through that function, never by calling
//!   `resolve::cockpit_config_dir` themselves.
//! - A production file that both resolves the global config directory
//!   (`global_config_dir` / `cockpit_config_dir` / `default_config_dir`) and
//!   calls raw `create_dir_all(` must be an enumerated funnel or a documented
//!   residual user-directed write site. Product-owned side-effect mkdirs of
//!   the missing global layer (including nested `providers/` and `sandbox/`)
//!   go through `create_dir_all_except_missing_global`,
//!   `ensure_config_layer_dir`, or `ensure_global_config_dir`.
//!
//! Remaining class: explicit user/model-directed arbitrary-path writes can
//! still materialize the global dir at umask-default permissions when a
//! session write scope covers `~/.config` (write-tool parent mkdir, `config
//! export-policy --output`, `bash`, daemon `fs_write` / `fs_create_dir`).
//! Those are deliberate file actions, not product-owned side-effect mkdirs.
//! `fs_api.rs` is allow-listed only because it also *mentions* the global
//! dir for snapshot identity; its mkdir targets are caller-supplied project
//! paths.

use std::fs;
use std::path::{Path, PathBuf};

const COCKPIT_CONFIG_DIR_ALLOWED: &[&str] = &[
    "crates/cockpit-config/src/config/resolve.rs",
    "crates/cockpit-config/src/config/dirs.rs",
];

const RESOLVER_AND_RAW_MKDIR_ALLOWED: &[&str] = &[
    "crates/cockpit-config/src/config/dirs.rs",
    "crates/cockpit-config/src/config/files.rs",
    "crates/cockpit-core/src/daemon/fs_api.rs",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn relative_repo(path: &Path) -> String {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    canonical
        .strip_prefix(repo_root())
        .unwrap_or(&canonical)
        .to_string_lossy()
        .replace('\\', "/")
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
            if !name.contains("test") && !name.contains("ratchet") {
                out.push(path);
            }
        }
    }
}

fn cfg_enables_test(attr: &str) -> bool {
    attr.contains("cfg(test)")
        || attr.contains("(test,")
        || attr.contains("(test)")
        || attr.contains(", test")
        || attr.contains(",test")
}

fn strip_vis(rest: &str) -> &str {
    rest.strip_prefix("pub(crate) ")
        .or_else(|| rest.strip_prefix("pub(super) "))
        .or_else(|| rest.strip_prefix("pub "))
        .unwrap_or(rest)
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
            let rest = strip_vis(src[attr_end..].trim_start());
            if cfg_enables_test(attr) && rest.starts_with("mod ") {
                let mut j = attr_end;
                while j < src.len() && bytes[j] != b'{' && bytes[j] != b';' {
                    j += 1;
                }
                if j < src.len() && bytes[j] == b';' {
                    // File module (`mod foo;`): drop the declaration, not the
                    // rest of this file. The sibling file is scanned on its own.
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

fn production_source(path: &Path) -> String {
    strip_test_modules(&fs::read_to_string(path).unwrap())
}

fn resolves_global_dir(source: &str) -> bool {
    source.contains("global_config_dir(")
        || source.contains("cockpit_config_dir(")
        || source.contains("default_config_dir(")
}

fn raw_create_dir_all(source: &str) -> bool {
    source.contains("create_dir_all(")
}

fn production_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = Vec::new();
    for rel in [
        "crates/cockpit-config/src",
        "crates/cockpit-core/src",
        "crates/cockpit-tui/src",
        "apps/cli/src",
    ] {
        collect_rs_files(&root.join(rel), &mut files);
    }
    files
}

#[test]
fn production_cockpit_config_dir_has_a_single_consumer() {
    let mut violations = Vec::new();
    let mut seen = vec![false; COCKPIT_CONFIG_DIR_ALLOWED.len()];
    for path in production_files() {
        let rel = relative_repo(&path);
        let source = production_source(&path);
        if !source.contains("cockpit_config_dir(") {
            continue;
        }
        match COCKPIT_CONFIG_DIR_ALLOWED
            .iter()
            .position(|allowed| *allowed == rel)
        {
            Some(idx) => seen[idx] = true,
            None => violations.push(format!(
                "{rel} calls cockpit_config_dir(); only global_config_dir may resolve the platform path"
            )),
        }
    }
    for (idx, allowed) in COCKPIT_CONFIG_DIR_ALLOWED.iter().enumerate() {
        if !seen[idx] {
            violations.push(format!(
                "allow-list entry {allowed} was not observed calling cockpit_config_dir("
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "cockpit_config_dir consumer ratchet violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn production_global_dir_resolvers_do_not_raw_mkdir_the_global_layer() {
    let mut violations = Vec::new();
    let mut seen = vec![false; RESOLVER_AND_RAW_MKDIR_ALLOWED.len()];
    for path in production_files() {
        let rel = relative_repo(&path);
        let source = production_source(&path);
        if !resolves_global_dir(&source) || !raw_create_dir_all(&source) {
            continue;
        }
        match RESOLVER_AND_RAW_MKDIR_ALLOWED
            .iter()
            .position(|allowed| *allowed == rel)
        {
            Some(idx) => seen[idx] = true,
            None => violations.push(format!(
                "{rel} resolves the global config dir and calls raw create_dir_all(; \
                 product-owned side-effect mkdirs must use create_dir_all_except_missing_global"
            )),
        }
    }
    for (idx, allowed) in RESOLVER_AND_RAW_MKDIR_ALLOWED.iter().enumerate() {
        if !seen[idx] {
            violations.push(format!(
                "allow-list entry {allowed} was not observed with both a global-dir resolver and raw create_dir_all("
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "global-layer mkdir ratchet violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn container_sandbox_materialization_uses_the_side_effect_mkdir_funnel() {
    let source =
        production_source(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/container/mod.rs"));
    let body = source
        .split("pub fn materialize_default_dockerfile(")
        .nth(1)
        .and_then(|tail| tail.split("\npub fn ").next())
        .expect("materialize_default_dockerfile");
    assert!(
        body.contains("create_dir_all_except_missing_global"),
        "container sandbox mkdir must refuse a missing global layer"
    );
    assert!(
        !body.contains("std::fs::create_dir_all"),
        "container sandbox mkdir must not raw-create the global layer"
    );
    let default_dir = source
        .split("pub fn default_config_dir(")
        .nth(1)
        .and_then(|tail| tail.split("\npub fn ").next())
        .expect("default_config_dir");
    assert!(
        default_dir.contains("global_config_dir"),
        "container default config dir must resolve through dirs::global_config_dir"
    );
    assert!(
        !default_dir.contains("cockpit_config_dir"),
        "container default config dir must not bypass dirs.rs"
    );
}
