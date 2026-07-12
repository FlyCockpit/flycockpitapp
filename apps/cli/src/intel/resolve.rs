//! Import-target resolution: raw import strings → a relative file path
//! inside the indexed tree, or `None` (unresolved) for external crates,
//! dynamic imports, and stdlib references.
//!
//! Resolution is deliberately conservative: a wrong resolution is worse
//! than an unresolved one for the weak-model target (priority #1), so a
//! candidate is only accepted when the corresponding file actually
//! exists in the on-disk set we're indexing. The `existing` set is the
//! collection of relative, forward-slash paths the index knows about.

use std::collections::HashSet;
use std::path::Path;

use crate::intel::lang::Language;

/// Resolve `raw` (the verbatim import target) imported from the file at
/// relative `importer` path. `existing` is the set of relative paths in
/// the index; `module_prefix` is the Go module path (from `go.mod`) or
/// empty. Returns the resolved relative path, or `None` if unresolved.
pub fn resolve(
    lang: Language,
    importer: &str,
    raw: &str,
    existing: &HashSet<String>,
    module_prefix: &str,
) -> Option<String> {
    match lang {
        Language::Rust => resolve_rust(importer, raw, existing),
        Language::TypeScript | Language::Tsx | Language::JavaScript => {
            resolve_js(importer, raw, existing)
        }
        Language::Python => resolve_python(importer, raw, existing),
        Language::Go => resolve_go(raw, existing, module_prefix),
        Language::C | Language::Cpp => resolve_c(importer, raw, existing),
        Language::Markdown
        | Language::Toml
        | Language::Yaml
        | Language::Json
        | Language::Html
        | Language::Css
        | Language::Sql
        | Language::Xml
        | Language::Shell
        | Language::Dockerfile
        | Language::Makefile
        | Language::Dotenv
        | Language::Text
        | Language::Unknown => None,
    }
}

/// Normalize a path made of `a/b/../c` components to a clean relative
/// forward-slash path, without touching the filesystem.
fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if matches!(parts.last(), Some(&"..") | None) {
                    parts.push("..");
                } else {
                    parts.pop();
                }
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

fn parent_dir(importer: &str) -> &str {
    match importer.rfind('/') {
        Some(i) => &importer[..i],
        None => "",
    }
}

fn join(dir: &str, rel: &str) -> String {
    if dir.is_empty() {
        normalize(rel)
    } else {
        normalize(&format!("{dir}/{rel}"))
    }
}

// ---- Rust ------------------------------------------------------------------

/// Resolve a Rust `use` target. We map the *first* module segment after
/// `crate::`/`self::`/`super::` to a file under the importer's crate.
/// External crates (no leading crate/self/super) are unresolved.
fn resolve_rust(importer: &str, raw: &str, existing: &HashSet<String>) -> Option<String> {
    // Strip a `… as Alias`, trailing braces, and whitespace; we only
    // need the module path leading to a file.
    let head = raw.split_whitespace().next().unwrap_or(raw);
    let head = head
        .split('{')
        .next()
        .unwrap_or(head)
        .trim_end_matches("::");
    let segments: Vec<&str> = head.split("::").filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return None;
    }

    // Locate the crate source root: the directory containing the
    // importer that holds a `lib.rs`/`main.rs`, walking up. We
    // approximate by treating the importer's own directory as the base
    // for `self`/`super` and the nearest `src/` ancestor for `crate`.
    let importer_dir = parent_dir(importer);

    let (base_dir, mod_segments): (String, &[&str]) = match segments[0] {
        "crate" => (rust_crate_root(importer, existing), &segments[1..]),
        "self" => (importer_dir.to_string(), &segments[1..]),
        "super" => {
            let mut dir = importer_dir.to_string();
            let mut idx = 1;
            while segments.get(idx) == Some(&"super") {
                dir = parent_dir(&dir).to_string();
                idx += 1;
            }
            (dir, &segments[idx..])
        }
        _ => return None, // external crate or std
    };

    // Try mapping progressively shorter module paths to `mod.rs`/`<m>.rs`.
    for take in (0..=mod_segments.len()).rev() {
        let mod_path = mod_segments[..take].join("/");
        for cand in rust_candidates(&base_dir, &mod_path) {
            if existing.contains(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

/// Best-effort crate source root for the importer: the directory of the
/// nearest `lib.rs`/`main.rs` ancestor, else the importer's `src` dir.
fn rust_crate_root(importer: &str, existing: &HashSet<String>) -> String {
    let mut dir = parent_dir(importer).to_string();
    loop {
        if existing.contains(&join(&dir, "lib.rs")) || existing.contains(&join(&dir, "main.rs")) {
            return dir;
        }
        if dir.is_empty() {
            return dir;
        }
        dir = parent_dir(&dir).to_string();
    }
}

fn rust_candidates(base: &str, mod_path: &str) -> Vec<String> {
    if mod_path.is_empty() {
        return vec![join(base, "lib.rs"), join(base, "main.rs")];
    }
    vec![
        join(base, &format!("{mod_path}.rs")),
        join(base, &format!("{mod_path}/mod.rs")),
    ]
}

// ---- JS / TS ---------------------------------------------------------------

const JS_EXTS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs"];

fn resolve_js(importer: &str, raw: &str, existing: &HashSet<String>) -> Option<String> {
    // Only relative imports resolve; bare specifiers are packages.
    if !(raw.starts_with("./") || raw.starts_with("../") || raw.starts_with('/')) {
        return None;
    }
    let dir = parent_dir(importer);
    let base = if let Some(stripped) = raw.strip_prefix('/') {
        normalize(stripped)
    } else {
        join(dir, raw)
    };
    // Exact (with extension) first.
    if existing.contains(&base) {
        return Some(base);
    }
    for ext in JS_EXTS {
        let cand = format!("{base}.{ext}");
        if existing.contains(&cand) {
            return Some(cand);
        }
    }
    for ext in JS_EXTS {
        let cand = format!("{base}/index.{ext}");
        if existing.contains(&cand) {
            return Some(cand);
        }
    }
    None
}

// ---- Python ----------------------------------------------------------------

fn resolve_python(importer: &str, raw: &str, existing: &HashSet<String>) -> Option<String> {
    let (base_dir, rest): (String, &str) = if let Some(stripped) = raw.strip_prefix('.') {
        // Relative: count leading dots.
        let dots = raw.len() - raw.trim_start_matches('.').len();
        let mut dir = parent_dir(importer).to_string();
        // One dot = current package; each extra dot goes up a level.
        for _ in 1..dots {
            dir = parent_dir(&dir).to_string();
        }
        (dir, stripped.trim_start_matches('.'))
    } else {
        // Absolute (project-rooted): map dots to slashes from the root.
        (String::new(), raw)
    };
    let rel = rest.replace('.', "/");
    let module_path = if rel.is_empty() {
        base_dir
    } else {
        join(&base_dir, &rel)
    };
    let file = format!("{module_path}.py");
    if existing.contains(&file) {
        return Some(file);
    }
    let pkg = join(&module_path, "__init__.py");
    if existing.contains(&pkg) {
        return Some(pkg);
    }
    None
}

// ---- Go --------------------------------------------------------------------

fn resolve_go(raw: &str, existing: &HashSet<String>, module_prefix: &str) -> Option<String> {
    if module_prefix.is_empty() {
        return None;
    }
    // Only intra-module imports resolve; the importee is a *package*
    // directory, so we accept any indexed `.go` file under it.
    let rel = raw.strip_prefix(module_prefix)?.trim_start_matches('/');
    if rel.is_empty() {
        return None;
    }
    let dir = normalize(rel);
    // Pick the first indexed `.go` file in that directory (deterministic
    // via sorted iteration) so the dep edge points at a concrete file.
    let mut hits: Vec<&String> = existing
        .iter()
        .filter(|p| {
            p.ends_with(".go")
                && Path::new(p.as_str())
                    .parent()
                    .map(|d| d.to_string_lossy().replace('\\', "/") == dir)
                    .unwrap_or(false)
        })
        .collect();
    hits.sort();
    hits.first().map(|s| (*s).clone())
}

// ---- C / C++ ---------------------------------------------------------------

fn resolve_c(importer: &str, raw: &str, existing: &HashSet<String>) -> Option<String> {
    // Quoted includes only (the extractor already stripped the quotes;
    // angle-bracket system headers were stored verbatim but rarely
    // resolve and that's fine). Try importer dir, then include/, src/.
    let dir = parent_dir(importer);
    let candidates = [
        join(dir, raw),
        join("include", raw),
        join("src", raw),
        normalize(raw),
    ];
    candidates.into_iter().find(|c| existing.contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn resolves_rust_crate_path() {
        let existing = set(&["src/lib.rs", "src/foo.rs", "src/bar/mod.rs"]);
        assert_eq!(
            resolve_rust("src/lib.rs", "crate::foo::Thing", &existing).as_deref(),
            Some("src/foo.rs")
        );
        assert_eq!(
            resolve_rust("src/lib.rs", "crate::bar::baz", &existing).as_deref(),
            Some("src/bar/mod.rs")
        );
        assert_eq!(resolve_rust("src/lib.rs", "std::fs::File", &existing), None);
    }

    #[test]
    fn resolves_js_relative_with_ext_probe() {
        let existing = set(&["src/app.ts", "src/util/index.ts"]);
        assert_eq!(
            resolve_js("src/app.ts", "./util", &existing).as_deref(),
            Some("src/util/index.ts")
        );
        assert_eq!(resolve_js("src/app.ts", "react", &existing), None);
    }

    #[test]
    fn resolves_python_relative_and_absolute() {
        let existing = set(&["pkg/a.py", "pkg/sub/__init__.py", "top.py"]);
        assert_eq!(
            resolve_python("pkg/main.py", ".a", &existing).as_deref(),
            Some("pkg/a.py")
        );
        assert_eq!(
            resolve_python("pkg/main.py", ".sub", &existing).as_deref(),
            Some("pkg/sub/__init__.py")
        );
        assert_eq!(
            resolve_python("pkg/main.py", "top", &existing).as_deref(),
            Some("top.py")
        );
    }

    #[test]
    fn resolves_go_intra_module() {
        let existing = set(&["internal/store/db.go", "main.go"]);
        assert_eq!(
            resolve_go(
                "example.com/app/internal/store",
                &existing,
                "example.com/app"
            )
            .as_deref(),
            Some("internal/store/db.go")
        );
        assert_eq!(resolve_go("fmt", &existing, "example.com/app"), None);
    }

    #[test]
    fn resolves_c_quoted_include() {
        let existing = set(&["src/main.c", "src/util.h", "include/api.h"]);
        assert_eq!(
            resolve_c("src/main.c", "util.h", &existing).as_deref(),
            Some("src/util.h")
        );
        assert_eq!(
            resolve_c("src/main.c", "api.h", &existing).as_deref(),
            Some("include/api.h")
        );
    }
}
